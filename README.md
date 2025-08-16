# MsGopsy — Fast, reliable Go CLI for O365 / EntraID account testing

MsGopsy is a Go-based port of [MSOLSpray](https://github.com/dafthack/MSOLSpray/tree/master) tool with added features, including single-name account brute-forcing and credential pair checking. Designed for speed, simplicity, and reliability, it helps security professionals test Microsoft account resilience efficiently.

## ⚠️ Disclaimer

This tool is intended for authorized security testing and educational purposes only. Users are responsible for ensuring they have explicit permission to test target systems. Unauthorized access to computer systems is illegal and unethical.

## Overview

MsGopsy is a lightweight Go CLI focused on automated assessment of Microsoft account authentication. It emphasizes clarity, portability, and predictable behavior across platforms.

## Features

- ✅ Single-name account brute-forcing
- ✅ Credential-pair checking (validates username/password lists)
- ✅ Multiple-name account password spraying
- ✅ Logging and output file support
- ✅ Multi-threading with configurable concurrency
- ✅ Jitter and rate limiting for stealth
- ✅ Custom User-Agent support
- ✅ [FireProx](https://github.com/ustayready/fireprox) integration
- ✅ Cross-platform compatibility (Windows, Linux, macOS)

## Installation

### Quick Install (Recommended)

Download pre-compiled binaries from the [Releases](https://github.com/h4ck3df1sh/MsGopsy/releases) page:

- **Windows**: `MsGopsy-windows-amd64.exe`
- **Linux**: `MsGopsy-linux-amd64`
- **macOS**: `MsGopsy-darwin-amd64`

### Build from Source (Optional)

If you prefer to build from source:

**Prerequisites:**
- Go 1.20 or higher

**Build:**
```bash
git https://github.com/h4ck3df1sh/MsGopsy.git
cd MsGopsy
go build -o MsGopsy .
./MsGopsy --help
```

## Usage

```bash
./MsGopsy --help

MsGopsy: Multi-threaded O365/Azure password spray tool
Usage examples:
  - Single user, single password:   -u user@domain.com -p Winter2025!
  - Single user, password list:   -u user@domain.com -P passwords.txt
  - User list, single password:   -U users.txt -p Winter2025!
  - User list, password list:     -U users.txt -P passwords.txt
Flags:
  -u, --username            Single username (user@domain.com)
  -U, --username-list       File with usernames, one per line
  -p, --password            Single password
  -P, --password-list       File with passwords, one per line
  -pl, --pair-list         File with username:password pairs, one per line (credential pair mode)
  -url                      URL to spray against (default: https://login.microsoft.com)
  -threads                  Number of concurrent threads (default: 5)
  -o, --output [dir]       Output file for successful results (JSON). If a directory or '.' is specified, saves as YYYY-MM-DD_HH-MM-SS_MsGopsy.json in that location.
  -no-color                 Disable color output
  -l, --log [dir]           Save raw log to file (optionally specify directory, default current directory)
  -v                        Verbose: include invalid password lines
  --only-success            Show only successful results (including MFA & conditional access)
  --only-success-nomfa      Show only successful results (no MFA)
  --delay-ms N              Base delay in milliseconds between attempts (rate limiting)
  --jitter-ms N             Add random 0..N ms jitter to each delay
  --user-agent UA           Set a custom User-Agent header
  --user-agent-random       Use a random common User-Agent each request
  --x-forwarded-for IP      Set X-Forwarded-For header (default 127.0.0.1)
  -h, --help                Show this help menu
  ```

### Input File Formats

**Username file (users.txt):**
```
user1@domain.com
user2@domain.com
admin@domain.com
```

**Password file (passwords.txt):**
```
Winter2025!
Summer2024!
Password123
```

**Credential pairs file (credentials.txt):**
```
user1@domain.com:Winter2025!
user2@domain.com:Summer2024!
admin@domain.com:Password123
```

## Output Interpretation

MsGopsy provides different result types:

- **SUCCESS**: Valid credentials, account accessible
- **MFA_REQUIRED**: Valid credentials, but MFA is required
- **CONDITIONAL_ACCESS**: Valid credentials, but conditional access policies block login
- **INVALID**: Invalid username or password
- **LOCKED**: Account is locked due to failed attempts
- **DISABLED**: Account exists but is disabled

## Security Considerations

- Always obtain written authorization before testing
- Be aware of account lockout policies
- Monitor your testing to avoid service disruption
- Use realistic timing to avoid detection
- Clean up logs and results files containing sensitive data

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details.

**Remember**: This tool should only be used for authorized security assessments and educational purposes. Always ensure you have proper permission before testing any systems.