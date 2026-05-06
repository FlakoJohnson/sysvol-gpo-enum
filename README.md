# sysvol-gpo-enum

**Author:** Bishop Fox Red Team  
**Language:** Go  
**Purpose:** Enumerate GPOs from SYSVOL over SMB, correlate with LDAP, parse policy files for misconfigurations and credential exposure.

---

## For Claude CLI — What This Project Is

This is a single-package Go tool (`package main`) with two files:

- `go.mod` — declares the module and single external dependency
- `main.go` — all logic in one file (~950 lines)

### External Dependency

```
github.com/mandiant/gopacket v0.0.0-20260424163850-5d927b8e6b8d
```

This is a Go reimplementation of Python's impacket library. It provides:
- `pkg/smb` — SMB2/3 client (Mount, ReadDir, Open/Read files)
- `pkg/ldap` — LDAP client with NTLM/Kerberos auth

**The API is beta.** The method signatures in `main.go` are based on the published pkg.go.dev docs and README examples, but may need adjustment after `go get` resolves the real source. See "Known API Uncertainties" below.

---

## Build Instructions

```bash
# Fetch dependencies
go mod tidy

# Build native Linux binary
go build -trimpath -ldflags="-s -w" -o sysvol-gpo-enum .

# Cross-compile Windows .exe (no CGO needed)
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
  go build -trimpath -ldflags="-s -w" -o sysvol-gpo-enum.exe .
```

---

## Usage

```bash
# Password auth
./sysvol-gpo-enum -u jsmith -p 'Password1' -d corp.local dc01.corp.local

# Pass-the-hash
./sysvol-gpo-enum -u jsmith -H aad3b435:fc525c9dc4a... -d corp.local dc01

# Kerberos (KRB5CCNAME must be set)
./sysvol-gpo-enum -u jsmith -k -d corp.local dc01

# SOCKS5 proxy + JSON output
./sysvol-gpo-enum -u jsmith -p 'P@ss' -d corp.local dc01 \
  -proxy socks5h://127.0.0.1:1080 -o report.json

# Show all GPOs including ones with no findings
./sysvol-gpo-enum -u jsmith -p 'P@ss' -d corp.local dc01 --all -v
```

---

## Code Structure (main.go)

| Section | Lines (approx) | What it does |
|---------|---------------|-------------|
| CLI / opts | ~60–110 | `flag` parsing, hash splitting |
| SMB transport | ~120–195 | `connectSMB()`, `listDir()`, `readFile()` via gopacket `pkg/smb` |
| LDAP transport | ~200–235 | `connectLDAP()`, NTLM/Kerberos bind via gopacket `pkg/ldap` |
| LDAP GPO queries | ~240–295 | `getGPONames()`, `getGPOLinks()` |
| Finding model | ~300–320 | `Finding`, `GPOResult` structs + JSON tags |
| cPassword decrypt | ~325–360 | MS14-025 AES-256-CBC with published Microsoft key |
| GptTmpl.inf parser | ~365–425 | Password policy, lockout, autologon, privileges |
| Registry.pol parser | ~430–530 | PReg binary format parser + interesting-key filter |
| XML parsers | ~530–660 | Groups.xml, Drives.xml, ScheduledTasks.xml |
| Script scanner | ~660–690 | Regex patterns over .ps1/.bat/.vbs/.cmd/.js |
| SYSVOL walker | ~690–785 | Recursive SMB walk, dispatches to parsers |
| Report printer | ~785–860 | Colour terminal output + finding summary |
| Helpers | ~860–920 | `atoi`, `truncate`, `randomHostname` |
| main() | ~920–990 | Orchestration: SMB → LDAP → walk → report → JSON |

---

## Known API Uncertainties (Fix These First)

The gopacket `pkg/smb` and `pkg/ldap` APIs are beta. After running `go mod tidy`, check the actual source and fix these call sites if the compiler errors:

### SMB (`pkg/smb`)

```go
// In connectSMB():
gsmb.Options{Host, Domain, Workstation, ProxyURL}  // verify field names
client.NTLMLogin(domain, user, pass, lmHash, ntHash) // may be NTLMBind() or Login()
client.KerberosLogin(user, domain)                   // verify sig
client.Mount("SYSVOL")                               // may be TreeConnect("SYSVOL")

// In smbSession methods:
s.share.ReadDir(path)   // returns []gsmb.DirEntry or []fs.DirEntry
s.share.Open(path)      // returns io.ReadCloser or similar
e.Name()                // on DirEntry — standard fs.DirEntry interface
e.IsDir()               // same
```

### LDAP (`pkg/ldap`)

```go
// In connectLDAP():
gldap.Dial(host, port)                              // verify signature
conn.NTLMBindFull(domain, user, pass, lm, nt)       // may be NTLMBind()
conn.KerberosBindFull(user, domain)                 // may be KerberosBind()

// In getGPONames / getGPOLinks:
conn.Search(base, filter, attrs, scope)             // verify param order & scope constant
results.Entries                                     // may be []*ldap.Entry
entry.GetAttributeValue("cn")                       // standard go-ldap style
entry.DN                                            // distinguished name field
gldap.ScopeWholeSubtree                             // may be int constant, not exported name
```

**Recommended approach for Claude CLI:**  
Run `go mod tidy` first, then `go build ./...` and fix errors one at a time from the compiler output. The logic (parsers, crypto, report) is all stdlib and will compile cleanly — only the gopacket call sites need verification.

---

## What the Tool Detects

| Severity | Examples |
|----------|---------|
| CRITICAL | cpassword in Groups/Drives/Tasks XML (MS14-025), AutoLogon plaintext password |
| HIGH | Password complexity disabled, lockout disabled, AutoLogon username, hardcoded script creds |
| MEDIUM | Weak min password length (<12), interesting Registry.pol entries |
| INFO | Interesting privilege assignments, script commands, mapped drive usernames |

---

## Evasion Properties

- Uses `crypto/rand` throughout — no predictable alnum-only patterns
- Random jitter (50–350ms) between SMB calls
- Random Windows-style hostname injected into NTLM negotiate
- Single compiled binary — no Python, no `.py` files, no impacket
- SOCKS5 proxy support via gopacket native (`-proxy` flag)
