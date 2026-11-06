// OKerberang — Kerberos AS-REP/Kerberoast Analyzer
// OWL Batch-3 offensive security toolkit.
// Author : khaled.s.haddad    Website : owlsec.org
// Language: Go (standard library only; static, CGO-free build).
// AUTHORIZED TESTING ONLY. See --howto for the legal & ethical warning.

package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// ---- OWL UI KIT (cyan "owl" house style) — stdlib only. ---------------------
const (
	R   = "\033[91m"
	GRN = "\033[92m"
	YLW = "\033[93m"
	CY  = "\033[96m"
	W   = "\033[97m"
	B   = "\033[1m"
	X   = "\033[0m"
	MG  = "\033[95m"
	DIM = "\033[2m"
	OR  = "\033[38;5;208m"
	GY  = "\033[90m"
	// legacy aliases (kept so older call-sites compile) — remapped to cyan house style
	DR = "\033[96m"
)

var noColor = os.Getenv("NO_COLOR") != "" || !isatty()

func isatty() bool { fi, _ := os.Stdout.Stat(); return (fi.Mode() & os.ModeCharDevice) != 0 }
func col(s string, c ...string) string {
	if noColor {
		return s
	}
	return strings.Join(c, "") + s + X
}
func clear()           { fmt.Print("\033[H\033[2J") }
func rule()            { fmt.Println(col(strings.Repeat("─", 66), CY)) }
func line(w int)       { fmt.Println(col(strings.Repeat("─", w), CY)) }
func okMsg(s string)   { fmt.Println("  " + col("[✔] ", GRN+B) + col(s, W)) }
func errMsg(s string)  { fmt.Println("  " + col("[✘] ", R+B) + col(s, R)) }
func warnMsg(s string) { fmt.Println("  " + col("[!] ", OR+B) + col(s, YLW)) }
func info(s string)    { fmt.Println("  " + col("[*] ", CY) + col(s, DIM+W)) }

func banner() {
	fmt.Println(col(BANNER, CY))
	fmt.Println("  " + col(SUITE+"  ", B+MG) + col("v"+VERSION, YLW))
	fmt.Println("  " + col(SUBLINE, W))
	fmt.Println()
	fmt.Println("  " + col("Developer : ", DIM) + col(AUTHOR, CY) +
		col("   |   Website : ", DIM) + col(WEBSITE, CY))
	rule()
	fmt.Println()
}

var stdin = bufio.NewReader(os.Stdin)

func prompt(label string) string {
	fmt.Print("  " + col("[»] ", YLW) + col(label+": ", W))
	s, err := stdin.ReadString('\n')
	if err != nil && s == "" {
		fmt.Println()
		os.Exit(0)
	}
	return strings.TrimSpace(s)
}
func pause() {
	fmt.Print(col("\n  [↩] Press Enter to continue...", YLW))
	stdin.ReadString('\n')
}

func stripANSI(s string) string {
	out := []rune{}
	esc := false
	for _, r := range s {
		if r == '\033' {
			esc = true
			continue
		}
		if esc {
			if r == 'm' {
				esc = false
			}
			continue
		}
		out = append(out, r)
	}
	return string(out)
}
func visw(s string) int { return len([]rune(stripANSI(s))) }
func pad(s string, n int) string {
	if visw(s) >= n {
		return s
	}
	return s + strings.Repeat(" ", n-visw(s))
}
func menu(title string, items []string) string {
	clear()
	banner()
	fmt.Println("  " + col("⬡  "+title, B+CY))
	fmt.Println()
	for i, it := range items {
		fmt.Printf("   %s  %s\n", col(fmt.Sprintf("[%02d]", i+1), CY+B), col(it, W))
	}
	fmt.Println("   " + col("[ H]", YLW+B) + "  " + col("Help & usage", YLW))
	fmt.Println("   " + col("[00]", GY) + "  " + col("Exit", GY))
	fmt.Println()
	return prompt("select")
}
func table(headers []string, rows [][]string) {
	w := make([]int, len(headers))
	for i, h := range headers {
		w[i] = visw(h)
	}
	for _, r := range rows {
		for i, c := range r {
			if i < len(w) && visw(c) > w[i] {
				w[i] = visw(c)
			}
		}
	}
	var hb strings.Builder
	for i, h := range headers {
		hb.WriteString(col(pad(h, w[i]), B+CY))
		if i < len(headers)-1 {
			hb.WriteString(col(" │ ", DIM))
		}
	}
	fmt.Println("  " + hb.String())
	seg := make([]string, len(w))
	for i := range w {
		seg[i] = strings.Repeat("─", w[i])
	}
	fmt.Println("  " + col(strings.Join(seg, "─┼─"), DIM))
	for _, r := range rows {
		var rb strings.Builder
		for i := range headers {
			v := ""
			if i < len(r) {
				v = r[i]
			}
			rb.WriteString(col(pad(v, w[i]), W))
			if i < len(headers)-1 {
				rb.WriteString(col(" │ ", DIM))
			}
		}
		fmt.Println("  " + rb.String())
	}
}

const (
	APPNAME = "OKerberang"
	SUITE   = "Owl Kerberos Suite"
	TAGLINE = "Kerberos AS-REP / Kerberoast Analyzer"
	SUBLINE = "AS-REP roast · Kerberoast · PA-less · etype triage · MITRE mapping"
	VERSION = "1.0"
	AUTHOR  = "khaled.s.haddad"
	WEBSITE = "owlsec.org"
)

const BANNER = `
 ██████╗ ██╗  ██╗███████╗██████╗ ██████╗ ███████╗██████╗  █████╗ ███╗   ██╗ ██████╗ 
██╔═══██╗██║ ██╔╝██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗██╔══██╗████╗  ██║██╔════╝ 
██║   ██║█████╔╝ █████╗  ██████╔╝██████╔╝█████╗  ██████╔╝███████║██╔██╗ ██║██║  ███╗
██║   ██║██╔═██╗ ██╔══╝  ██╔══██╗██╔══██╗██╔══╝  ██╔══██╗██╔══██║██║╚██╗██║██║   ██║
╚██████╔╝██║  ██╗███████╗██║  ██║██████╔╝███████╗██║  ██║██║  ██║██║ ╚████║╚██████╔╝
 ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝
`

// ============================================================================
//  SHARED ENGINE  —  types, CLI, export (txt/md/json/csv/sarif), grading,
//  HOW TO USE renderer, interactive cyan TUI, and domain utilities.
//  This block is identical across every OWL Batch-3 tool; each tool supplies
//  its own deep domain engine (catalogs, parsers, generators, scoring) that
//  plugs into the hooks declared at the bottom of this file.
// ============================================================================

// Finding is a single analysis result with MITRE ATT&CK mapping and a score.
type Finding struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Severity    string   `json:"severity"`
	Category    string   `json:"category"`
	Detail      string   `json:"detail"`
	Evidence    string   `json:"evidence"`
	Remediation string   `json:"remediation"`
	Mitre       []string `json:"mitre"`
	Score       int      `json:"score"`
	Ref         string   `json:"ref,omitempty"`
}

// Section is a titled block of lines used by HOW TO USE and catalog views.
type Section struct {
	Title string
	Lines []string
}

// MenuItem is one interactive action in the TUI.
type MenuItem struct {
	Label  string
	Action func()
}

// AnalysisResult is the full output of a domain analysis or demo run.
type AnalysisResult struct {
	Target   string            `json:"target"`
	Tool     string            `json:"tool"`
	When     string            `json:"when"`
	Findings []Finding         `json:"findings"`
	Stats    map[string]string `json:"stats"`
	Grade    string            `json:"grade"`
	Notes    []string          `json:"notes,omitempty"`
}

// ---------------------------------------------------------------------------
//  Severity model
// ---------------------------------------------------------------------------

const (
	SevCrit = "CRITICAL"
	SevHigh = "HIGH"
	SevMed  = "MEDIUM"
	SevLow  = "LOW"
	SevInfo = "INFO"
)

func sevRank(s string) int {
	switch strings.ToUpper(s) {
	case SevCrit:
		return 5
	case SevHigh:
		return 4
	case SevMed:
		return 3
	case SevLow:
		return 2
	case SevInfo:
		return 1
	}
	return 0
}

func sevWeight(s string) int {
	switch strings.ToUpper(s) {
	case SevCrit:
		return 40
	case SevHigh:
		return 25
	case SevMed:
		return 12
	case SevLow:
		return 5
	case SevInfo:
		return 1
	}
	return 0
}

func sevColor(s string) string {
	switch strings.ToUpper(s) {
	case SevCrit:
		return R + B
	case SevHigh:
		return R
	case SevMed:
		return YLW
	case SevLow:
		return W
	default:
		return GY
	}
}

// sarifLevel maps a severity to a SARIF result level.
func sarifLevel(s string) string {
	switch strings.ToUpper(s) {
	case SevCrit, SevHigh:
		return "error"
	case SevMed:
		return "warning"
	case SevLow, SevInfo:
		return "note"
	}
	return "none"
}

// ---------------------------------------------------------------------------
//  Grading — convert a set of findings into an A+..F posture grade.
// ---------------------------------------------------------------------------

func gradeFromFindings(fs []Finding) string {
	risk := 0
	for _, f := range fs {
		risk += sevWeight(f.Severity)
	}
	switch {
	case risk == 0:
		return "A+"
	case risk <= 5:
		return "A"
	case risk <= 15:
		return "B"
	case risk <= 30:
		return "C"
	case risk <= 60:
		return "D"
	case risk <= 100:
		return "E"
	default:
		return "F"
	}
}

func gradeMeaning(g string) string {
	switch g {
	case "A+":
		return "no material exposure detected"
	case "A":
		return "minimal exposure; strong posture"
	case "B":
		return "minor issues; generally solid"
	case "C":
		return "moderate exposure; remediation advised"
	case "D":
		return "significant exposure; prioritize fixes"
	case "E":
		return "severe exposure; urgent remediation"
	default:
		return "critical exposure; immediate action required"
	}
}

func gradeColor(g string) string {
	switch g {
	case "A+", "A":
		return GRN + B
	case "B", "C":
		return YLW + B
	default:
		return R + B
	}
}

// ---------------------------------------------------------------------------
//  Global flags / state
// ---------------------------------------------------------------------------

var (
	flHelp    = flag.Bool("help", false, "show rich usage help and exit")
	flH       = flag.Bool("h", false, "alias for --help")
	flVersion = flag.Bool("version", false, "print version and exit")
	flHowto   = flag.Bool("howto", false, "show the HOW TO USE screen and exit")
	flDemo    = flag.Bool("demo", false, "run a self-contained synthetic demonstration")
	flInput   = flag.String("input", "", "path to an input file to analyze")
	flPath    = flag.String("path", "", "alias for --input (subject path/file)")
	flTarget  = flag.String("target", "", "logical target name/label for the report")
	flFormat  = flag.String("format", "txt", "export format: txt|md|json|csv|sarif")
	flOutput  = flag.String("output", "", "write export to FILE instead of stdout")
	flNoColor = flag.Bool("no-color", false, "disable ANSI colors")
	flCatalog = flag.Bool("catalog", false, "print the built-in reference catalog and exit")
	flList    = flag.Bool("list", false, "alias for --catalog")
	flQuiet   = flag.Bool("quiet", false, "suppress banner in CLI export mode")
	flSelf    = flag.Bool("selftest", false, "run built-in self-tests and exit")
)

var lastResult *AnalysisResult

// ---------------------------------------------------------------------------
//  main
// ---------------------------------------------------------------------------

func main() {
	flag.Usage = usage
	flag.Parse()

	if *flNoColor {
		noColor = true
	}

	switch {
	case *flSelf:
		os.Exit(runSelfTest())
	case *flHelp || *flH:
		usage()
		return
	case *flVersion:
		fmt.Printf("%s %s  (author khaled.s.haddad, owlsec.org)\n", APPNAME, VERSION)
		return
	case *flHowto:
		printHowto()
		return
	case *flCatalog || *flList:
		printCatalog()
		return
	case *flDemo:
		res := domainDemoResult()
		finalize(&res)
		lastResult = &res
		if !*flQuiet {
			renderResult(&res)
		}
		if *flOutput != "" || *flFormat != "txt" {
			emitExport(&res)
		}
		return
	}

	in := firstNonEmpty(*flInput, *flPath)
	if in != "" {
		res, err := domainAnalyze(in)
		if err != nil {
			errMsg("analysis failed: " + err.Error())
			os.Exit(1)
		}
		finalize(&res)
		lastResult = &res
		if !*flQuiet {
			renderResult(&res)
		}
		emitExport(&res)
		return
	}

	// No actionable flags -> interactive TUI.
	interactive()
}

func firstNonEmpty(a ...string) string {
	for _, s := range a {
		if strings.TrimSpace(s) != "" {
			return s
		}
	}
	return ""
}

// finalize fills defaulted fields (timestamp, tool, grade) on a result.
func finalize(r *AnalysisResult) {
	if r.When == "" {
		r.When = time.Now().Format("2006-01-02 15:04:05 -0700")
	}
	if r.Tool == "" {
		r.Tool = APPNAME
	}
	if r.Stats == nil {
		r.Stats = map[string]string{}
	}
	if r.Grade == "" {
		r.Grade = gradeFromFindings(r.Findings)
	}
	sortFindings(r.Findings)
}

func sortFindings(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		if sevRank(fs[i].Severity) != sevRank(fs[j].Severity) {
			return sevRank(fs[i].Severity) > sevRank(fs[j].Severity)
		}
		return fs[i].ID < fs[j].ID
	})
}

// ---------------------------------------------------------------------------
//  Usage / help
// ---------------------------------------------------------------------------

func usage() {
	if !*flQuiet {
		banner()
	}
	fmt.Println("  " + col("USAGE", CY+B))
	fmt.Printf("    %s [flags]\n", strings.ToLower(APPNAME))
	fmt.Println()
	fmt.Println("  " + col("DESCRIPTION", CY+B))
	for _, ln := range wrap(domainSummary(), 68) {
		fmt.Println("    " + ln)
	}
	fmt.Println()
	fmt.Println("  " + col("CORE FLAGS", CY+B))
	helpRow("-h, --help", "show this rich usage help")
	helpRow("--version", "print version and exit")
	helpRow("--howto", "show the HOW TO USE screen (legal, steps, nav)")
	helpRow("--demo", "run a self-contained synthetic demonstration")
	helpRow("--catalog, --list", "print the built-in reference catalog")
	helpRow("--input FILE", "analyze FILE (also --path)")
	helpRow("--target NAME", "label the engagement/target in the report")
	helpRow("--format FMT", "export format: txt|md|json|csv|sarif")
	helpRow("--output FILE", "write export to FILE (default stdout)")
	helpRow("--no-color", "disable ANSI colors")
	helpRow("--quiet", "suppress banner in export mode")
	fmt.Println()
	fmt.Println("  " + col("EXAMPLES", CY+B))
	fmt.Printf("    %s                      # interactive cyan TUI\n", strings.ToLower(APPNAME))
	fmt.Printf("    %s --demo                # synthetic walkthrough\n", strings.ToLower(APPNAME))
	fmt.Printf("    %s --howto               # how-to-use + legal warning\n", strings.ToLower(APPNAME))
	fmt.Printf("    %s --input data --format sarif --output out.sarif\n", strings.ToLower(APPNAME))
	fmt.Println()
	fmt.Println("  " + col("MITRE ATT&CK", CY+B))
	fmt.Println("    primary: " + MITRE_PRIMARY + "  (" + mitreName(MITRE_PRIMARY) + ")")
	fmt.Println("    " + strings.Join(MITRE_TAGS, ", "))
	fmt.Println()
	line(64)
	fmt.Println("  " + col("Authorized testing only. See --howto for the legal warning.", GY))
}

func helpRow(a, b string) {
	fmt.Printf("    %s %s\n", col(pad(a, 22), W), col(b, GY))
}

// ---------------------------------------------------------------------------
//  HOW TO USE screen  (MANDATORY — menu item + --howto flag)
// ---------------------------------------------------------------------------

func howtoSections() []Section {
	var secs []Section
	secs = append(secs, Section{
		Title: "LEGAL & ETHICAL WARNING",
		Lines: []string{
			APPNAME + " is an offensive-security tool for AUTHORIZED testing only.",
			"Use it solely on systems and data you own or have EXPLICIT, WRITTEN",
			"permission to assess. Unauthorized access, interception, or attack is",
			"illegal in most jurisdictions (e.g. CFAA, Computer Misuse Act, GDPR).",
			"This build performs OFFLINE analysis, parsing, planning and lab",
			"generation only; it does not attack third parties. You are solely",
			"responsible for staying within the scope of your engagement and law.",
			"Keep all artifacts, hashes and credentials in your authorized vault.",
		},
	})
	steps := domainHowtoSteps()
	secs = append(secs, Section{Title: "HOW TO USE", Lines: numbered(steps)})
	secs = append(secs, Section{
		Title: "NAVIGATION",
		Lines: []string{
			"Launch with no arguments for the interactive cyan TUI.",
			"At each menu type the [NN] number of an option and press Enter.",
			"[00] exits the current menu or the program.",
			"HOW TO USE is always available from the main menu and via --howto.",
			"Every result view can be exported (txt/md/json/csv/sarif).",
			"Use --input FILE for non-interactive (CLI) analysis and export.",
		},
	})
	secs = append(secs, Section{Title: "REQUIREMENTS", Lines: domainRequirements()})
	secs = append(secs, domainHowtoNotes()...)
	secs = append(secs, Section{
		Title: "EXPORT & REPORTING",
		Lines: []string{
			"Formats: txt (console report), md (Markdown), json (machine),",
			"csv (spreadsheet), sarif (SARIF 2.1.0 for CI/code-scanning).",
			"Findings carry MITRE ATT&CK technique IDs and an A+..F grade.",
			"Example: --input data --format sarif --output report.sarif",
		},
	})
	return secs
}

func printHowto() {
	clear()
	banner()
	fmt.Println("  " + col("⬡ HOW TO USE — "+APPNAME, CY+B))
	fmt.Println()
	renderSections(howtoSections())
}

func renderSections(secs []Section) {
	for _, s := range secs {
		fmt.Println("  " + col("⬡ "+s.Title, CY+B))
		line(64)
		for _, ln := range s.Lines {
			fmt.Println("   " + col(ln, W))
		}
		fmt.Println()
	}
}

func numbered(items []string) []string {
	out := make([]string, 0, len(items))
	for i, it := range items {
		out = append(out, fmt.Sprintf("%2d. %s", i+1, it))
	}
	return out
}

// ---------------------------------------------------------------------------
//  Catalog printing (CLI)
// ---------------------------------------------------------------------------

func printCatalog() {
	if !*flQuiet {
		clear()
		banner()
	}
	fmt.Println("  " + col("⬡ REFERENCE CATALOG — "+APPNAME, CY+B))
	fmt.Println()
	renderSections(domainCatalogSections())
}

// ---------------------------------------------------------------------------
//  Result rendering (console)
// ---------------------------------------------------------------------------

func renderResult(r *AnalysisResult) {
	clear()
	banner()
	fmt.Println("  " + col("⬡ RESULT — "+r.Tool, CY+B))
	fmt.Println("  " + col("target : ", DIM) + col(nz(r.Target, "(none)"), W))
	fmt.Println("  " + col("time   : ", DIM) + col(r.When, W))
	gc := gradeColor(r.Grade)
	fmt.Println("  " + col("grade  : ", DIM) + col(r.Grade, gc) + col("  ("+gradeMeaning(r.Grade)+")", GY))
	fmt.Println()
	if len(r.Stats) > 0 {
		fmt.Println("  " + col("⬡ STATISTICS", CY+B))
		keys := make([]string, 0, len(r.Stats))
		for k := range r.Stats {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Printf("   %s %s\n", col(pad(k+":", 22), GY), col(r.Stats[k], W))
		}
		fmt.Println()
	}
	renderSevHistogram(r.Findings)
	if len(r.Findings) == 0 {
		okMsg("no findings")
	} else {
		fmt.Println("  " + col(fmt.Sprintf("⬡ FINDINGS (%d)", len(r.Findings)), CY+B))
		line(64)
		for _, f := range r.Findings {
			renderFinding(f)
		}
	}
	if tm := topMitre(r.Findings, 6); len(tm) > 0 {
		fmt.Println()
		fmt.Println("  " + col("⬡ TOP MITRE ATT&CK", CY+B))
		for _, m := range tm {
			info(m)
		}
	}
	if len(r.Notes) > 0 {
		fmt.Println()
		fmt.Println("  " + col("⬡ NOTES", CY+B))
		for _, n := range r.Notes {
			info(n)
		}
	}
}

func renderFinding(f Finding) {
	tag := col("["+f.Severity+"]", sevColor(f.Severity))
	fmt.Printf("  %s %s %s\n", tag, col(f.ID, DR), col(f.Title, W+B))
	if f.Category != "" {
		fmt.Println("      " + col("category : ", GY) + col(f.Category, W))
	}
	for _, ln := range wrap(f.Detail, 60) {
		fmt.Println("      " + col(ln, W))
	}
	if f.Evidence != "" {
		for _, ln := range wrap("evidence: "+f.Evidence, 60) {
			fmt.Println("      " + col(ln, GY))
		}
	}
	if f.Remediation != "" {
		for _, ln := range wrap("fix: "+f.Remediation, 60) {
			fmt.Println("      " + col(ln, GRN))
		}
	}
	if len(f.Mitre) > 0 {
		fmt.Println("      " + col("mitre: "+strings.Join(f.Mitre, ", "), R))
	}
	fmt.Println()
}

// ---------------------------------------------------------------------------
//  Export engine — TXT / MD / JSON / CSV / SARIF 2.1.0
// ---------------------------------------------------------------------------

func emitExport(r *AnalysisResult) {
	format := strings.ToLower(strings.TrimSpace(*flFormat))
	var data string
	switch format {
	case "", "txt":
		data = exportTXT(r)
	case "md", "markdown":
		data = exportMD(r)
	case "json":
		data = exportJSON(r)
	case "csv":
		data = exportCSV(r)
	case "sarif":
		data = exportSARIF(r)
	default:
		errMsg("unknown format: " + format + " (use txt|md|json|csv|sarif)")
		return
	}
	if *flOutput == "" {
		if format != "txt" {
			fmt.Println(data)
		}
		return
	}
	if err := os.WriteFile(*flOutput, []byte(data), 0644); err != nil {
		errMsg("write failed: " + err.Error())
		return
	}
	okMsg(fmt.Sprintf("wrote %s (%d bytes, %s)", *flOutput, len(data), format))
}

func exportTXT(r *AnalysisResult) string {
	var b strings.Builder
	b.WriteString("OWL " + APPNAME + " — " + TAGLINE + "\n")
	b.WriteString("author khaled.s.haddad  owlsec.org\n")
	b.WriteString(strings.Repeat("=", 64) + "\n")
	b.WriteString("target : " + nz(r.Target, "(none)") + "\n")
	b.WriteString("time   : " + r.When + "\n")
	b.WriteString("grade  : " + r.Grade + " (" + gradeMeaning(r.Grade) + ")\n")
	b.WriteString("mitre  : " + MITRE_PRIMARY + " " + strings.Join(MITRE_TAGS, " ") + "\n\n")
	if len(r.Stats) > 0 {
		b.WriteString("STATISTICS\n" + strings.Repeat("-", 64) + "\n")
		for _, k := range sortedKeys(r.Stats) {
			b.WriteString("  " + pad(k+":", 24) + r.Stats[k] + "\n")
		}
		b.WriteString("\n")
	}
	b.WriteString(fmt.Sprintf("FINDINGS (%d)\n", len(r.Findings)))
	b.WriteString(strings.Repeat("-", 64) + "\n")
	for _, f := range r.Findings {
		b.WriteString(fmt.Sprintf("[%s] %s  %s\n", f.Severity, f.ID, f.Title))
		if f.Category != "" {
			b.WriteString("    category   : " + f.Category + "\n")
		}
		if f.Detail != "" {
			b.WriteString("    detail     : " + f.Detail + "\n")
		}
		if f.Evidence != "" {
			b.WriteString("    evidence   : " + f.Evidence + "\n")
		}
		if f.Remediation != "" {
			b.WriteString("    remediation: " + f.Remediation + "\n")
		}
		if len(f.Mitre) > 0 {
			b.WriteString("    mitre      : " + strings.Join(f.Mitre, ", ") + "\n")
		}
		b.WriteString("    score      : " + strconv.Itoa(f.Score) + "\n\n")
	}
	for _, n := range r.Notes {
		b.WriteString("note: " + n + "\n")
	}
	return b.String()
}

func exportMD(r *AnalysisResult) string {
	var b strings.Builder
	b.WriteString("# OWL " + APPNAME + " — " + TAGLINE + "\n\n")
	b.WriteString("*author khaled.s.haddad · owlsec.org*\n\n")
	b.WriteString("| field | value |\n|---|---|\n")
	b.WriteString("| target | " + mdEsc(nz(r.Target, "(none)")) + " |\n")
	b.WriteString("| time | " + mdEsc(r.When) + " |\n")
	b.WriteString("| grade | **" + r.Grade + "** (" + gradeMeaning(r.Grade) + ") |\n")
	b.WriteString("| mitre | " + MITRE_PRIMARY + " " + strings.Join(MITRE_TAGS, " ") + " |\n\n")
	if len(r.Stats) > 0 {
		b.WriteString("## Statistics\n\n| metric | value |\n|---|---|\n")
		for _, k := range sortedKeys(r.Stats) {
			b.WriteString("| " + mdEsc(k) + " | " + mdEsc(r.Stats[k]) + " |\n")
		}
		b.WriteString("\n")
	}
	b.WriteString(fmt.Sprintf("## Findings (%d)\n\n", len(r.Findings)))
	for _, f := range r.Findings {
		b.WriteString("### [" + f.Severity + "] " + mdEsc(f.Title) + " `" + f.ID + "`\n\n")
		if f.Category != "" {
			b.WriteString("- **category:** " + mdEsc(f.Category) + "\n")
		}
		if f.Detail != "" {
			b.WriteString("- **detail:** " + mdEsc(f.Detail) + "\n")
		}
		if f.Evidence != "" {
			b.WriteString("- **evidence:** `" + f.Evidence + "`\n")
		}
		if f.Remediation != "" {
			b.WriteString("- **remediation:** " + mdEsc(f.Remediation) + "\n")
		}
		if len(f.Mitre) > 0 {
			b.WriteString("- **mitre:** " + strings.Join(f.Mitre, ", ") + "\n")
		}
		b.WriteString("- **score:** " + strconv.Itoa(f.Score) + "\n\n")
	}
	return b.String()
}

func exportJSON(r *AnalysisResult) string {
	payload := map[string]interface{}{
		"tool":         APPNAME,
		"tagline":      TAGLINE,
		"version":      VERSION,
		"author":       "khaled.s.haddad",
		"website":      "owlsec.org",
		"mitrePrimary": MITRE_PRIMARY,
		"mitreTags":    MITRE_TAGS,
		"result":       r,
	}
	buf, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return "{\"error\":\"" + err.Error() + "\"}"
	}
	return string(buf)
}

func exportCSV(r *AnalysisResult) string {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	w.Write([]string{"id", "severity", "category", "title", "detail", "evidence", "remediation", "mitre", "score"})
	for _, f := range r.Findings {
		w.Write([]string{
			f.ID, f.Severity, f.Category, f.Title, f.Detail, f.Evidence,
			f.Remediation, strings.Join(f.Mitre, " "), strconv.Itoa(f.Score),
		})
	}
	w.Flush()
	return buf.String()
}

func exportSARIF(r *AnalysisResult) string {
	rules := map[string]bool{}
	var ruleList []map[string]interface{}
	var results []map[string]interface{}
	for _, f := range r.Findings {
		if !rules[f.ID] {
			rules[f.ID] = true
			ruleList = append(ruleList, map[string]interface{}{
				"id":               f.ID,
				"name":             f.Title,
				"shortDescription": map[string]string{"text": f.Title},
				"fullDescription":  map[string]string{"text": nz(f.Detail, f.Title)},
				"helpUri":          "https://owlsec.org",
				"properties": map[string]interface{}{
					"category": f.Category,
					"mitre":    f.Mitre,
				},
			})
		}
		results = append(results, map[string]interface{}{
			"ruleId": f.ID,
			"level":  sarifLevel(f.Severity),
			"message": map[string]string{
				"text": f.Title + ". " + f.Detail + nzPrefix(" Evidence: ", f.Evidence),
			},
			"properties": map[string]interface{}{
				"severity": f.Severity,
				"score":    f.Score,
				"mitre":    f.Mitre,
			},
			"locations": []map[string]interface{}{
				{
					"physicalLocation": map[string]interface{}{
						"artifactLocation": map[string]string{"uri": nz(r.Target, APPNAME)},
					},
				},
			},
		})
	}
	sarif := map[string]interface{}{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs": []map[string]interface{}{
			{
				"tool": map[string]interface{}{
					"driver": map[string]interface{}{
						"name":           APPNAME,
						"fullName":       "OWL " + APPNAME + " — " + TAGLINE,
						"version":        VERSION,
						"informationUri": "https://owlsec.org",
						"organization":   "owlsec.org / khaled.s.haddad",
						"rules":          ruleList,
					},
				},
				"results": results,
				"properties": map[string]interface{}{
					"grade":        r.Grade,
					"mitrePrimary": MITRE_PRIMARY,
					"target":       r.Target,
				},
			},
		},
	}
	buf, err := json.MarshalIndent(sarif, "", "  ")
	if err != nil {
		return "{\"error\":\"" + err.Error() + "\"}"
	}
	return string(buf)
}

// ---------------------------------------------------------------------------
//  Interactive TUI
// ---------------------------------------------------------------------------

func interactive() {
	for {
		items := []string{
			"Run DEMO (synthetic walkthrough)",
			"Analyze an input file",
			"Reference catalog",
		}
		dm := domainMenuItems()
		for _, m := range dm {
			items = append(items, m.Label)
		}
		items = append(items,
			"View last result",
			"Export last result",
			"About / MITRE mapping",
		)
		choice := menu("MAIN MENU — "+TAGLINE, items)
		switch choice {
		case "0", "00":
			clear()
			okMsg("Stay authorized. Goodbye.")
			return
		case "H", "h":
			tuiHelp()
		case "1":
			res := domainDemoResult()
			finalize(&res)
			lastResult = &res
			renderResult(&res)
			pause()
		case "2":
			actionAnalyze()
		case "3":
			clear()
			banner()
			fmt.Println("  " + col("⬡ REFERENCE CATALOG", CY+B))
			fmt.Println()
			renderSections(domainCatalogSections())
			pause()
		default:
			handleDynamicChoice(choice, dm)
		}
	}
}

// handleDynamicChoice resolves menu numbers for domain items and trailing items.
func handleDynamicChoice(choice string, dm []MenuItem) {
	n, err := strconv.Atoi(choice)
	if err != nil {
		errMsg("invalid selection")
		pause()
		return
	}
	base := 3 // first three fixed items
	if n > base && n <= base+len(dm) {
		dm[n-base-1].Action()
		return
	}
	idx := n - base - len(dm)
	switch idx {
	case 1: // view last
		if lastResult == nil {
			warnMsg("no result yet — run DEMO or analyze a file first")
			pause()
			return
		}
		renderResult(lastResult)
		pause()
	case 2: // export last
		actionExport()
	case 3: // about
		actionAbout()
	default:
		errMsg("invalid selection")
		pause()
	}
}

func actionAnalyze() {
	clear()
	banner()
	fmt.Println("  " + col("⬡ ANALYZE INPUT", CY+B))
	fmt.Println()
	p := prompt("path to input file")
	if p == "" {
		warnMsg("cancelled")
		pause()
		return
	}
	res, err := domainAnalyze(p)
	if err != nil {
		errMsg(err.Error())
		pause()
		return
	}
	finalize(&res)
	lastResult = &res
	renderResult(&res)
	pause()
}

func actionExport() {
	if lastResult == nil {
		warnMsg("no result yet — run DEMO or analyze a file first")
		pause()
		return
	}
	clear()
	banner()
	fmt.Println("  " + col("⬡ EXPORT LAST RESULT", CY+B))
	fmt.Println()
	f := prompt("format txt|md|json|csv|sarif")
	if f == "" {
		f = "txt"
	}
	o := prompt("output file (blank = screen)")
	*flFormat = f
	*flOutput = o
	if o == "" {
		var data string
		switch strings.ToLower(f) {
		case "md":
			data = exportMD(lastResult)
		case "json":
			data = exportJSON(lastResult)
		case "csv":
			data = exportCSV(lastResult)
		case "sarif":
			data = exportSARIF(lastResult)
		default:
			data = exportTXT(lastResult)
		}
		fmt.Println()
		fmt.Println(data)
	} else {
		emitExport(lastResult)
	}
	pause()
}

func actionAbout() {
	clear()
	banner()
	fmt.Println("  " + col("⬡ ABOUT", CY+B))
	fmt.Println()
	for _, ln := range wrap(domainSummary(), 64) {
		fmt.Println("   " + col(ln, W))
	}
	fmt.Println()
	fmt.Println("  " + col("⬡ MITRE ATT&CK", CY+B))
	fmt.Println("   primary : " + col(MITRE_PRIMARY+"  "+mitreName(MITRE_PRIMARY), W))
	for _, t := range MITRE_TAGS {
		fmt.Println("   " + col(pad(t, 12), R) + col(mitreName(t), GY))
		if notes := mitreKerberosNotes[t]; len(notes) > 0 {
			fmt.Println("               " + col(notes[0], DIM))
		}
	}
	fmt.Println()
	fmt.Println("  " + col("author khaled.s.haddad  ·  owlsec.org  ·  "+VERSION, GY))
	pause()
}

// ---------------------------------------------------------------------------
//  MITRE reference table (subset relevant to Batch-3 offensive tooling)
// ---------------------------------------------------------------------------

var mitreTable = map[string]string{
	"T1027":     "Obfuscated Files or Information",
	"T1027.009": "Embedded Payloads",
	"T1027.010": "Command Obfuscation",
	"T1059":     "Command and Scripting Interpreter",
	"T1059.001": "PowerShell",
	"T1059.003": "Windows Command Shell",
	"T1059.004": "Unix Shell",
	"T1059.005": "Visual Basic",
	"T1059.006": "Python",
	"T1059.007": "JavaScript",
	"T1105":     "Ingress Tool Transfer",
	"T1090":     "Proxy",
	"T1087":     "Account Discovery",
	"T1087.002": "Domain Account Discovery",
	"T1110":     "Brute Force",
	"T1110.003": "Password Spraying",
	"T1134":     "Access Token Manipulation",
	"T1134.001": "Token Impersonation/Theft",
	"T1134.002": "Create Process with Token",
	"T1134.005": "SID-History Injection",
	"T1135":     "Network Share Discovery",
	"T1548":     "Abuse Elevation Control Mechanism",
	"T1548.002": "Bypass User Account Control",
	"T1548.003": "Sudo and Sudo Caching",
	"T1558":     "Steal or Forge Kerberos Tickets",
	"T1558.001": "Golden Ticket",
	"T1558.002": "Silver Ticket",
	"T1558.003": "Kerberoasting",
	"T1558.004": "AS-REP Roasting",
	"T1550":     "Use Alternate Authentication Material",
	"T1550.003": "Pass the Ticket",
	"T1187":     "Forced Authentication",
	"T1557":     "Adversary-in-the-Middle",
	"T1557.001": "LLMNR/NBT-NS Poisoning and SMB Relay",
	"T1207":     "Rogue Domain Controller",
	"T1484":     "Domain or Tenant Policy Modification",
	"T1484.001": "Group Policy Modification",
	"T1098":     "Account Manipulation",
	"T1078.002": "Domain Accounts",
	"T1611":     "Escape to Host",
	"T1210":     "Exploitation of Remote Services",
	"T1021":     "Remote Services",
	"T1021.002": "SMB/Windows Admin Shares",
	"T1069":     "Permission Groups Discovery",
	"T1482":     "Domain Trust Discovery",
	"T1078":     "Valid Accounts",
	"T1003":     "OS Credential Dumping",
	"TA0001":    "Initial Access",
	"TA0002":    "Execution",
	"TA0003":    "Persistence",
	"TA0004":    "Privilege Escalation",
	"TA0005":    "Defense Evasion",
	"TA0006":    "Credential Access",
	"TA0007":    "Discovery",
	"TA0008":    "Lateral Movement",
	"TA0010":    "Exfiltration",
	"TA0011":    "Command and Control",
}

func mitreName(id string) string {
	if n, ok := mitreTable[id]; ok {
		return n
	}
	return "technique"
}

// mitreKerberosNotes expands ATT&CK IDs that matter for offline Kerberos
// roast / ticket / delegation analysis planning (authorized assessments).
var mitreKerberosNotes = map[string][]string{
	"T1558": {
		"Parent technique: steal or forge Kerberos tickets (TGT/TGS).",
		"OKerberang focuses on offline hash classification under this family.",
		"Correlate findings with ticket lifetime, etype policy, and account UAC.",
	},
	"T1558.001": {
		"Golden Ticket: forged TGT using krbtgt hash (offline forging labs).",
		"Not roasted here — flag only when planning post-compromise ticket abuse.",
		"Detection: anomalous TGT lifetime, SIDHistory, missing PAC validation.",
	},
	"T1558.002": {
		"Silver Ticket: forged TGS using a service account hash.",
		"Often follows successful Kerberoast of a high-value SPN.",
		"Detection: TGS without prior TGT, mismatched PAC / service keys.",
	},
	"T1558.003": {
		"Kerberoasting: request TGS for SPN-bearing accounts, crack offline.",
		"Hash formats: $krb5tgs$23$ (RC4), $krb5tgs$17$/$18$ (AES).",
		"Prioritize user-owned SPNs over machine accounts; prefer RC4 etype.",
		"Remediation: gMSA, long random passwords, disable RC4, monitor 4769.",
	},
	"T1558.004": {
		"AS-REP Roasting: accounts with DONT_REQ_PREAUTH (UAC 0x400000).",
		"Hash format: $krb5asrep$23$ / $krb5asrep$18$ — crack offline.",
		"Detection: 4768 with Preauth Type = 0; remediate by enabling preauth.",
	},
	"T1550.003": {
		"Pass-the-Ticket: reuse stolen/forged TGT or TGS in the lab scope.",
		"Planning note only — OKerberang does not inject tickets into LSASS.",
		"Detection: 4769 from unusual hosts; ticket encryption mismatches.",
	},
	"T1187": {
		"Forced Authentication: coerce a host to authenticate (e.g. PrinterBug,",
		"PetitPotam-class planning) then capture material for offline analysis.",
		"Often chained with relay or Kerberos coercion paths into roastable SPNs.",
	},
	"T1557.001": {
		"LLMNR/NBT-NS poisoning can yield Net-NTLM; sometimes chained to",
		"Kerberos abuse planning when relay/unconstrained delegation is present.",
	},
	"TA0006": {
		"Credential Access tactic — parent for roast and ticket-theft techniques.",
	},
	"TA0008": {
		"Lateral Movement — Pass-the-Ticket and service-ticket reuse land here.",
	},
}

func mitreKerberosBlurb(id string) []string {
	if notes, ok := mitreKerberosNotes[id]; ok {
		return notes
	}
	if n, ok := mitreTable[id]; ok {
		return []string{id + " — " + n}
	}
	return []string{id + " — (no local notes)"}
}

func mitreKerberosCatalogSection() Section {
	ids := []string{
		"T1558", "T1558.001", "T1558.002", "T1558.003", "T1558.004",
		"T1550.003", "T1187", "T1557.001",
	}
	var lines []string
	for _, id := range ids {
		name := mitreName(id)
		lines = append(lines, fmt.Sprintf("%s  %s", id, name))
		for _, note := range mitreKerberosNotes[id] {
			lines = append(lines, "  · "+note)
		}
	}
	return Section{Title: "MITRE ATT&CK — KERBEROS FAMILY", Lines: lines}
}

// ---------------------------------------------------------------------------
//  Domain utilities shared by every tool (entropy, hashing, encoders, text)
// ---------------------------------------------------------------------------

// shannonEntropy returns bits/byte (0..8) for a byte slice.
func shannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var counts [256]int
	for _, b := range data {
		counts[b]++
	}
	n := float64(len(data))
	ent := 0.0
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		ent -= p * math.Log2(p)
	}
	return ent
}

func entropyVerdict(e float64) string {
	switch {
	case e >= 7.5:
		return "very high (encrypted/packed/compressed)"
	case e >= 6.5:
		return "high (encoded/compressed)"
	case e >= 5.0:
		return "moderate (mixed/base64-ish)"
	case e >= 3.0:
		return "low (plain text/code)"
	default:
		return "very low (repetitive/structured)"
	}
}

func b64Encode(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
func b64Decode(s string) (string, error) {
	d, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	return string(d), err
}
func hexEncode(s string) string { return hex.EncodeToString([]byte(s)) }

func gzipB64(s string) string {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	w.Write([]byte(s))
	w.Close()
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

func md5Hex(s string) string    { h := md5.Sum([]byte(s)); return hex.EncodeToString(h[:]) }
func sha1Hex(s string) string   { h := sha1.Sum([]byte(s)); return hex.EncodeToString(h[:]) }
func sha256Hex(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

// utf16leB64 encodes a string as UTF-16LE then base64 (PowerShell -EncodedCommand).
func utf16leB64(s string) string {
	var buf bytes.Buffer
	for _, r := range s {
		if r < 0x10000 {
			buf.WriteByte(byte(r))
			buf.WriteByte(byte(r >> 8))
		} else {
			r -= 0x10000
			hi := 0xD800 + (r >> 10)
			lo := 0xDC00 + (r & 0x3FF)
			buf.WriteByte(byte(hi))
			buf.WriteByte(byte(hi >> 8))
			buf.WriteByte(byte(lo))
			buf.WriteByte(byte(lo >> 8))
		}
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

func xorBytes(data []byte, key []byte) []byte {
	if len(key) == 0 {
		return data
	}
	out := make([]byte, len(data))
	for i := range data {
		out[i] = data[i] ^ key[i%len(key)]
	}
	return out
}

// classifyCharset reports character-class composition of a string.
func classifyCharset(s string) (lower, upper, digit, space, punct int) {
	for _, r := range s {
		switch {
		case unicode.IsLower(r):
			lower++
		case unicode.IsUpper(r):
			upper++
		case unicode.IsDigit(r):
			digit++
		case unicode.IsSpace(r):
			space++
		default:
			punct++
		}
	}
	return
}

func randHex(n int) string {
	const h = "0123456789abcdef"
	b := make([]byte, n)
	for i := range b {
		b[i] = h[rand.Intn(16)]
	}
	return string(b)
}

func randID(prefix string) string {
	return prefix + "-" + randHex(6)
}

// ---------------------------------------------------------------------------
//  Small text/formatting helpers
// ---------------------------------------------------------------------------

func nz(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}

func nzPrefix(prefix, s string) string {
	if strings.TrimSpace(s) == "" {
		return ""
	}
	return prefix + s
}

func mdEsc(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}

func sortedKeys(m map[string]string) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

func wrap(s string, width int) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	words := strings.Fields(s)
	var lines []string
	cur := ""
	for _, w := range words {
		if cur == "" {
			cur = w
		} else if len(cur)+1+len(w) <= width {
			cur += " " + w
		} else {
			lines = append(lines, cur)
			cur = w
		}
	}
	if cur != "" {
		lines = append(lines, cur)
	}
	return lines
}

func readFileLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 8*1024*1024)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	return lines, sc.Err()
}

func readFileString(path string) (string, error) {
	b, err := os.ReadFile(path)
	return string(b), err
}

func baseName(p string) string { return filepath.Base(p) }

func mustInt(s string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	return n
}

func reFind(pattern, s string) []string {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil
	}
	return re.FindStringSubmatch(s)
}

func reAll(pattern, s string) [][]string {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil
	}
	return re.FindAllStringSubmatch(s, -1)
}

func contains(hay, needle string) bool {
	return strings.Contains(strings.ToLower(hay), strings.ToLower(needle))
}

func titleOf(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func mkFinding(id, title, sev, cat, detail string, mitre []string) Finding {
	return Finding{
		ID:       id,
		Title:    title,
		Severity: sev,
		Category: cat,
		Detail:   detail,
		Mitre:    mitre,
		Score:    sevWeight(sev),
	}
}

// ---------------------------------------------------------------------------
//  Binary read helpers (little/big endian) for protocol parsers.
// ---------------------------------------------------------------------------

func u16LE(b []byte, off int) uint16 {
	if off < 0 || off+2 > len(b) {
		return 0
	}
	return binary.LittleEndian.Uint16(b[off : off+2])
}

func u32LE(b []byte, off int) uint32 {
	if off < 0 || off+4 > len(b) {
		return 0
	}
	return binary.LittleEndian.Uint32(b[off : off+4])
}

func u16BE(b []byte, off int) uint16 {
	if off < 0 || off+2 > len(b) {
		return 0
	}
	return binary.BigEndian.Uint16(b[off : off+2])
}

func u32BE(b []byte, off int) uint32 {
	if off < 0 || off+4 > len(b) {
		return 0
	}
	return binary.BigEndian.Uint32(b[off : off+4])
}

func hexDump(b []byte, max int) string {
	if len(b) > max {
		b = b[:max]
	}
	var sb strings.Builder
	for i := 0; i < len(b); i += 16 {
		end := i + 16
		if end > len(b) {
			end = len(b)
		}
		sb.WriteString(fmt.Sprintf("%08x  ", i))
		for j := i; j < i+16; j++ {
			if j < end {
				sb.WriteString(fmt.Sprintf("%02x ", b[j]))
			} else {
				sb.WriteString("   ")
			}
		}
		sb.WriteString(" |")
		for j := i; j < end; j++ {
			c := b[j]
			if c >= 32 && c < 127 {
				sb.WriteByte(c)
			} else {
				sb.WriteByte('.')
			}
		}
		sb.WriteString("|\n")
	}
	return sb.String()
}

// ---------------------------------------------------------------------------
//  Severity analytics (used by result rendering and stats)
// ---------------------------------------------------------------------------

func sevHistogram(fs []Finding) map[string]int {
	h := map[string]int{SevCrit: 0, SevHigh: 0, SevMed: 0, SevLow: 0, SevInfo: 0}
	for _, f := range fs {
		k := strings.ToUpper(f.Severity)
		if _, ok := h[k]; ok {
			h[k]++
		} else {
			h[SevInfo]++
		}
	}
	return h
}

func renderSevHistogram(fs []Finding) {
	if len(fs) == 0 {
		return
	}
	h := sevHistogram(fs)
	order := []string{SevCrit, SevHigh, SevMed, SevLow, SevInfo}
	max := 1
	for _, k := range order {
		if h[k] > max {
			max = h[k]
		}
	}
	fmt.Println("  " + col("⬡ SEVERITY BREAKDOWN", CY+B))
	for _, k := range order {
		n := h[k]
		barLen := (n * 30) / max
		if n > 0 && barLen == 0 {
			barLen = 1
		}
		bar := strings.Repeat("█", barLen)
		fmt.Printf("   %s %s %s\n", col(pad(k, 9), sevColor(k)), col(pad(strconv.Itoa(n), 3), W), col(bar, sevColor(k)))
	}
	fmt.Println()
}

// mitreTally counts technique IDs across findings.
func mitreTally(fs []Finding) map[string]int {
	t := map[string]int{}
	for _, f := range fs {
		for _, m := range f.Mitre {
			t[m]++
		}
	}
	return t
}

func topMitre(fs []Finding, n int) []string {
	t := mitreTally(fs)
	type kv struct {
		k string
		v int
	}
	var arr []kv
	for k, v := range t {
		arr = append(arr, kv{k, v})
	}
	sort.Slice(arr, func(i, j int) bool {
		if arr[i].v != arr[j].v {
			return arr[i].v > arr[j].v
		}
		return arr[i].k < arr[j].k
	})
	var out []string
	for i, e := range arr {
		if i >= n {
			break
		}
		out = append(out, fmt.Sprintf("%s x%d (%s)", e.k, e.v, mitreName(e.k)))
	}
	return out
}

// ---------------------------------------------------------------------------
//  Generic parsing & text helpers (shared by domain engines)
// ---------------------------------------------------------------------------

func parseKVLine(line, sep string) (string, string, bool) {
	i := strings.Index(line, sep)
	if i < 0 {
		return "", "", false
	}
	return strings.TrimSpace(line[:i]), strings.TrimSpace(line[i+len(sep):]), true
}

// tokenizeArgs splits a command line honoring simple single/double quotes.
func tokenizeArgs(s string) []string {
	var out []string
	var cur strings.Builder
	var quote rune
	inTok := false
	for _, r := range s {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				cur.WriteRune(r)
			}
			inTok = true
		case r == '\'' || r == '"':
			quote = r
			inTok = true
		case r == ' ' || r == '\t':
			if inTok {
				out = append(out, cur.String())
				cur.Reset()
				inTok = false
			}
		default:
			cur.WriteRune(r)
			inTok = true
		}
	}
	if inTok {
		out = append(out, cur.String())
	}
	return out
}

func splitList(s string) []string {
	f := strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\t'
	})
	var out []string
	for _, x := range f {
		x = strings.TrimSpace(x)
		if x != "" {
			out = append(out, x)
		}
	}
	return out
}

func atoiOr(s string, def int) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return def
	}
	return n
}

func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func pct(part, total int) float64 {
	if total == 0 {
		return 0
	}
	return float64(part) * 100.0 / float64(total)
}

func trimQuotes(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

func isHexString(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
}

func rot13(s string) string {
	b := []byte(s)
	for i, c := range b {
		switch {
		case c >= 'a' && c <= 'z':
			b[i] = 'a' + (c-'a'+13)%26
		case c >= 'A' && c <= 'Z':
			b[i] = 'A' + (c-'A'+13)%26
		}
	}
	return string(b)
}

const b32alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

func base32Encode(data []byte) string {
	var sb strings.Builder
	var buf uint64
	var bits int
	for _, b := range data {
		buf = (buf << 8) | uint64(b)
		bits += 8
		for bits >= 5 {
			bits -= 5
			sb.WriteByte(b32alpha[(buf>>uint(bits))&0x1f])
		}
	}
	if bits > 0 {
		sb.WriteByte(b32alpha[(buf<<uint(5-bits))&0x1f])
	}
	for sb.Len()%8 != 0 {
		sb.WriteByte('=')
	}
	return sb.String()
}

// ---------------------------------------------------------------------------
//  Generic directed graph with weighted BFS/Dijkstra shortest path.
//  Used by attack-path / reachability domains.
// ---------------------------------------------------------------------------

type GraphEdge struct {
	To     string
	Label  string
	Weight int
}

type Graph struct {
	Adj   map[string][]GraphEdge
	Nodes map[string]bool
}

func NewGraph() *Graph {
	return &Graph{Adj: map[string][]GraphEdge{}, Nodes: map[string]bool{}}
}

func (g *Graph) AddNode(n string) {
	if n == "" {
		return
	}
	g.Nodes[n] = true
	if _, ok := g.Adj[n]; !ok {
		g.Adj[n] = nil
	}
}

func (g *Graph) AddEdge(from, to, label string, weight int) {
	g.AddNode(from)
	g.AddNode(to)
	g.Adj[from] = append(g.Adj[from], GraphEdge{To: to, Label: label, Weight: weight})
}

// ShortestPath returns the min-weight path and total cost, or nil if none.
func (g *Graph) ShortestPath(src, dst string) ([]string, []string, int) {
	const inf = int(^uint(0) >> 1)
	dist := map[string]int{}
	prev := map[string]string{}
	prevLabel := map[string]string{}
	for n := range g.Nodes {
		dist[n] = inf
	}
	if _, ok := g.Nodes[src]; !ok {
		return nil, nil, -1
	}
	dist[src] = 0
	visited := map[string]bool{}
	for {
		u := ""
		best := inf
		for n, d := range dist {
			if !visited[n] && d < best {
				best = d
				u = n
			}
		}
		if u == "" {
			break
		}
		if u == dst {
			break
		}
		visited[u] = true
		for _, e := range g.Adj[u] {
			nd := dist[u] + e.Weight
			if nd < dist[e.To] {
				dist[e.To] = nd
				prev[e.To] = u
				prevLabel[e.To] = e.Label
			}
		}
	}
	if dist[dst] == inf {
		return nil, nil, -1
	}
	var path []string
	var labels []string
	cur := dst
	for cur != src {
		path = append([]string{cur}, path...)
		labels = append([]string{prevLabel[cur]}, labels...)
		p, ok := prev[cur]
		if !ok {
			return nil, nil, -1
		}
		cur = p
	}
	path = append([]string{src}, path...)
	return path, labels, dist[dst]
}

// ReachableFrom returns all nodes reachable from src (BFS).
func (g *Graph) ReachableFrom(src string) []string {
	seen := map[string]bool{src: true}
	queue := []string{src}
	var out []string
	for len(queue) > 0 {
		u := queue[0]
		queue = queue[1:]
		for _, e := range g.Adj[u] {
			if !seen[e.To] {
				seen[e.To] = true
				out = append(out, e.To)
				queue = append(queue, e.To)
			}
		}
	}
	sort.Strings(out)
	return out
}

// ---------------------------------------------------------------------------
//  SID / RID helpers (Windows / AD domains)
// ---------------------------------------------------------------------------

// parseSIDString validates and splits an SDDL-style SID string.
func parseSIDString(s string) (parts []string, ok bool) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "S-") {
		return nil, false
	}
	parts = strings.Split(s, "-")
	if len(parts) < 3 {
		return nil, false
	}
	for i := 1; i < len(parts); i++ {
		if _, err := strconv.ParseUint(parts[i], 10, 64); err != nil {
			return nil, false
		}
	}
	return parts, true
}

func sidRID(s string) (uint64, bool) {
	parts, ok := parseSIDString(s)
	if !ok || len(parts) < 3 {
		return 0, false
	}
	n, err := strconv.ParseUint(parts[len(parts)-1], 10, 64)
	return n, err == nil
}

func wellKnownRID(rid uint64) string {
	switch rid {
	case 500:
		return "Administrator"
	case 501:
		return "Guest"
	case 502:
		return "KRBTGT"
	case 512:
		return "Domain Admins"
	case 513:
		return "Domain Users"
	case 514:
		return "Domain Guests"
	case 515:
		return "Domain Computers"
	case 516:
		return "Domain Controllers"
	case 518:
		return "Schema Admins"
	case 519:
		return "Enterprise Admins"
	case 520:
		return "Group Policy Creator Owners"
	case 544:
		return "Administrators (builtin)"
	case 545:
		return "Users (builtin)"
	case 546:
		return "Guests (builtin)"
	case 547:
		return "Power Users (builtin)"
	case 548:
		return "Account Operators"
	case 549:
		return "Server Operators"
	case 550:
		return "Print Operators"
	case 551:
		return "Backup Operators"
	case 552:
		return "Replicator"
	case 553:
		return "RAS and IAS Servers"
	case 554:
		return "Pre-Windows 2000 Compatible Access"
	case 555:
		return "Remote Desktop Users"
	case 556:
		return "Network Configuration Operators"
	case 557:
		return "Incoming Forest Trust Builders"
	case 558:
		return "Performance Monitor Users"
	case 559:
		return "Performance Log Users"
	case 560:
		return "Windows Authorization Access Group"
	case 561:
		return "Terminal Server License Servers"
	case 562:
		return "Distributed COM Users"
	case 568:
		return "IIS_IUSRS"
	case 569:
		return "Cryptographic Operators"
	case 573:
		return "Event Log Readers"
	case 574:
		return "Certificate Service DCOM Access"
	case 575:
		return "RDS Remote Access Servers"
	case 576:
		return "RDS Endpoint Servers"
	case 577:
		return "RDS Management Servers"
	case 578:
		return "Hyper-V Administrators"
	case 579:
		return "Access Control Assistance Operators"
	case 580:
		return "Remote Management Users"
	}
	return ""
}

func isPrivilegedRID(rid uint64) bool {
	switch rid {
	case 500, 512, 518, 519, 520, 544, 548, 549, 550, 551, 578:
		return true
	}
	return false
}

// ---------------------------------------------------------------------------
//  Hash format detectors (NTLM / Kerberos / Unix)
// ---------------------------------------------------------------------------

type hashKind struct {
	Name   string
	Mode   string // hashcat mode
	Sample string
	Re     *regexp.Regexp
}

var hashKinds = []hashKind{
	{"NTLM", "1000", "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0", regexp.MustCompile(`(?i)^[0-9a-f]{32}:[0-9a-f]{32}$`)},
	{"NTLM-hash-only", "1000", "31d6cfe0d16ae931b73c59d7e0c089c0", regexp.MustCompile(`(?i)^[0-9a-f]{32}$`)},
	{"NetNTLMv1", "5500", "user::domain:LMRESP:NTRESP:challenge", regexp.MustCompile(`^[^:]+:[^:]*:[^:]*:[0-9a-fA-F]{48}:[0-9a-fA-F]{48}:[0-9a-fA-F]+$`)},
	{"NetNTLMv2", "5600", "user::domain:challenge:response:blob", regexp.MustCompile(`^[^:]+:[^:]*:[^:]*:[0-9a-fA-F]{16}:[0-9a-fA-F]{32}:.+`)},
	{"Kerberos-23-TGS", "13100", "$krb5tgs$23$*user$realm$spn*$checksum$edata", regexp.MustCompile(`(?i)^\$krb5tgs\$23\$`)},
	{"Kerberos-18-TGS", "19700", "$krb5tgs$18$user$realm$*spn*$checksum$edata", regexp.MustCompile(`(?i)^\$krb5tgs\$18\$`)},
	{"Kerberos-17-TGS", "19600", "$krb5tgs$17$user$realm$*spn*$checksum$edata", regexp.MustCompile(`(?i)^\$krb5tgs\$17\$`)},
	{"Kerberos-23-ASREP", "18200", "$krb5asrep$23$user@realm$hash", regexp.MustCompile(`(?i)^\$krb5asrep\$23\$`)},
	{"Kerberos-18-ASREP", "19800", "$krb5asrep$18$user@realm$hash", regexp.MustCompile(`(?i)^\$krb5asrep\$18\$`)},
	{"md5crypt", "500", "$1$salt$hash", regexp.MustCompile(`^\$1\$[^$]+\$[./0-9A-Za-z]{22}$`)},
	{"sha256crypt", "7400", "$5$salt$hash", regexp.MustCompile(`^\$5\$(rounds=\d+\$)?[^$]+\$[./0-9A-Za-z]{43}$`)},
	{"sha512crypt", "1800", "$6$salt$hash", regexp.MustCompile(`^\$6\$(rounds=\d+\$)?[^$]+\$[./0-9A-Za-z]{86}$`)},
	{"bcrypt", "3200", "$2y$10$...", regexp.MustCompile(`^\$2[aby]?\$\d{2}\$[./A-Za-z0-9]{53}$`)},
	{"yescrypt", "n/a", "$y$j9T$...", regexp.MustCompile(`^\$y\$`)},
	{"LM", "3000", "aad3b435b51404eeaad3b435b51404ee", regexp.MustCompile(`(?i)^[0-9a-f]{32}$`)},
	{"mscash2", "2100", "$DCC2$10240#user#hash", regexp.MustCompile(`(?i)^\$DCC2\$\d+#.+#[0-9a-f]{32}$`)},
	{"krb5pa-23", "7500", "$krb5pa$23$user$realm$salt$hash", regexp.MustCompile(`(?i)^\$krb5pa\$23\$`)},
	{"krb5pa-18", "19900", "$krb5pa$18$user$realm$salt$hash", regexp.MustCompile(`(?i)^\$krb5pa\$18\$`)},
}

func detectHash(line string) *hashKind {
	line = strings.TrimSpace(line)
	for i := range hashKinds {
		if hashKinds[i].Re.MatchString(line) {
			return &hashKinds[i]
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
//  Minimal LDIF parser (shared by AD/LDAP tools)
// ---------------------------------------------------------------------------

type LDIFEntry struct {
	DN     string
	Attrs  map[string][]string
	Object string // first objectClass
}

func parseLDIF(text string) []LDIFEntry {
	var out []LDIFEntry
	var cur *LDIFEntry
	flush := func() {
		if cur != nil && cur.DN != "" {
			out = append(out, *cur)
		}
		cur = nil
	}
	lines := strings.Split(text, "\n")
	var cont string
	for _, raw := range lines {
		if strings.HasPrefix(raw, " ") && cont != "" {
			cont += strings.TrimPrefix(raw, " ")
			continue
		}
		if cont != "" {
			applyLDIFLine(&cur, cont)
			cont = ""
		}
		if strings.TrimSpace(raw) == "" {
			flush()
			continue
		}
		if strings.HasPrefix(raw, "#") || strings.HasPrefix(raw, "version:") {
			continue
		}
		cont = strings.TrimRight(raw, "\r")
	}
	if cont != "" {
		applyLDIFLine(&cur, cont)
	}
	flush()
	return out
}

func applyLDIFLine(cur **LDIFEntry, line string) {
	if strings.HasPrefix(line, "dn:") {
		if *cur == nil {
			*cur = &LDIFEntry{Attrs: map[string][]string{}}
		}
		(*cur).DN = strings.TrimSpace(strings.TrimPrefix(line, "dn:"))
		if strings.HasPrefix((*cur).DN, ":") { // base64 dn
			(*cur).DN = strings.TrimSpace(strings.TrimPrefix((*cur).DN, ":"))
			if d, err := base64.StdEncoding.DecodeString((*cur).DN); err == nil {
				(*cur).DN = string(d)
			}
		}
		return
	}
	if *cur == nil {
		*cur = &LDIFEntry{Attrs: map[string][]string{}}
	}
	i := strings.Index(line, ":")
	if i < 0 {
		return
	}
	attr := strings.TrimSpace(line[:i])
	val := strings.TrimSpace(line[i+1:])
	if strings.HasPrefix(val, ":") { // base64
		val = strings.TrimSpace(strings.TrimPrefix(val, ":"))
		if d, err := base64.StdEncoding.DecodeString(val); err == nil {
			val = string(d)
		}
	} else if strings.HasPrefix(val, "<") {
		// URL reference; keep as-is
	}
	(*cur).Attrs[attr] = append((*cur).Attrs[attr], val)
	if strings.EqualFold(attr, "objectClass") && (*cur).Object == "" {
		(*cur).Object = val
	}
}

func (e LDIFEntry) HasClass(c string) bool {
	for _, v := range e.Attrs["objectClass"] {
		if strings.EqualFold(v, c) {
			return true
		}
	}
	return false
}

func (e LDIFEntry) Attr(name string) string {
	vs := e.Attrs[name]
	if len(vs) == 0 {
		return ""
	}
	return vs[0]
}

// ---------------------------------------------------------------------------
//  CSV helpers
// ---------------------------------------------------------------------------

func parseCSVText(text string) (headers []string, rows [][]string, err error) {
	r := csv.NewReader(strings.NewReader(text))
	r.FieldsPerRecord = -1
	r.TrimLeadingSpace = true
	all, err := r.ReadAll()
	if err != nil {
		return nil, nil, err
	}
	if len(all) == 0 {
		return nil, nil, nil
	}
	return all[0], all[1:], nil
}

func rowMap(headers, row []string) map[string]string {
	m := map[string]string{}
	for i, h := range headers {
		if i < len(row) {
			m[h] = row[i]
		}
	}
	return m
}

// ---------------------------------------------------------------------------
//  Score helpers used by graders
// ---------------------------------------------------------------------------

func riskBucket(score int) string {
	switch {
	case score >= 100:
		return "CRITICAL"
	case score >= 60:
		return "HIGH"
	case score >= 30:
		return "MEDIUM"
	case score >= 10:
		return "LOW"
	default:
		return "INFO"
	}
}

func combineGrades(gs ...string) string {
	worst := "A+"
	order := map[string]int{"A+": 0, "A": 1, "B": 2, "C": 3, "D": 4, "E": 5, "F": 6}
	for _, g := range gs {
		if order[g] > order[worst] {
			worst = g
		}
	}
	return worst
}

// ============================================================================
//  DOMAIN ENGINE — OKerberang : Kerberos AS-REP / Kerberoast Analyzer
//  Parses offline Kerberos tickets/hashes, extracts AS-REP roast and
//  Kerberoast material, exports hashcat formats, analyzes SPNs. MITRE T1558
// ============================================================================

var MITRE_PRIMARY = "T1558"
var MITRE_TAGS = []string{"T1558", "T1558.001", "T1558.002", "T1558.003", "T1558.004", "T1550.003", "T1187", "TA0006", "TA0008"}

func domainSummary() string {
	return "OKerberang is an offline Kerberos ticket and hash analyzer for AUTHORIZED " +
		"Active Directory assessments. It detects and classifies AS-REP roastable and " +
		"Kerberoastable material ($krb5asrep$ / $krb5tgs$), extracts SPNs, maps etypes " +
		"(RC4/AES128/AES256), exports hashcat modes 18200/13100/19600/19700, and grades " +
		"account exposure from LDIF/CSV/hash dumps. It does not request tickets from a " +
		"live KDC — bring captured hashes or Rubeus/Impacket output."
}

type krbHash struct {
	Kind   string // asrep | tgs | pa
	Etype  int
	User   string
	Realm  string
	SPN    string
	Raw    string
	HCMode string
	LineNo int
}

var etypeName = map[int]string{
	1:  "des-cbc-crc",
	2:  "des-cbc-md4",
	3:  "des-cbc-md5",
	5:  "des3-cbc-md5",
	7:  "des3-cbc-sha1",
	16: "des3-cbc-sha1-kd",
	17: "aes128-cts-hmac-sha1-96",
	18: "aes256-cts-hmac-sha1-96",
	19: "aes128-cts-hmac-sha256-128",
	20: "aes256-cts-hmac-sha384-192",
	23: "rc4-hmac",
	24: "rc4-hmac-exp",
	25: "camellia128-cts-cmac",
	26: "camellia256-cts-cmac",
}

// etypeDetail holds roastability / crack-difficulty notes for operators.
type etypeDetail struct {
	Name       string
	Family     string // des | 3des | aes | rc4 | camellia | other
	Roastable  string // yes | limited | n/a
	CrackDiff  string // trivial | easy | moderate | hard | very-hard
	HashcatTip string
	PolicyNote string
}

var etypeDetails = map[int]etypeDetail{
	1: {
		Name: "des-cbc-crc", Family: "des", Roastable: "yes", CrackDiff: "trivial",
		HashcatTip: "Legacy DES — treat any occurrence as critical misconfiguration.",
		PolicyNote: "Disable DES entirely (msDS-SupportedEncryptionTypes / KDC policy).",
	},
	3: {
		Name: "des-cbc-md5", Family: "des", Roastable: "yes", CrackDiff: "trivial",
		HashcatTip: "DES-CBC-MD5 tickets crack instantly on modern GPUs.",
		PolicyNote: "Remove DES from domain-supported etypes; audit legacy apps.",
	},
	17: {
		Name: "aes128-cts-hmac-sha1-96", Family: "aes", Roastable: "yes", CrackDiff: "hard",
		HashcatTip: "hashcat 19600 (TGS AES128); still viable if password is weak/short.",
		PolicyNote: "Acceptable when paired with long random / gMSA passwords.",
	},
	18: {
		Name: "aes256-cts-hmac-sha1-96", Family: "aes", Roastable: "yes", CrackDiff: "very-hard",
		HashcatTip: "hashcat 19700 (TGS) / 19800 (AS-REP); prioritize wordlists + rules.",
		PolicyNote: "Preferred etype domain-wide; enforce AES256 where possible.",
	},
	19: {
		Name: "aes128-cts-hmac-sha256-128", Family: "aes", Roastable: "limited", CrackDiff: "very-hard",
		HashcatTip: "Newer AES-SHA2 profile; tooling support varies — note for inventory.",
		PolicyNote: "Track alongside classic AES128/256 in SupportedEncryptionTypes.",
	},
	20: {
		Name: "aes256-cts-hmac-sha384-192", Family: "aes", Roastable: "limited", CrackDiff: "very-hard",
		HashcatTip: "Newer AES-SHA2 profile; treat like AES256 for planning.",
		PolicyNote: "Modern clients/KDCs; still require strong service passwords.",
	},
	23: {
		Name: "rc4-hmac", Family: "rc4", Roastable: "yes", CrackDiff: "easy",
		HashcatTip: "hashcat 13100 (TGS) / 18200 (AS-REP) / 7500 (PA) — GPU-friendly.",
		PolicyNote: "Disable RC4_HMAC in domain policy; force AES for all principals.",
	},
	24: {
		Name: "rc4-hmac-exp", Family: "rc4", Roastable: "yes", CrackDiff: "easy",
		HashcatTip: "Export-grade RC4 — weaker than 23; escalate severity if seen.",
		PolicyNote: "Never allow export RC4; remove from SupportedEncryptionTypes.",
	},
	25: {
		Name: "camellia128-cts-cmac", Family: "camellia", Roastable: "limited", CrackDiff: "hard",
		HashcatTip: "Rare in AD; inventory only unless lab tooling supports it.",
		PolicyNote: "Unusual on Windows KDCs — verify interoperability needs.",
	},
	26: {
		Name: "camellia256-cts-cmac", Family: "camellia", Roastable: "limited", CrackDiff: "very-hard",
		HashcatTip: "Rare in AD; note presence for crypto-inventory reports.",
		PolicyNote: "Prefer AES256 on Windows domains unless Camellia is required.",
	},
}

func lookupEtype(e int) (string, etypeDetail, bool) {
	name, ok := etypeName[e]
	if !ok {
		return "", etypeDetail{}, false
	}
	if d, ok2 := etypeDetails[e]; ok2 {
		return name, d, true
	}
	return name, etypeDetail{Name: name, Family: "other", Roastable: "n/a", CrackDiff: "unknown",
		HashcatTip: "No local crack notes for this etype.",
		PolicyNote: "Document and research before recommending policy changes.",
	}, true
}

func etypeRoastHint(e int) string {
	_, d, ok := lookupEtype(e)
	if !ok {
		return "unknown etype"
	}
	return fmt.Sprintf("family=%s roastable=%s crack=%s", d.Family, d.Roastable, d.CrackDiff)
}

func etypeCatalogLines() []string {
	keys := make([]int, 0, len(etypeName))
	for k := range etypeName {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	var lines []string
	for _, k := range keys {
		name := etypeName[k]
		if d, ok := etypeDetails[k]; ok {
			lines = append(lines, fmt.Sprintf("%2d  %-32s  [%s] roast=%s crack=%s",
				k, name, d.Family, d.Roastable, d.CrackDiff))
			lines = append(lines, "    tip: "+d.HashcatTip)
		} else {
			lines = append(lines, fmt.Sprintf("%2d  %s", k, name))
		}
	}
	return lines
}

func parseKrbLine(line string, ln int) *krbHash {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return nil
	}
	patterns := []struct {
		kind, mode                          string
		re                                  *regexp.Regexp
		etypeIdx, userIdx, realmIdx, spnIdx int
	}{
		{"asrep", "18200", regexp.MustCompile(`(?i)^\$krb5asrep\$23\$([^@]+)@([^:]+):(.+)$`), 23, 1, 2, -1},
		{"asrep", "18200", regexp.MustCompile(`(?i)^\$krb5asrep\$(\d+)\$([^@]+)@([^:]+):(.+)$`), -1, 2, 3, -1},
		{"tgs", "13100", regexp.MustCompile(`(?i)^\$krb5tgs\$23\$\*?([^**$]+)\$([^$*]+)\$\*([^*]+)\*\$([0-9a-fA-F]+)\$(.+)$`), 23, 1, 2, 3},
		{"tgs", "13100", regexp.MustCompile(`(?i)^\$krb5tgs\$23\$.+`), 23, -1, -1, -1},
		{"tgs", "19700", regexp.MustCompile(`(?i)^\$krb5tgs\$18\$`), 18, -1, -1, -1},
		{"tgs", "19600", regexp.MustCompile(`(?i)^\$krb5tgs\$17\$`), 17, -1, -1, -1},
		{"pa", "7500", regexp.MustCompile(`(?i)^\$krb5pa\$23\$`), 23, -1, -1, -1},
		{"pa", "19900", regexp.MustCompile(`(?i)^\$krb5pa\$18\$`), 18, -1, -1, -1},
	}
	for _, p := range patterns {
		if !p.re.MatchString(line) {
			continue
		}
		h := &krbHash{Kind: p.kind, HCMode: p.mode, Raw: line, LineNo: ln, Etype: p.etypeIdx}
		m := p.re.FindStringSubmatch(line)
		if p.etypeIdx < 0 && len(m) > 1 {
			h.Etype = atoiOr(m[1], 0)
		}
		if p.userIdx > 0 && p.userIdx < len(m) {
			h.User = m[p.userIdx]
		}
		if p.realmIdx > 0 && p.realmIdx < len(m) {
			h.Realm = m[p.realmIdx]
		}
		if p.spnIdx > 0 && p.spnIdx < len(m) {
			h.SPN = m[p.spnIdx]
		}
		// fallback loose parse
		if h.User == "" {
			if mm := regexp.MustCompile(`(?i)\$krb5(?:asrep|tgs|pa)\$\d+\$\*?([^$*@]+)@?([^$*]*)`).FindStringSubmatch(line); len(mm) > 1 {
				h.User = mm[1]
				if len(mm) > 2 {
					h.Realm = strings.Trim(mm[2], "$")
				}
			}
		}
		if h.SPN == "" && p.kind == "tgs" {
			if mm := regexp.MustCompile(`\*([^*]+)\*`).FindStringSubmatch(line); len(mm) > 1 {
				h.SPN = mm[1]
			}
		}
		return h
	}
	return nil
}

type spnInfo struct {
	SPN     string
	Service string
	Host    string
	Risk    string
	Note    string
}

func classifySPN(spn string) spnInfo {
	info := spnInfo{SPN: spn, Risk: SevMed, Note: "Kerberoastable service ticket hash."}
	parts := strings.SplitN(spn, "/", 2)
	if len(parts) > 0 {
		info.Service = parts[0]
	}
	if len(parts) > 1 {
		info.Host = parts[1]
	}
	switch strings.ToLower(info.Service) {
	case "http", "https":
		info.Risk = SevHigh
		info.Note = "Web SPN — often tied to a user/service account with a crackable password."
	case "mssqlsvc", "msolapsvc", "msolapdisco.3":
		info.Risk = SevHigh
		info.Note = "SQL SPN — frequently high-value; cracked hash may yield DB admin."
	case "cifs", "host", "ldap", "dns", "gc":
		info.Risk = SevMed
		info.Note = "Machine-class SPN — usually long random password; lower roast value."
	case "exchange", "exchangemdb", "exchangeservices":
		info.Risk = SevHigh
		info.Note = "Exchange SPN — high-value mailbox / domain exposure."
	case "termsrv", "wsman":
		info.Risk = SevMed
		info.Note = "Remote access SPN."
	default:
		if info.Service != "" && !strings.Contains(strings.ToLower(info.Host), "$") {
			info.Risk = SevHigh
			info.Note = "Non-machine SPN — prioritize for offline cracking."
		}
	}
	return info
}

func analyzeKerberos(text, target string) AnalysisResult {
	res := AnalysisResult{Target: target, Tool: APPNAME, Stats: map[string]string{}}
	var findings []Finding
	var hashes []*krbHash
	for i, line := range strings.Split(text, "\n") {
		if h := parseKrbLine(line, i+1); h != nil {
			hashes = append(hashes, h)
		}
	}
	// also parse LDIF for roastable flags
	if strings.Contains(text, "userAccountControl") || strings.Contains(text, "servicePrincipalName") {
		findings = append(findings, analyzeLDIFRoast(text)...)
	}
	asrep, tgs, pa := 0, 0, 0
	rc4 := 0
	for i, h := range hashes {
		switch h.Kind {
		case "asrep":
			asrep++
			sev := SevHigh
			if h.Etype == 23 {
				sev = SevCrit
				rc4++
			}
			findings = append(findings, Finding{
				ID: fmt.Sprintf("KRB-ASREP-%03d", i+1), Title: "AS-REP roastable hash: " + nz(h.User, "?"),
				Severity: sev, Category: "asrep",
				Detail:   fmt.Sprintf("etype=%d (%s) realm=%s hashcat=%s", h.Etype, etypeName[h.Etype], h.Realm, h.HCMode),
				Evidence: preview(h.Raw, 100), Remediation: "Enable Kerberos pre-authentication (unset DONT_REQ_PREAUTH); reset password; monitor 4768.",
				Mitre: []string{"T1558.004"}, Score: sevWeight(sev),
			})
		case "tgs":
			tgs++
			spn := classifySPN(h.SPN)
			sev := spn.Risk
			if h.Etype == 23 {
				rc4++
				if sevRank(sev) < sevRank(SevHigh) {
					sev = SevHigh
				}
			}
			findings = append(findings, Finding{
				ID: fmt.Sprintf("KRB-TGS-%03d", i+1), Title: "Kerberoastable TGS: " + nz(h.SPN, nz(h.User, "?")),
				Severity: sev, Category: "kerberoast",
				Detail:   fmt.Sprintf("%s etype=%d (%s) user=%s hashcat=%s", spn.Note, h.Etype, etypeName[h.Etype], h.User, h.HCMode),
				Evidence: preview(h.Raw, 100), Remediation: "Use long random passwords on service accounts; prefer gMSA; disable RC4; monitor 4769.",
				Mitre: []string{"T1558.003"}, Score: sevWeight(sev),
			})
		case "pa":
			pa++
			findings = append(findings, Finding{
				ID: fmt.Sprintf("KRB-PA-%03d", i+1), Title: "Kerberos PA-ENC-TIMESTAMP hash",
				Severity: SevMed, Category: "preauth",
				Detail:   "Offline crackable preauth timestamp (etype " + strconv.Itoa(h.Etype) + ").",
				Evidence: preview(h.Raw, 80), Remediation: "Strong user passwords; detect spray via 4771.",
				Mitre: []string{"T1558"}, Score: sevWeight(SevMed),
			})
		}
	}
	if rc4 > 0 {
		findings = append(findings, Finding{
			ID: "KRB-RC4-001", Title: "RC4 (etype 23) tickets present", Severity: SevHigh,
			Category: "etype", Detail: fmt.Sprintf("%d RC4 hashes — far cheaper to crack than AES.", rc4),
			Remediation: "Disable RC4_HMAC in domain policy; enforce AES128/AES256.",
			Mitre:       []string{"T1558.003", "T1558.004"}, Score: sevWeight(SevHigh),
		})
	}
	res.Findings = findings
	res.Stats["hashes"] = strconv.Itoa(len(hashes))
	res.Stats["asrep"] = strconv.Itoa(asrep)
	res.Stats["tgs"] = strconv.Itoa(tgs)
	res.Stats["pa"] = strconv.Itoa(pa)
	res.Stats["rc4"] = strconv.Itoa(rc4)
	res.Grade = gradeFromFindings(findings)
	return res
}

func analyzeLDIFRoast(text string) []Finding {
	var out []Finding
	entries := parseLDIF(text)
	n := 0
	for _, e := range entries {
		if !e.HasClass("user") && !e.HasClass("person") {
			continue
		}
		uac := atoiOr(e.Attr("userAccountControl"), 0)
		sam := e.Attr("sAMAccountName")
		spns := e.Attrs["servicePrincipalName"]
		// DONT_REQ_PREAUTH = 0x400000
		if uac&0x400000 != 0 {
			n++
			out = append(out, Finding{
				ID: fmt.Sprintf("KRB-LDAP-ASREP-%03d", n), Title: "DONT_REQ_PREAUTH set: " + sam,
				Severity: SevHigh, Category: "ldap-asrep",
				Detail:   "Account does not require Kerberos pre-authentication — AS-REP roastable.",
				Evidence: e.DN, Remediation: "Clear DONT_REQ_PREAUTH in account options.",
				Mitre: []string{"T1558.004"}, Score: sevWeight(SevHigh),
			})
		}
		if len(spns) > 0 && !strings.HasSuffix(sam, "$") {
			for _, spn := range spns {
				n++
				info := classifySPN(spn)
				out = append(out, Finding{
					ID: fmt.Sprintf("KRB-LDAP-SPN-%03d", n), Title: "User account with SPN: " + sam + " → " + spn,
					Severity: info.Risk, Category: "ldap-kerberoast",
					Detail: info.Note, Evidence: e.DN,
					Remediation: "Move SPN to a gMSA or computer account; enforce long password.",
					Mitre:       []string{"T1558.003"}, Score: sevWeight(info.Risk),
				})
			}
		}
	}
	return out
}

func domainAnalyze(path string) (AnalysisResult, error) {
	text, err := readFileString(path)
	if err != nil {
		return AnalysisResult{}, err
	}
	return analyzeKerberos(text, baseName(path)), nil
}

func domainDemoResult() AnalysisResult {
	demo := strings.Join([]string{
		"$krb5asrep$23$svc_backup@CORP.LOCAL:AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899",
		"$krb5tgs$23$*svc_sql$CORP.LOCAL$MSSQLSvc/sql01.corp.local:1433*$0123456789abcdef0123456789abcdef$0123456789abcdef0123456789abcdef0123456789abcdef",
		"$krb5tgs$18$app_web$CORP.LOCAL$*HTTP/web.corp.local*$0123456789abcdef0123456789abcdef$0123456789abcdef",
		"dn: CN=svc_backup,OU=Service,DC=corp,DC=local",
		"objectClass: user",
		"sAMAccountName: svc_backup",
		"userAccountControl: 4194304",
		"",
		"dn: CN=svc_sql,OU=Service,DC=corp,DC=local",
		"objectClass: user",
		"sAMAccountName: svc_sql",
		"servicePrincipalName: MSSQLSvc/sql01.corp.local:1433",
		"userAccountControl: 512",
	}, "\n")
	res := analyzeKerberos(demo, "demo-kerberos")
	res.Notes = append(res.Notes, "Demo mixes synthetic hashcat lines with LDIF roast flags; no KDC was contacted.")
	res.Notes = append(res.Notes, "hashcat: mode 18200 (AS-REP RC4), 13100 (TGS RC4), 19700 (TGS AES256).")
	return res
}

func domainHowtoSteps() []string {
	return []string{
		"Collect hashes: Rubeus asreproast/kerberoast, Impacket GetNPUsers/GetUserSPNs, or a raw hash file.",
		"Optionally include an LDIF/CSV of users with uAC + SPN attributes (DONT_REQ_PREAUTH, servicePrincipalName).",
		"Run OKerberang --input FILE to classify hashes and roastable accounts (offline; no KDC contact).",
		"Review AS-REP (T1558.004) and TGS (T1558.003) findings; prioritize RC4 (etype 23) and user-owned SPNs.",
		"Use the catalog / etype explainer to map each hash to hashcat mode and crack-difficulty notes.",
		"Export hashcat-ready material (raw lines already in hashcat format) and crack offline in the lab.",
		"Plan delegation follow-ups: unconstrained / constrained / resource-based (S4U2Self + S4U2Proxy) paths.",
		"If Pass-the-Ticket (T1550.003) is in scope, document ticket reuse separately — this tool only classifies.",
		"Remediate: enable preauth, gMSA for services, disable RC4, long random passwords, tighten delegation.",
		"Hand findings to blue team with Windows event IDs (4768/4769/4771) and MITRE IDs from the report.",
	}
}

func domainRequirements() []string {
	return []string{
		"Offline hash dump and/or LDIF/CSV — no live KDC access required by this tool.",
		"Authorization to assess the AD domain's Kerberos posture.",
		"Optional: hashcat/john in the lab for offline cracking of exported hashes.",
	}
}

func domainHowtoNotes() []Section {
	return []Section{
		{Title: "HASHCAT MODES", Lines: []string{
			"18200  $krb5asrep$23$   AS-REP roast (RC4)",
			"19800  $krb5asrep$18$   AS-REP roast (AES256)",
			"13100  $krb5tgs$23$     Kerberoast TGS (RC4)",
			"19600  $krb5tgs$17$     Kerberoast TGS (AES128)",
			"19700  $krb5tgs$18$     Kerberoast TGS (AES256)",
			"7500   $krb5pa$23$      Preauth timestamp (RC4)",
			"19900  $krb5pa$18$      Preauth timestamp (AES256)",
		}},
		{Title: "UAC / ACCOUNT FLAGS", Lines: []string{
			"DONT_REQ_PREAUTH = 0x00400000 (4194304) — AS-REP roastable when set.",
			"TRUSTED_FOR_DELEGATION = 0x00080000 — unconstrained delegation (high risk).",
			"TRUSTED_TO_AUTH_FOR_DELEGATION = 0x01000000 — constrained (S4U2Proxy) enabled.",
			"NOT_DELEGATED = 0x00100000 — account is sensitive and cannot be delegated.",
			"Use LDIF userAccountControl + msDS-AllowedToDelegateTo for path planning.",
		}},
		{Title: "DELEGATION PATH NOTES (S4U2Self / S4U2Proxy)", Lines: []string{
			"S4U2Self: a trusted service obtains a TGS to itself on behalf of a user.",
			"S4U2Proxy: that service then requests a TGS to a front-end SPN (constrained).",
			"Resource-Based Constrained Delegation (RBCD): msDS-AllowedToActOnBehalfOfOtherIdentity.",
			"Unconstrained delegation stores forwardable TGTs — combine with coercion (T1187) planning.",
			"OKerberang does not live-abuse S4U; use catalog notes to prioritize offline review.",
			"Correlate roastable service hashes with BloodHound edges (AllowedToDelegate, etc.).",
		}},
		{Title: "DETECTION GUIDANCE", Lines: detectionGuidanceLines()},
		mitreKerberosCatalogSection(),
	}
}

func detectionGuidanceLines() []string {
	return []string{
		"4768 (TGT requested) with Preauth Type = 0 → likely AS-REP roast attempt (T1558.004).",
		"4768 spikes for many users from one host → AS-REP enumeration / spraying adjacent activity.",
		"4769 (TGS requested) volume spikes, especially RC4 etype=0x17 → Kerberoast (T1558.003).",
		"4769 for unusual SPNs (MSSQLSvc/HTTP/Exchange) from non-app hosts → prioritize triage.",
		"4771 (Kerberos pre-auth failed) bursts → password spray / brute against preauth accounts.",
		"Ticket encryption type anomalies (RC4 when AES is mandated) → weak etype policy or attack.",
		"Pass-the-Ticket (T1550.003): 4769 without matching interactive logon; odd workstation names.",
		"Forced auth / coercion (T1187): sudden machine auth to attacker-controlled listener.",
		"Baseline per-user TGS request volume; alert on deviation + RC4 combination.",
		"Monitor krbtgt password age; dual-reset after suspected Golden Ticket (T1558.001).",
		"Alert on TGS without prior TGT for Silver Ticket (T1558.002) hunting hypotheses.",
		"Export SIEM queries with account, SPN, Ticket Encryption Type, and Client Address fields.",
	}
}

func domainCatalogSections() []Section {
	modes := []string{
		"18200 AS-REP RC4          ($krb5asrep$23$)",
		"19800 AS-REP AES256       ($krb5asrep$18$)",
		"13100 TGS RC4             ($krb5tgs$23$)",
		"19600 TGS AES128          ($krb5tgs$17$)",
		"19700 TGS AES256          ($krb5tgs$18$)",
		"7500  PA RC4              ($krb5pa$23$)",
		"19900 PA AES256           ($krb5pa$18$)",
	}
	return []Section{
		krbNotesSection(),
		mitreKerberosCatalogSection(),
		{Title: "KERBEROS ETYPES (roastability)", Lines: etypeCatalogLines()},
		{Title: "HASHCAT MODES", Lines: modes},
		{Title: "HIGH-VALUE SPN PREFIXES", Lines: []string{
			"MSSQLSvc / HTTP / HTTPS / exchange* / TERMSRV / WSMAN / LDAP (user-owned)",
			"Prefer user accounts with SPNs over MACHINE$ accounts for roast priority.",
			"gMSA-backed SPNs are usually impractical to crack (120-char random).",
		}},
		{Title: "DETECTION QUICK REF", Lines: detectionGuidanceLines()},
	}
}

func domainMenuItems() []MenuItem {
	return []MenuItem{
		{Label: "Classify a single hash line", Action: actionKrbClassify},
		{Label: "Explain an etype", Action: actionEtype},
		{Label: "SPN risk classifier", Action: actionSPN},
	}
}

func actionKrbClassify() {
	clear()
	banner()
	fmt.Println("  " + col("⬡ CLASSIFY HASH", CY+B))
	fmt.Println()
	line := prompt("hash line")
	h := parseKrbLine(line, 1)
	if h == nil {
		warnMsg("unrecognized kerberos hash")
		pause()
		return
	}
	okMsg(h.Kind + " etype=" + strconv.Itoa(h.Etype) + " (" + etypeName[h.Etype] + ")")
	info("user=" + h.User + " realm=" + h.Realm + " spn=" + h.SPN)
	info("hashcat mode " + h.HCMode)
	info(etypeRoastHint(h.Etype))
	if _, d, ok := lookupEtype(h.Etype); ok && d.HashcatTip != "" {
		info(d.HashcatTip)
	}
	pause()
}

func actionEtype() {
	clear()
	banner()
	fmt.Println("  " + col("⬡ ETYPE", CY+B))
	fmt.Println()
	e := atoiOr(prompt("etype number"), -1)
	name, d, ok := lookupEtype(e)
	if !ok {
		warnMsg("unknown etype")
		pause()
		return
	}
	okMsg(fmt.Sprintf("%d = %s", e, name))
	fmt.Println("   " + col("family     : ", GY) + col(d.Family, W))
	fmt.Println("   " + col("roastable  : ", GY) + col(d.Roastable, W))
	fmt.Println("   " + col("crack diff : ", GY) + col(d.CrackDiff, W))
	info(d.HashcatTip)
	info(d.PolicyNote)
	if e == 23 || e == 24 {
		warnMsg("RC4 family — prioritize cracking / disable in domain policy")
	}
	if e == 1 || e == 2 || e == 3 {
		warnMsg("DES family — critical legacy crypto; remediate immediately")
	}
	if e == 17 || e == 18 || e == 19 || e == 20 {
		info("AES family — stronger; still crackable when passwords are weak")
	}
	pause()
}

func actionSPN() {
	clear()
	banner()
	fmt.Println("  " + col("⬡ SPN RISK", CY+B))
	fmt.Println()
	spn := prompt("SPN (e.g. MSSQLSvc/sql01.corp.local:1433)")
	info2 := classifySPN(spn)
	okMsg(info2.SPN)
	fmt.Println("   " + col("service : ", GY) + col(info2.Service, W))
	fmt.Println("   " + col("host    : ", GY) + col(info2.Host, W))
	fmt.Println("   " + col("risk    : ", GY) + col(info2.Risk, sevColor(info2.Risk)))
	fmt.Println("   " + col("note    : ", GY) + col(info2.Note, W))
	pause()
}

func preview(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

var krbOpNotes = []string{
	"Prefer AES etypes domain-wide; track msDS-SupportedEncryptionTypes.",
	"gMSA passwords are 120 chars random — not practically roastable.",
	"Monitor 4769 RC4 spikes; baseline per-user TGS request volume.",
	"AS-REP roast without preauth is often a single weak service account.",
	"Silver/Golden ticket forging is out of scope here (T1558.001 / T1558.002 labs).",
	"Pass-the-Ticket (T1550.003) planning is separate from roast hash export.",
	"S4U2Self/S4U2Proxy and RBCD edges amplify cracked service hashes — map them.",
	"Forced authentication (T1187) can feed unconstrained-delegation paths.",
	"Always crack offline; never spray cracked passwords outside of scope.",
	"Export only the hash lines you intend to crack; redact unrelated secrets.",
	"Correlate roastable SPNs with BloodHound paths to Domain Admins.",
	"RC4 (23) ≪ AES128 (17) ≪ AES256 (18) for GPU crack cost — triage accordingly.",
	"Disable DES and RC4; require AES; dual-reset krbtgt after suspected forgery.",
}

func krbNotesSection() Section { return Section{Title: "OPERATOR NOTES", Lines: krbOpNotes} }

// ============================================================================
//  Help & Usage  (interactive menu [H])  +  self-test
// ============================================================================

var owlHelpAbout = []string{
	"OKerberang is an OFFLINE Kerberos ticket & hash analyzer for authorized " +
		"Active Directory assessments. It never contacts a live KDC — you bring " +
		"captured material (Rubeus / Impacket / hashcat-format dumps, or an LDIF/CSV).",
	"",
	"It classifies AS-REP roastable ($krb5asrep$) and Kerberoastable ($krb5tgs$) " +
		"hashes, extracts SPNs, maps encryption types (RC4/AES128/AES256) to hashcat " +
		"modes (18200/13100/19600/19700), flags DONT_REQ_PREAUTH accounts, and grades " +
		"the domain's Kerberos exposure with MITRE ATT&CK (T1558.*) mapping.",
}

var owlHelpFlow = []string{
	"Pick [1] Run DEMO first to see a full synthetic walkthrough and grade.",
	"Then [2] Analyze an input file on your own hash dump / LDIF / CSV.",
	"Use [3] Reference catalog and the classifier helpers to understand each hash.",
	"View / export the last result, then crack exported hashes offline in the lab.",
	"Type the number and press Enter. [00] exits, [H] opens this help.",
}

var owlHelpMenu = []owlHelpItem{
	{"1", "Run DEMO — synthetic hashes + LDIF, full classify & grade (no KDC)."},
	{"2", "Analyze an input file — hash dump, Rubeus/Impacket output, LDIF or CSV."},
	{"3", "Reference catalog — etypes, hashcat modes, SPN prefixes, detection ref."},
	{"4", "Classify a single hash line — paste one $krb5asrep$/$krb5tgs$ line."},
	{"5", "Explain an etype — RC4/AES family, roastability, crack difficulty."},
	{"6", "SPN risk classifier — service/host split and roast priority."},
	{"7", "View last result — re-render the most recent analysis."},
	{"8", "Export last result — write txt/md/json/csv/sarif."},
	{"9", "About / MITRE mapping — tool identity and ATT&CK technique IDs."},
	{"H", "This help & usage screen (two pages)."},
	{"00", "Exit."},
}

var owlHelpTips = []owlHelpItem{
	{"*", "Hashes are already hashcat-ready: 18200 AS-REP RC4, 13100 TGS RC4, 19700 TGS AES256."},
	{"*", "RC4 (etype 23) cracks far faster than AES — triage those service accounts first."},
	{"*", "DONT_REQ_PREAUTH (uAC 0x400000) = AS-REP roastable without any credentials."},
	{"*", "Prefer user-owned SPNs over MACHINE$; gMSA passwords are ~impractical to crack."},
	{"*", "--howto prints the full legal / workflow screen; --selftest validates the engine."},
	{"*", "Authorized testing only. This tool classifies offline material; it never abuses S4U."},
}

func owlHelpCLI() {
	// Page 2 of the in-app help mirrors the command-line reference (--help).
	bak := *flQuiet
	*flQuiet = false
	usage()
	*flQuiet = bak
}

// ---------------------------------------------------------------------------
//  Self-test (--selftest): exercise the engine on known vectors, no I/O.
// ---------------------------------------------------------------------------

func runSelfTest() int {
	pass, fail := 0, 0
	check := func(name string, ok bool) {
		if ok {
			pass++
			fmt.Println("  " + col("[✔] ", GRN+B) + col(name, W))
		} else {
			fail++
			fmt.Println("  " + col("[✘] ", R+B) + col(name, R))
		}
	}
	oldNC := noColor
	_ = oldNC

	// 1-4: AS-REP RC4 parse
	as := parseKrbLine("$krb5asrep$23$svc_backup@CORP.LOCAL:AABBCCDDEEFF00112233445566778899AABBCCDDEEFF0011", 1)
	check("AS-REP: recognized", as != nil)
	if as != nil {
		check("AS-REP: kind=asrep", as.Kind == "asrep")
		check("AS-REP: etype 23 (RC4)", as.Etype == 23)
		check("AS-REP: hashcat mode 18200", as.HCMode == "18200")
		check("AS-REP: user=svc_backup", as.User == "svc_backup")
	}

	// 5-8: Kerberoast TGS RC4 parse
	tgs := parseKrbLine("$krb5tgs$23$*svc_sql$CORP.LOCAL$MSSQLSvc/sql01.corp.local:1433*$0123456789abcdef0123456789abcdef$0123456789abcdef0123456789abcdef", 2)
	check("TGS: recognized", tgs != nil)
	if tgs != nil {
		check("TGS: kind=tgs", tgs.Kind == "tgs")
		check("TGS: hashcat mode 13100", tgs.HCMode == "13100")
		check("TGS: SPN extracted", strings.Contains(tgs.SPN, "MSSQLSvc/sql01.corp.local"))
	}

	// 9: TGS AES256 mode
	tgsA := parseKrbLine("$krb5tgs$18$app_web$CORP.LOCAL$*HTTP/web.corp.local*$00$00", 3)
	check("TGS AES256: mode 19700", tgsA != nil && tgsA.HCMode == "19700" && tgsA.Etype == 18)

	// 10: non-kerberos line rejected
	check("non-kerberos line rejected", parseKrbLine("just some text", 4) == nil)

	// 11: etype lookup RC4 roastable
	if name, d, ok := lookupEtype(23); ok {
		check("etype 23 name/roastable", strings.Contains(strings.ToLower(name), "rc4") && d.Roastable != "")
	} else {
		check("etype 23 name/roastable", false)
	}

	// 12: SPN classifier splits service/host
	sp := classifySPN("MSSQLSvc/sql01.corp.local:1433")
	check("SPN classify service=MSSQLSvc", strings.EqualFold(sp.Service, "MSSQLSvc"))

	// 13-16: full demo analysis + grade + export round-trips
	res := domainDemoResult()
	finalize(&res)
	check("demo: findings present", len(res.Findings) > 0)
	check("demo: grade assigned", res.Grade != "")
	hasAsrep, hasTgs := false, false
	for _, f := range res.Findings {
		t := strings.ToLower(f.Title + f.Detail + f.Category)
		if strings.Contains(t, "as-rep") || strings.Contains(t, "asrep") {
			hasAsrep = true
		}
		if strings.Contains(t, "kerberoast") || strings.Contains(t, "tgs") {
			hasTgs = true
		}
	}
	check("demo: detects AS-REP roast", hasAsrep)
	check("demo: detects Kerberoast", hasTgs)

	// 17-19: exporters produce non-empty, valid-ish output
	check("export txt non-empty", len(exportTXT(&res)) > 50)
	js := exportJSON(&res)
	var jv interface{}
	check("export json valid", json.Unmarshal([]byte(js), &jv) == nil)
	check("export sarif has schema", strings.Contains(exportSARIF(&res), "sarif"))

	fmt.Println()
	line(64)
	if fail == 0 {
		fmt.Println("  " + col(fmt.Sprintf("[✔] self-test PASSED — %d/%d checks", pass, pass), GRN+B))
		return 0
	}
	fmt.Println("  " + col(fmt.Sprintf("[✘] self-test FAILED — %d passed, %d failed", pass, fail), R+B))
	return 1
}

// ---------------------------------------------------------------------------
// Help & Usage  (interactive menu [H])
// Page 1: in-app guide (what the tool does, every menu option, tips).
// Page 2: the full command-line reference (same text as --help).
// ---------------------------------------------------------------------------

type owlHelpItem struct{ key, text string }

func owlHelpWrap(s string, width int) []string {
	var out []string
	for _, para := range strings.Split(s, "\n") {
		words := strings.Fields(para)
		if len(words) == 0 {
			out = append(out, "")
			continue
		}
		cur := ""
		for _, w := range words {
			if cur != "" && len([]rune(cur))+1+len([]rune(w)) > width {
				out = append(out, cur)
				cur = w
			} else if cur == "" {
				cur = w
			} else {
				cur += " " + w
			}
		}
		out = append(out, cur)
	}
	return out
}

func owlHelpTitle(t string) {
	fmt.Println()
	fmt.Println("  " + col("▸ "+t, B+CY))
}

func owlHelpPara(lines []string) {
	for _, l := range lines {
		for _, w := range owlHelpWrap(l, 60) {
			fmt.Println("    " + col(w, W))
		}
	}
}

func owlHelpRows(items []owlHelpItem) {
	kw := 0
	for _, it := range items {
		if n := len([]rune(it.key)); n > kw {
			kw = n
		}
	}
	for _, it := range items {
		k := "[" + it.key + "]" + strings.Repeat(" ", kw-len([]rune(it.key)))
		for i, w := range owlHelpWrap(it.text, 56-kw) {
			if i == 0 {
				fmt.Println("    " + col(k, YLW+B) + "  " + col(w, W))
			} else {
				fmt.Println("    " + strings.Repeat(" ", kw+2) + "  " + col(w, W))
			}
		}
	}
}

func owlHelpRule() { fmt.Println(col(strings.Repeat("─", 66), CY)) }

func tuiHelp() {
	clear()
	banner()
	owlHelpRule()
	fmt.Println("  " + col("⬡  Help & Usage — "+APPNAME, B+CY))
	owlHelpRule()
	owlHelpTitle("WHAT IT DOES")
	owlHelpPara(owlHelpAbout)
	owlHelpTitle("HOW TO USE THE MENU")
	owlHelpPara(owlHelpFlow)
	owlHelpTitle("MENU OPTIONS")
	owlHelpRows(owlHelpMenu)
	owlHelpTitle("TIPS")
	owlHelpRows(owlHelpTips)
	fmt.Println()
	owlHelpRule()
	fmt.Println("  " + col("Next page: command-line flags & copy-paste examples", DIM))
	pause()
	clear()
	owlHelpCLI()
	fmt.Println()
	fmt.Println("  " + col("Tip: the same reference is printed by  "+APPNAME+" --help", DIM))
	pause()
}
