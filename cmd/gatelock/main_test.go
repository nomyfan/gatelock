package main

import (
	"context"
	"errors"
	"image/png"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/egoist/mygo/ui"

	"gatelock/internal/history"
	"gatelock/internal/vault"
)

type memKeychain map[string][]byte

func (k memKeychain) Get(a string) ([]byte, error) {
	if v, ok := k[a]; ok {
		return v, nil
	}
	return nil, errors.New("not found")
}
func (k memKeychain) Set(a string, v []byte) error { k[a] = v; return nil }
func (k memKeychain) Delete(a string) error        { delete(k, a); return nil }

type denyAll struct{}

func (denyAll) ConfirmUser(context.Context, string) error { return vault.ErrDenied }
func (denyAll) AskPassphrase(context.Context, string, string, bool) ([]byte, error) {
	return nil, vault.ErrDenied
}

// testApp is an app over a vault with a namespace, and a record of runs.
func testApp(t *testing.T) *app {
	t.Helper()
	dir := t.TempDir()
	v, err := vault.Open(filepath.Join(dir, "namespaces"), memKeychain{}, denyAll{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Create("prod-api", []byte("pw"), true, vault.Policy{Mode: vault.Session}); err != nil {
		t.Fatal(err)
	}
	v.SetEnv("prod-api", "STRIPE_KEY", []byte("sk_live_1"))
	v.SetEnv("prod-api", "PORT", []byte("5432"))
	v.SetSensitive("prod-api", "PORT", false)
	h, err := history.Open(filepath.Join(dir, "runs"), func() {})
	if err != nil {
		t.Fatal(err)
	}
	rec, _ := h.Begin("prod-api", []string{"npm", "run", "deploy"}, "/work/api", func() {})
	rec.Authorized()
	rec.Write([]byte("deploying with [REDACTED:prod-api/STRIPE_KEY]\n"))
	rec.Exited(0)
	running, _ := h.Begin("prod-api", []string{"npm", "run", "dev"}, "/work/api", func() {})
	running.Authorized()

	a := &app{home: dir, vault: v, history: h}
	a.view.page = pageRuns
	a.refresh()
	return a
}

// snapshot saves the tester's frame as name.png in $GATELOCK_SNAPSHOTS,
// when set, to look at.
func snapshot(t *testing.T, tt *ui.Tester, name string) {
	dir := os.Getenv("GATELOCK_SNAPSHOTS")
	if dir == "" {
		return
	}
	f, err := os.Create(filepath.Join(dir, name+".png"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	png.Encode(f, tt.Image())
}

func TestPagesInBothAppearances(t *testing.T) {
	for _, dark := range []bool{false, true} {
		a := testApp(t)
		tt := ui.NewTester(a.mainView, 960, 640)
		tt.SetDark(dark)
		tt.Frame()
		kind := map[bool]string{false: "light", true: "dark"}[dark]

		if !tt.HasText("npm run dev") || !tt.HasText("running") || !tt.HasText("exit 0") {
			t.Fatalf("%s runs page: %q", kind, tt.Texts())
		}
		if err := tt.Click("npm run deploy"); err != nil {
			t.Fatal(err)
		}
		if !tt.HasText("deploying with [REDACTED:prod-api/STRIPE_KEY]\n") {
			t.Errorf("%s: output not shown: %q", kind, tt.Texts())
		}
		snapshot(t, tt, "runs-"+kind)

		if err := tt.Click("prod-api"); err != nil {
			t.Fatal(err)
		}
		if !tt.HasText("STRIPE_KEY") || !tt.HasText("PORT") || tt.HasText("sk_live_1") {
			t.Errorf("%s namespace page: %q", kind, tt.Texts())
		}
		snapshot(t, tt, "namespace-"+kind)

		if err := tt.Click("Settings"); err != nil {
			t.Fatal(err)
		}
		if !tt.HasText("prod-api Settings") {
			t.Errorf("%s: settings not open: %q", kind, tt.Texts())
		}
		snapshot(t, tt, "settings-"+kind)
	}
}

func TestAddEnv(t *testing.T) {
	a := testApp(t)
	tt := ui.NewTester(a.mainView, 960, 640)
	tt.Click("prod-api")
	tt.Click("Key")
	tt.Type("NEW_TOKEN")
	tt.Click("Value")
	tt.Type("secret")
	if err := tt.Click("Add"); err != nil {
		t.Fatal(err)
	}
	ns, _ := a.vault.Namespace("prod-api")
	var keys []string
	for _, e := range ns.Envs {
		keys = append(keys, e.Key)
	}
	if strings.Join(keys, ",") != "NEW_TOKEN,PORT,STRIPE_KEY" || !tt.HasText("NEW_TOKEN") {
		t.Fatalf("envs %v, texts %q", keys, tt.Texts())
	}
}

func TestStopFromRunsPage(t *testing.T) {
	a := testApp(t)
	stopped := false
	rec, _ := a.history.Begin("prod-api", []string{"sleep", "60"}, "/", func() { stopped = true })
	rec.Authorized()
	a.refresh()
	tt := ui.NewTester(a.mainView, 960, 640)
	tt.Click("sleep 60")
	if err := tt.Click("Stop"); err != nil {
		t.Fatal(err)
	}
	if !stopped {
		t.Fatal("stop not asked")
	}
}

func TestSetEnvReplacesInEnviron(t *testing.T) {
	env := setEnv([]string{"PATH=/bin", "TOKEN=old", "TOKENX=keep"}, "TOKEN", "new")
	if strings.Join(env, " ") != "PATH=/bin TOKENX=keep TOKEN=new" {
		t.Fatalf("got %v", env)
	}
}

func TestLockHidesValuesShownAndUnderWay(t *testing.T) {
	a := testApp(t)
	a.view.page, a.view.revealedNS = nsPage("prod-api"), "prod-api"
	a.view.revealed = map[string]string{"STRIPE_KEY": "sk_live_1"}
	tt := ui.NewTester(a.mainView, 960, 640)
	if !tt.HasText("sk_live_1") {
		t.Fatalf("value not shown: %q", tt.Texts())
	}
	gen := a.view.revealGen
	a.lock("")
	tt.Frame()
	if tt.HasText("sk_live_1") {
		t.Fatal("value still shown after locking")
	}
	if a.view.revealGen == gen {
		t.Fatal("a reveal under way would still show its values")
	}
}
