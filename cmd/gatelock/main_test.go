package main

import (
	"context"
	"errors"
	"image/png"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

// testApp is an app over a store with a vault, and a record of activities.
func testApp(t *testing.T) *app {
	t.Helper()
	dir := t.TempDir()
	v, err := vault.Open(filepath.Join(dir, "vaults"), memKeychain{}, denyAll{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Create("prod-api", []byte("pw"), true, vault.Policy{Mode: vault.Session}); err != nil {
		t.Fatal(err)
	}
	v.SetEnv("prod-api", "STRIPE_KEY", []byte("sk_live_1"))
	v.SetEnv("prod-api", "PORT", []byte("5432"))
	v.SetSensitive("prod-api", "PORT", false)
	h, err := history.Open(filepath.Join(dir, "activities"), func() {})
	if err != nil {
		t.Fatal(err)
	}
	rec, _ := h.Begin("prod-api", []string{"npm", "run", "deploy"}, "/work/api", func() {})
	rec.Authorized()
	rec.Write([]byte("deploying with [REDACTED:prod-api/STRIPE_KEY]\n"))
	rec.Exited(0)
	running, _ := h.Begin("prod-api", []string{"npm", "run", "dev"}, "/work/api", func() {})
	running.Authorized()

	a := &app{home: dir, vaults: v, history: h}
	a.view.page = pageActivities
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

		if !tt.HasText("npm run dev") || !tt.HasText("npm run deploy") || tt.HasText("exit 0") {
			t.Fatalf("%s activities page: %q", kind, tt.Texts())
		}
		if err := tt.Click("npm run deploy"); err != nil {
			t.Fatal(err)
		}
		if !tt.HasText("deploying with [REDACTED:prod-api/STRIPE_KEY]") {
			t.Errorf("%s: output not shown: %q", kind, tt.Texts())
		}
		snapshot(t, tt, "activities-"+kind)

		if err := tt.Click("prod-api"); err != nil {
			t.Fatal(err)
		}
		if !tt.HasText("STRIPE_KEY") || !tt.HasText("PORT") || tt.HasText("sk_live_1") {
			t.Errorf("%s vault page: %q", kind, tt.Texts())
		}
		snapshot(t, tt, "vault-"+kind)

		if err := tt.Click("Settings…"); err != nil {
			t.Fatal(err)
		}
		if !tt.HasText("Keep in the Keychain") {
			t.Errorf("%s: settings not open: %q", kind, tt.Texts())
		}
		snapshot(t, tt, "settings-"+kind)
	}
}

func TestAddEnv(t *testing.T) {
	a := testApp(t)
	tt := ui.NewTester(a.mainView, 960, 640)
	tt.Click("prod-api")
	if err := tt.Click("Add Env…"); err != nil {
		t.Fatal(err)
	}
	tt.Type("NEW_TOKEN")
	tt.Click("Value")
	tt.Type("secret")
	if err := tt.Click("Add"); err != nil {
		t.Fatal(err)
	}
	if a.view.form.open {
		t.Fatal("the new row is still there")
	}
	vt, _ := a.vaults.Vault("prod-api")
	var keys []string
	for _, e := range vt.Envs {
		keys = append(keys, e.Key)
	}
	if strings.Join(keys, ",") != "NEW_TOKEN,PORT,STRIPE_KEY" || !tt.HasText("NEW_TOKEN") {
		t.Fatalf("envs %v, texts %q", keys, tt.Texts())
	}
}

func TestStopFromActivitiesPage(t *testing.T) {
	a := testApp(t)
	stopped := false
	rec, _ := a.history.Begin("prod-api", []string{"sleep", "60"}, "/", func() { stopped = true })
	rec.Authorized()
	a.refresh()
	tt := ui.NewTester(a.mainView, 960, 640)
	if err := tt.Click("Stop"); err != nil {
		t.Fatal(err)
	}
	if !stopped {
		t.Fatal("stop not asked")
	}
	if len(a.view.activityViews) != 0 {
		t.Fatal("stopping opened the activity too")
	}
}

func TestActivitiesOpenAndCloseOnTheirOwn(t *testing.T) {
	a := testApp(t)
	tt := ui.NewTester(a.mainView, 960, 640)
	tt.Click("npm run deploy")
	tt.Click("npm run dev")
	if !tt.HasText("deploying with [REDACTED:prod-api/STRIPE_KEY]") || !tt.HasText("(no output)") {
		t.Fatalf("both should be open: %q", tt.Texts())
	}
	tt.Click("npm run deploy")
	tt.Advance(time.Second)
	if tt.HasText("deploying with [REDACTED:prod-api/STRIPE_KEY]") || !tt.HasText("(no output)") {
		t.Fatalf("only npm run dev should be open: %q", tt.Texts())
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
	a.view.page, a.view.revealedVault = pageVault("prod-api"), "prod-api"
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

func TestCopyShowsOnlyWithTheValue(t *testing.T) {
	a := testApp(t)
	a.view.page = pageVault("prod-api")
	tt := ui.NewTester(a.mainView, 960, 640)
	if _, ok := tt.Find("Copy Value"); ok {
		t.Fatal("copy offered for a hidden value")
	}
	a.view.revealedVault, a.view.revealed = "prod-api", map[string]string{"STRIPE_KEY": "sk_live_1", "PORT": "5432"}
	tt.Frame()
	// Not clicked: the clipboard is the system's, and needs the running app.
	if _, ok := tt.Find("Copy Value"); !ok {
		t.Fatalf("copy not offered for a value shown: %q", tt.Texts())
	}
}

func TestWritePrivateFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".env.prod-api")
	os.WriteFile(path, []byte("old, longer content"), 0o644)
	if err := writePrivateFile(path, []byte("A=\"1\"\n")); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(path)
	data, _ := os.ReadFile(path)
	if info.Mode().Perm() != 0o600 || string(data) != "A=\"1\"\n" {
		t.Fatalf("mode %v, content %q", info.Mode().Perm(), data)
	}
}

func TestClearEndedActivities(t *testing.T) {
	a := testApp(t)
	tt := ui.NewTester(a.mainView, 960, 640)
	tt.Click("npm run deploy")
	if err := tt.Click("Clear Ended Activities…"); err != nil {
		t.Fatal(err)
	}
	if err := tt.Click("Clear"); err != nil {
		t.Fatal(err)
	}
	tt.Frame()
	if !tt.HasText("npm run dev") || tt.HasText("npm run deploy") || len(a.view.activityViews) != 0 {
		t.Fatalf("texts %q, views %v", tt.Texts(), a.view.activityViews)
	}
	if _, ok := tt.Find("Clear Ended Activities…"); ok {
		t.Fatal("clear shown with nothing ended")
	}
}

func TestDeleteFromSidebarShowsOnHover(t *testing.T) {
	a := testApp(t)
	tt := ui.NewTester(a.mainView, 960, 640)
	if _, ok := tt.Find("Delete prod-api…"); ok {
		t.Fatal("delete shown without hover")
	}
	r, _ := tt.Find("prod-api")
	tt.Move(r.X+r.W/2, r.Y+r.H/2)
	tt.Frame()
	if err := tt.Click("Delete prod-api…"); err != nil {
		t.Fatalf("delete not shown on hover: %v", err)
	}
	if !a.view.deletingVault || a.view.deleteVault != "prod-api" || a.view.page != pageActivities {
		t.Fatalf("deleting %v %q, page %q", a.view.deletingVault, a.view.deleteVault, a.view.page)
	}
}

func TestDotenvMenu(t *testing.T) {
	a := testApp(t)
	a.view.page = pageVault("prod-api")
	tt := ui.NewTester(a.mainView, 960, 640)
	if err := tt.Click(".env File"); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(tt.Menu(), ", "); got != "Import from .env…, Export to .env…" {
		t.Fatalf("menu %q", got)
	}
}

func TestAddEnvLeftWithEscape(t *testing.T) {
	a := testApp(t)
	a.view.page = pageVault("prod-api")
	tt := ui.NewTester(a.mainView, 960, 640)
	tt.Click("Add Env…")
	tt.Type("DRAFT")
	tt.Key(0, ui.KeyEscape)
	vt, _ := a.vaults.Vault("prod-api")
	if a.view.form.open || len(vt.Envs) != 2 {
		t.Fatalf("adding %v, envs %v", a.view.form.open, vt.Envs)
	}
}

func TestAddMultilineEnv(t *testing.T) {
	a := testApp(t)
	a.view.page = pageVault("prod-api")
	// As if shown, so that the value added shows as stored.
	a.view.revealedVault, a.view.revealed = "prod-api", map[string]string{}
	tt := ui.NewTester(a.mainView, 960, 640)
	tt.Click("Add Env…")
	tt.Type("CERT")
	tt.Click("Value")
	tt.Type("line 1")
	tt.Key(ui.Shift, ui.KeyEnter)
	tt.Type("line 2")
	if !a.view.form.open {
		t.Fatal("Shift+Enter added the env")
	}
	tt.Key(0, ui.KeyEnter)
	if a.view.form.open {
		t.Fatal("Enter did not add the env")
	}
	if got := a.view.revealed["CERT"]; got != "line 1\nline 2" {
		t.Fatalf("CERT is %q", got)
	}
}

func TestEditEnvInline(t *testing.T) {
	a := testApp(t)
	a.view.page = pageVault("prod-api")
	a.view.revealedVault, a.view.revealed = "prod-api", map[string]string{"PORT": "5432", "STRIPE_KEY": "sk_live_1"}
	tt := ui.NewTester(a.mainView, 960, 640)
	tt.Click("Edit Value") // PORT's, the first
	if f := a.view.form; !f.open || !f.editing || f.key != "PORT" || f.value != "5432" || f.mask {
		t.Fatalf("form %+v", f)
	}
	tt.Type("1")
	want := a.view.form.value
	tt.Key(0, ui.KeyEnter)
	if a.view.form.open || want == "5432" || a.view.revealed["PORT"] != want {
		t.Fatalf("open %v, typed %q, stored %q", a.view.form.open, want, a.view.revealed["PORT"])
	}
	vt, _ := a.vaults.Vault("prod-api")
	if len(vt.Envs) != 2 || vt.Envs[0].Sensitive {
		t.Fatalf("envs %+v", vt.Envs)
	}
}

// Cmd+B and the title bar's button hide the sidebar and show it again.
func TestToggleSidebar(t *testing.T) {
	a := testApp(t)
	tt := ui.NewTester(a.mainView, 960, 640)
	tt.Key(ui.Cmd, ui.KeyB)
	if !a.view.sidebarHidden {
		t.Fatal("Cmd+B left the sidebar shown")
	}
	tt.Advance(time.Second)
	// Into the room the sidebar left, clear of the toggle at 8 to 34.
	if r, ok := tt.Find("1 running now"); !ok || r.X < 34 || r.X > sidebarWidth {
		t.Fatalf("the header's subtitle at %v", r)
	}
	if err := tt.Click("Show Sidebar"); err != nil {
		t.Fatal(err)
	}
	if a.view.sidebarHidden {
		t.Fatal("the button left the sidebar hidden")
	}
}
