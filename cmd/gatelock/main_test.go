package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"image/png"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/egoist/mygo/ui"

	"gatelock/internal/caller"
	"gatelock/internal/history"
	"gatelock/internal/telegram"
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

func (denyAll) ConfirmUser(context.Context, vault.Prompt) error { return vault.ErrDenied }
func (denyAll) AskPassphrase(context.Context, string, string, bool) ([]byte, error) {
	return nil, vault.ErrDenied
}

// allowAll approves, and gives testApp's passphrase.
type allowAll struct{}

func (allowAll) ConfirmUser(context.Context, vault.Prompt) error { return nil }
func (allowAll) AskPassphrase(context.Context, string, string, bool) ([]byte, error) {
	return []byte("pw"), nil
}

// unlock unlocks a's vault name, through a store over the same directory
// that approves, which a then uses.
func unlock(t *testing.T, a *app, name string) {
	t.Helper()
	v, err := vault.Open(filepath.Join(a.home, "vaults"), memKeychain{}, allowAll{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Resolve(context.Background(), name, "test"); err != nil {
		t.Fatal(err)
	}
	a.vaults = v
	a.refresh()
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
	rec, _ := h.Begin(history.Activity{Vault: "prod-api", Argv: []string{"npm", "run", "deploy"}, Cwd: "/work/api", Caller: caller.Codex}, func() {})
	rec.Authorized()
	rec.Write([]byte("deploying with [REDACTED:prod-api/STRIPE_KEY]\n"))
	rec.Exited(0)
	running, _ := h.Begin(history.Activity{Vault: "prod-api", Argv: []string{"npm", "run", "dev"}, Cwd: "/work/api", Caller: caller.ClaudeCode}, func() {})
	running.Authorized()

	px := newProxy(filepath.Join(dir, "settings.json"))
	a := &app{home: dir, vaults: v, history: h, proxy: px, remote: &remote{path: filepath.Join(dir, "telegram.json"), kc: memKeychain{}, rt: px.transport}}
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

		if !tt.HasText("npm run dev") || !tt.HasText("npm run deploy") || tt.HasText("exit 0") ||
			!tt.HasText("Claude Code  ·  prod-api  ·  /work/api") {
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
	rec, _ := a.history.Begin(history.Activity{Vault: "prod-api", Argv: []string{"sleep", "60"}, Cwd: "/"}, func() { stopped = true })
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

func TestOutputNotRecorded(t *testing.T) {
	a := testApp(t)
	rec, _ := a.history.Begin(history.Activity{Vault: "prod-api", Argv: []string{"npm", "run", "serve"}, Cwd: "/work/api", OutputNotRecorded: true}, func() {})
	rec.Authorized()
	a.refresh()
	tt := ui.NewTester(a.mainView, 960, 640)
	tt.Frame()
	if err := tt.Click("npm run serve"); err != nil {
		t.Fatal(err)
	}
	if !tt.HasText("(output not recorded)") {
		t.Fatalf("texts %q", tt.Texts())
	}
}

func TestRunUnknownOption(t *testing.T) {
	for _, args := range [][]string{
		{"--quiet", "prod-api", "true"},
		{"--reason=deploy", "--quiet", "prod-api", "true"},
		{"--reason"},
	} {
		if code := runCommand(args); code != exitGatelock {
			t.Fatalf("%q: code %d", args, code)
		}
	}
}

func TestPurposeShown(t *testing.T) {
	a := testApp(t)
	a.history.Begin(history.Activity{Vault: "prod-api", Argv: []string{"make", "deploy"}, Cwd: "/work/api", Purpose: "deploy the hotfix"}, func() {})
	a.refresh()
	tt := ui.NewTester(a.mainView, 960, 640)
	if !tt.HasText("Reason given: deploy the hotfix") {
		t.Fatalf("%q", tt.Texts())
	}
}

func TestSetEnvReplacesInEnviron(t *testing.T) {
	env := setEnv([]string{"PATH=/bin", "TOKEN=old", "TOKENX=keep"}, "TOKEN", "new")
	if strings.Join(env, " ") != "PATH=/bin TOKENX=keep TOKEN=new" {
		t.Fatalf("got %v", env)
	}
}

// An activity found lost on opening has no end, so no time it took.
func TestWhenLostWithoutEnd(t *testing.T) {
	start := time.Now().Add(-time.Hour)
	if got := when(history.Activity{StartedAt: start, Status: history.Lost}); strings.Contains(got, "·") {
		t.Errorf("lost: %q", got)
	}
	if got := when(history.Activity{StartedAt: start, Status: history.Running}); !strings.HasSuffix(got, "1h0m0s") {
		t.Errorf("running: %q", got)
	}
}

// The lock button locks only an unlocked vault, and shows which it is.
func TestLockButtonFollowsUnlock(t *testing.T) {
	a := testApp(t)
	a.view.page = pageVault("prod-api")
	tt := ui.NewTester(a.mainView, 960, 640)
	if _, ok := tt.Find("Locked"); !ok {
		t.Fatalf("not shown locked: %q", tt.Texts())
	}
	unlock(t, a, "prod-api")
	tt.Frame()
	if err := tt.Click("Lock Now"); err != nil {
		t.Fatal(err)
	}
	if vt, _ := a.vaults.Vault("prod-api"); vt.Unlocked {
		t.Fatal("still unlocked")
	}
	if _, ok := tt.Find("Locked"); !ok {
		t.Fatalf("not shown locked again: %q", tt.Texts())
	}
}

// Under Every, which never keeps a vault unlocked, values shown still
// show it open, and Lock Now hides them.
func TestLockNowHidesValuesUnderEvery(t *testing.T) {
	a := testApp(t)
	a.vaults.SetPolicy("prod-api", vault.Policy{Mode: vault.Every})
	a.view.page = pageVault("prod-api")
	a.view.revealedVault, a.view.revealed = "prod-api", map[string]string{"PORT": "5432", "STRIPE_KEY": "sk_live_1"}
	a.refresh()
	tt := ui.NewTester(a.mainView, 960, 640)
	if err := tt.Click("Lock Now"); err != nil {
		t.Fatalf("%v: %q", err, tt.Texts())
	}
	if a.view.revealed != nil || tt.HasText("sk_live_1") {
		t.Fatal("values still shown")
	}
	if _, ok := tt.Find("Locked"); !ok {
		t.Fatalf("not shown locked: %q", tt.Texts())
	}
}

// As an unlock with a TTL ends, the app refreshes to show it locked, and
// hides the values shown.
func TestRefreshAsUnlockExpires(t *testing.T) {
	a := testApp(t)
	a.vaults.SetPolicy("prod-api", vault.Policy{Mode: vault.TTL, TTL: time.Second})
	unlock(t, a, "prod-api")
	a.view.revealedVault, a.view.revealed = "prod-api", map[string]string{"PORT": "5432", "STRIPE_KEY": "sk_live_1"}
	if a.expiresAt.IsZero() {
		t.Fatal("no refresh set for the expiry")
	}
	a.dirty.Store(false)
	time.Sleep(1100 * time.Millisecond)
	if !a.dirty.Load() {
		t.Fatal("no refresh as the unlock ended")
	}
	a.refresh()
	if a.view.vaults[0].Unlocked || !a.expiresAt.IsZero() || a.view.revealed != nil {
		t.Fatalf("unlocked %v, refresh at %v, shown %v", a.view.vaults[0].Unlocked, a.expiresAt, a.view.revealed)
	}
}

func TestLockHidesValuesShownAndUnderWay(t *testing.T) {
	a := testApp(t)
	a.view.page, a.view.revealedVault = pageVault("prod-api"), "prod-api"
	unlock(t, a, "prod-api")
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

// A key copies on a click, a value only while shown.
func TestCopyShowsOnlyWithTheValue(t *testing.T) {
	a := testApp(t)
	a.view.page = pageVault("prod-api")
	tt := ui.NewTester(a.mainView, 960, 640)
	if _, ok := tt.Find("Copy PORT"); !ok {
		t.Fatal("copy not offered for a key")
	}
	if _, ok := tt.Find("Copy the value of PORT"); ok {
		t.Fatal("copy offered for a hidden value")
	}
	unlock(t, a, "prod-api")
	a.view.revealedVault, a.view.revealed = "prod-api", map[string]string{"STRIPE_KEY": "sk_live_1", "PORT": "5432"}
	tt.Frame()
	// Not clicked: the clipboard is the system's, and needs the running app.
	if _, ok := tt.Find("Copy the value of PORT"); !ok {
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

func TestDeleteActivity(t *testing.T) {
	a := testApp(t)
	tt := ui.NewTester(a.mainView, 960, 640)
	tt.Click("npm run deploy")
	// Only the activity ended has it; the one running has Stop.
	if err := tt.Click("Delete Activity…"); err != nil {
		t.Fatal(err)
	}
	if err := tt.Click("Cancel"); err != nil {
		t.Fatal(err)
	}
	tt.Frame()
	if !tt.HasText("npm run deploy") {
		t.Fatalf("deleted though canceled: %q", tt.Texts())
	}
	if err := tt.Click("Delete Activity…"); err != nil {
		t.Fatal(err)
	}
	if err := tt.Click("Delete"); err != nil {
		t.Fatal(err)
	}
	tt.Frame()
	if !tt.HasText("npm run dev") || tt.HasText("npm run deploy") || len(a.view.activityViews) != 0 {
		t.Fatalf("texts %q, views %v", tt.Texts(), a.view.activityViews)
	}
	if _, ok := tt.Find("Delete Activity…"); ok {
		t.Fatal("delete shown for the activity running")
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
	if got := strings.Join(tt.Menu(), ", "); got != "Import from .env…, Export to .env…, Export to .env.example…" {
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
	// As if shown, which unlocks, so that the value added shows as stored.
	unlock(t, a, "prod-api")
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

// Values imported while the vault's are shown show too, the new ones and
// those replaced; while hidden, they stay hidden.
func TestImportKeepsValuesShown(t *testing.T) {
	a := testApp(t)
	a.view.page = pageVault("prod-api")
	unlock(t, a, "prod-api")
	a.view.revealedVault, a.view.revealed = "prod-api", map[string]string{"PORT": "5432", "STRIPE_KEY": "sk_live_1"}
	values, err := a.vaults.Import("prod-api", []byte("PORT=8080\nNEW_TOKEN=tok_new_1\n"))
	if err != nil {
		t.Fatal(err)
	}
	a.imported("prod-api", "/work/api/.env", values)
	a.view.askRemove = false
	tt := ui.NewTester(a.mainView, 960, 640)
	if !tt.HasText("tok_new_1") || !tt.HasText("8080") || tt.HasText("5432") || !tt.HasText("sk_live_1") {
		t.Fatalf("values shown: %q", tt.Texts())
	}
	if got := strings.Join(a.view.imported, ", "); got != "NEW_TOKEN, PORT" {
		t.Fatalf("imported %q", got)
	}

	a.hideValues()
	values, _ = a.vaults.Import("prod-api", []byte("OTHER=tok_other_1\n"))
	a.imported("prod-api", "/work/api/.env", values)
	a.view.askRemove = false
	tt = ui.NewTester(a.mainView, 960, 640)
	if a.view.revealed != nil || tt.HasText("tok_other_1") {
		t.Fatalf("values shown while hidden: %q", tt.Texts())
	}
}

func TestEditEnvInline(t *testing.T) {
	a := testApp(t)
	a.view.page = pageVault("prod-api")
	unlock(t, a, "prod-api")
	a.view.revealedVault, a.view.revealed = "prod-api", map[string]string{"PORT": "5432", "STRIPE_KEY": "sk_live_1"}
	tt := ui.NewTester(a.mainView, 960, 640)
	tt.Click("Edit") // PORT's, the first
	if f := a.view.form; !f.open || f.from != "PORT" || f.key != "PORT" || f.value != "5432" || f.mask {
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

// Renaming with the values hidden keeps the value, which the form never
// had.
func TestRenameEnvInline(t *testing.T) {
	a := testApp(t)
	a.view.page = pageVault("prod-api")
	before, _ := a.vaults.Vault("prod-api")
	tt := ui.NewTester(a.mainView, 960, 640)
	tt.Click("Edit") // PORT's, the first
	tt.Click("Key")
	tt.Key(ui.Cmd, ui.KeyA)
	tt.Type("STRIPE_KEY")
	if !tt.HasText("STRIPE_KEY is there already.") {
		t.Fatal("no warning for a key taken")
	}
	tt.Key(0, ui.KeyEnter)
	if !a.view.form.open {
		t.Fatal("saved onto a key taken")
	}
	tt.Key(ui.Cmd, ui.KeyA)
	tt.Type("DB_PORT")
	tt.Key(0, ui.KeyEnter)
	vt, _ := a.vaults.Vault("prod-api")
	if a.view.form.open || len(vt.Envs) != 2 || vt.Envs[0].Key != "DB_PORT" || !vt.Envs[0].UpdatedAt.Equal(before.Envs[0].UpdatedAt) {
		t.Fatalf("open %v, envs %+v", a.view.form.open, vt.Envs)
	}
}

// A hidden value typed in and emptied again is saved empty, not kept.
func TestEmptyHiddenValue(t *testing.T) {
	a := testApp(t)
	a.view.page = pageVault("prod-api")
	before, _ := a.vaults.Vault("prod-api")
	tt := ui.NewTester(a.mainView, 960, 640)
	tt.Click("Edit") // PORT's, the first
	tt.Type("x")
	tt.Key(0, ui.KeyBackspace)
	if a.view.form.value != "" || !a.view.form.typed {
		t.Fatalf("form %+v", a.view.form)
	}
	tt.Key(0, ui.KeyEnter)
	vt, _ := a.vaults.Vault("prod-api")
	if a.view.form.open || !vt.Envs[0].UpdatedAt.After(before.Envs[0].UpdatedAt) {
		t.Fatalf("open %v, envs %+v", a.view.form.open, vt.Envs)
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

func TestLongConfirmKeepsButtonsInView(t *testing.T) {
	a := testApp(t)
	a.view.page = pageVault("prod-api")
	for i := range 300 {
		a.view.imported = append(a.view.imported, fmt.Sprintf("SOME_RATHER_LONG_KEY_%d", i))
	}
	a.view.importedFrom, a.view.askRemove = "/work/api/.env", true
	tt := ui.NewTester(a.mainView, 960, 640)
	snapshot(t, tt, "long-confirm")
	for _, label := range []string{"Keep It", "Delete"} {
		r, ok := tt.Find(label)
		if !ok || r.Y < 0 || r.Y+r.H > 640 {
			t.Fatalf("%s at %v, shown %v", label, r, ok)
		}
	}
}

func TestLongKeyKeepsToItsColumn(t *testing.T) {
	a := testApp(t)
	a.vaults.SetEnv("prod-api", "APP_RELEASES_JSON_URL_TEMPLATE_FOR_THE_STABLE_CHANNEL", []byte("x"))
	a.refresh()
	a.view.page = pageVault("prod-api")
	tt := ui.NewTester(a.mainView, 960, 640)
	column := func() (key, value ui.Rect) {
		key, _ = tt.Find("Copy APP_RELEASES_JSON_URL_TEMPLATE_FOR_THE_STABLE_CHANNEL")
		value, _ = tt.Find("••••••••")
		if key.X+key.W > value.X {
			t.Fatalf("key at %v overlaps the value at %v", key, value)
		}
		return key, value
	}
	narrow, _ := column()
	tt.SetSize(1400, 640)
	tt.Frame()
	if wide, _ := column(); wide.W <= narrow.W {
		t.Fatalf("key %v wide in a wider window, %v before", wide.W, narrow.W)
	}
}

// pairTelegram pairs a's Telegram, as its Setup card would.
func pairTelegram(a *app) {
	a.remote.mu.Lock()
	defer a.remote.mu.Unlock()
	a.remote.set(&telegram.Config{
		Bot:          telegram.User{ID: 1, IsBot: true, Username: "my_gatelock_bot"},
		User:         telegram.User{ID: 42, FirstName: "Ada", Username: "ada"},
		TokenAccount: newTokenAccount(),
	}, nil)
}

// Pairings in data directories of their own keep their bots' tokens apart
// in the one Keychain, so that disconnecting one leaves the others.
func TestTokenPerPairing(t *testing.T) {
	kc := memKeychain{}
	pairIn := func(token string) *remote {
		t.Helper()
		r := &remote{path: filepath.Join(t.TempDir(), "telegram.json"), kc: kc}
		bot, err := telegram.New(token, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := r.pair(bot, token, telegram.Config{Bot: telegram.User{ID: 1, IsBot: true}, User: telegram.User{ID: 42}}); err != nil {
			t.Fatal(err)
		}
		return r
	}
	first, second := pairIn("1:first"), pairIn("2:second")
	if err := second.forget(); err != nil {
		t.Fatal(err)
	}
	again := &remote{path: first.path, kc: kc}
	again.load()
	c, ok := again.paired()
	if token, err := kc.Get(c.TokenAccount); !ok || err != nil || string(token) != "1:first" {
		t.Fatalf("the first pairing's token: %q, %v", token, err)
	}
	if len(kc) != 1 {
		t.Fatalf("Keychain holds %d", len(kc))
	}
}

// A pairing kept without a token account of its own, such as one whose
// account names a vault's passphrase, is none, and disconnecting deletes
// nothing.
func TestPairingNeedsItsOwnAccount(t *testing.T) {
	for _, a := range []string{newTokenAccount(), tokenAccount + rand.Text() + rand.Text()} {
		if !ownTokenAccount(a) {
			t.Fatalf("%q not its own", a)
		}
	}
	vaultID := rand.Text()
	kc := memKeychain{"telegram-bot-token": []byte("1:first"), vaultID: []byte("passphrase")}
	for _, account := range []string{"", `,"token_account":"telegram-bot-token"`, `,"token_account":"` + vaultID + `"`, `,"token_account":"telegram-bot-token-` + vaultID[:25] + `"`, `,"token_account":"telegram-bot-token-` + vaultID + `1"`, `,"token_account":"telegram-bot-token-` + strings.ToLower(vaultID) + `"`} {
		path := filepath.Join(t.TempDir(), "telegram.json")
		if err := os.WriteFile(path, []byte(`{"bot":{"id":1,"is_bot":true,"first_name":"Gatelock"},"user":{"id":42,"is_bot":false,"first_name":"Ada"}`+account+`}`), 0o600); err != nil {
			t.Fatal(err)
		}
		r := &remote{path: path, kc: kc}
		r.load()
		if _, ok := r.paired(); ok {
			t.Fatalf("paired with %s", account)
		}
		if err := r.forget(); err != nil || len(kc) != 2 {
			t.Fatalf("disconnecting with %s: %v, %d left", account, err, len(kc))
		}
	}
}

// flakyKeychain fails to delete while fail is set.
type flakyKeychain struct {
	memKeychain
	fail bool
}

func (k *flakyKeychain) Delete(a string) error {
	if k.fail {
		return errors.New("the Keychain is locked")
	}
	return k.memKeychain.Delete(a)
}

// A disconnect that fails to delete the token withdraws the questions
// open but keeps the pairing, so that disconnecting again finishes it.
func TestDisconnectAgain(t *testing.T) {
	kc := &flakyKeychain{memKeychain: memKeychain{}}
	r := &remote{path: filepath.Join(t.TempDir(), "telegram.json"), kc: kc}
	bot, err := telegram.New("1:first", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.pair(bot, "1:first", telegram.Config{Bot: telegram.User{ID: 1, IsBot: true}, User: telegram.User{ID: 42}}); err != nil {
		t.Fatal(err)
	}
	pairing := r.pairing
	kc.fail = true
	if err := r.forget(); err == nil {
		t.Fatal("disconnected without deleting the token")
	}
	if pairing.Err() == nil {
		t.Fatal("questions open not withdrawn")
	}
	if _, ok := r.paired(); !ok || r.pairing.Err() != nil {
		t.Fatal("the pairing is gone, with its token left")
	}
	if _, err := os.Stat(r.path); err != nil {
		t.Fatal(err)
	}
	kc.fail = false
	if err := r.forget(); err != nil {
		t.Fatal(err)
	}
	if _, ok := r.paired(); ok || len(kc.memKeychain) != 0 {
		t.Fatalf("paired %v, Keychain holds %d", ok, len(kc.memKeychain))
	}
	if _, err := os.Stat(r.path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("telegram.json: %v", err)
	}
}

// Disconnecting withdraws the questions asked in Telegram, which wait on
// the pairing.
func TestDisconnectWithdraws(t *testing.T) {
	a := testApp(t)
	pairTelegram(a)
	pairing := a.remote.pairing
	if err := a.remote.forget(); err != nil {
		t.Fatal(err)
	}
	if pairing.Err() == nil {
		t.Fatal("the pairing goes on")
	}
	if err := a.remote.ask(context.Background(), vault.Prompt{}); !errors.Is(err, errUnpaired) {
		t.Fatalf("asked unpaired: %v", err)
	}
}

func TestAlsoAskInTelegram(t *testing.T) {
	a := testApp(t)
	tt := ui.NewTester(a.mainView, 960, 640)
	tt.Click("prod-api")
	if err := tt.Click("Settings…"); err != nil {
		t.Fatal(err)
	}
	if !tt.HasText("Set Telegram up on the Setup page first.") {
		t.Fatalf("not paired: %q", tt.Texts())
	}
	tt.Click("Ask in Telegram too")
	if vt, _ := a.vaults.Vault("prod-api"); vt.Remote {
		t.Fatal("turned on without Telegram")
	}

	pairTelegram(a)
	tt.Frame()
	if !tt.HasText("Telegram is sent the command line.") {
		t.Fatalf("paired: %q", tt.Texts())
	}
	if err := tt.Click("Ask in Telegram too"); err != nil {
		t.Fatal(err)
	}
	if vt, _ := a.vaults.Vault("prod-api"); !vt.Remote {
		t.Fatal("not turned on")
	}
	snapshot(t, tt, "settings-telegram")
	tt.Click("Done")
	if !tt.HasText("passphrase in the Keychain, commands asked in Telegram too") {
		t.Fatalf("vault page: %q", tt.Texts())
	}
}

func TestDenialShownWithItsReason(t *testing.T) {
	a := testApp(t)
	rec, _ := a.history.Begin(history.Activity{Vault: "prod-api", Argv: []string{"make", "migrate"}, Cwd: "/work/api", Caller: caller.ClaudeCode}, func() {})
	rec.Denied("Telegram", "use staging")
	a.refresh()
	tt := ui.NewTester(a.mainView, 960, 640)
	if !tt.HasText("Denied in Telegram: use staging") {
		t.Fatalf("%q", tt.Texts())
	}
	snapshot(t, tt, "activities-denied")
}

func TestTelegramSetupCard(t *testing.T) {
	a := testApp(t)
	a.view.page = pageSetup
	// Not checking the shell's PATH, which is not the test's.
	a.view.setup.checked = true
	tt := ui.NewTester(a.mainView, 960, 640)
	if !tt.HasText("Make a bot of Gatelock's own with @BotFather") {
		t.Fatalf("not paired: %q", tt.Texts())
	}
	if err := tt.Click("Bot token"); err != nil {
		t.Fatal(err)
	}
	tt.Type("not a token")
	if err := tt.Click("Connect"); err != nil {
		t.Fatal(err)
	}
	tt.Frame()
	if a.view.setup.telegram.busy || !tt.HasText("that is not a bot token") {
		t.Fatalf("a bad token: %q", tt.Texts())
	}
	snapshot(t, tt, "setup")

	pairTelegram(a)
	tt.Frame()
	if !tt.HasText("Asks Ada (@ada) through @my_gatelock_bot") {
		t.Fatalf("paired: %q", tt.Texts())
	}
	if err := tt.Click("Disconnect"); err != nil {
		t.Fatal(err)
	}
	if _, paired := a.remote.paired(); paired {
		t.Fatal("still paired")
	}
}

func TestParseProxy(t *testing.T) {
	for in, want := range map[string]string{
		"":                             "",
		"  ":                           "",
		"127.0.0.1:7890":               "http://127.0.0.1:7890",
		" http://127.0.0.1:7890/ ":     "http://127.0.0.1:7890",
		"socks5://127.0.0.1:7890":      "socks5://127.0.0.1:7890",
		"socks5h://u:p@127.0.0.1:1080": "socks5h://u:p@127.0.0.1:1080",
		"https://proxy.example":        "https://proxy.example",
	} {
		u, err := parseProxy(in)
		if err != nil {
			t.Errorf("%q: %v", in, err)
			continue
		}
		got := ""
		if u != nil {
			got = u.String()
		}
		if got != want {
			t.Errorf("%q: got %q, want %q", in, got, want)
		}
	}
	for _, bad := range []string{"ftp://127.0.0.1:21", "http://", "http://127.0.0.1:7890/path", "http://127.0.0.1:7890?x=1", "http://u:secret@[::1"} {
		if _, err := parseProxy(bad); err == nil {
			t.Errorf("%q taken", bad)
		} else if strings.Contains(err.Error(), "secret") {
			t.Errorf("%q: the error repeats it: %v", bad, err)
		}
	}
}

// The proxy set is kept, and the bots' connections go through it; with
// none set, through the environment's.
func TestProxyKept(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	req, _ := http.NewRequest(http.MethodPost, "https://api.telegram.org/bot1:x/getMe", nil)
	p := newProxy(path)
	if err := p.set("socks5://127.0.0.1:7890"); err != nil {
		t.Fatal(err)
	}
	again := newProxy(path)
	if again.String() != "socks5://127.0.0.1:7890" {
		t.Fatalf("read back %q", again.String())
	}
	if u, err := again.transport.Proxy(req); err != nil || u == nil || u.String() != "socks5://127.0.0.1:7890" {
		t.Fatalf("connects through %v, %v", u, err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("settings.json is %v", fi.Mode())
	}
	if err := again.set(""); err != nil {
		t.Fatal(err)
	}
	if newProxy(path).String() != "" {
		t.Fatal("still kept")
	}
	u, err := again.transport.Proxy(req)
	want, wantErr := http.ProxyFromEnvironment(req)
	if (u == nil) != (want == nil) || u != nil && u.String() != want.String() || err != wantErr {
		t.Fatalf("connects through %v, %v; the environment's is %v, %v", u, err, want, wantErr)
	}
	if err := again.set("ftp://x"); err == nil {
		t.Fatal("a bad proxy taken")
	}
}

func TestProxyOnSetupCard(t *testing.T) {
	a := testApp(t)
	a.view.page = pageSetup
	a.view.setup.checked = true
	tt := ui.NewTester(a.mainView, 960, 640)
	if err := tt.Click("Proxy"); err != nil {
		t.Fatal(err)
	}
	tt.Type("ftp://127.0.0.1")
	if err := tt.Click("Save"); err != nil {
		t.Fatal(err)
	}
	tt.Frame()
	if a.proxy.String() != "" || !tt.HasText("that is not a proxy") {
		t.Fatalf("a bad proxy: %q, %q", a.proxy.String(), tt.Texts())
	}
	a.view.setup.telegram.proxy = ""
	tt.Frame()
	if err := tt.Click("Proxy"); err != nil {
		t.Fatal(err)
	}
	tt.Type("127.0.0.1:7890")
	if err := tt.Click("Save"); err != nil {
		t.Fatal(err)
	}
	tt.Frame()
	if a.proxy.String() != "http://127.0.0.1:7890" || a.view.setup.telegram.proxy != "http://127.0.0.1:7890" {
		t.Fatalf("set %q, shown %q", a.proxy.String(), a.view.setup.telegram.proxy)
	}
	if !tt.HasText("Proxy saved") {
		t.Fatalf("%q", tt.Texts())
	}
	if in, _ := tt.Access("Proxy"); in.Value != "http://127.0.0.1:7890" {
		t.Fatalf("the proxy kept not shown: %+v", in)
	}

	// Shown while paired too.
	pairTelegram(a)
	tt.Frame()
	if !tt.HasText("Asks Ada (@ada) through @my_gatelock_bot") {
		t.Fatalf("paired: %q", tt.Texts())
	}
	if err := tt.Click("Proxy"); err != nil {
		t.Fatalf("paired: %v", err)
	}
	snapshot(t, tt, "setup-proxy")
}

// A token checked through a proxy that is not there says Telegram could
// not be reached, not that no one pressed Start in time.
func TestUnreachable(t *testing.T) {
	p := newProxy(filepath.Join(t.TempDir(), "settings.json"))
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	if err := p.set("http://" + addr); err != nil {
		t.Fatal(err)
	}
	bot, err := telegram.New("1:x", p.transport)
	if err != nil {
		t.Fatal(err)
	}
	_, err = bot.Me(context.Background())
	err = unreachable(err)
	if err == nil || !strings.Contains(err.Error(), "Could not reach Telegram") || !strings.Contains(err.Error(), addr) {
		t.Fatalf("got %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 0)
	defer cancel()
	_, err = bot.Me(ctx)
	if err = unreachable(err); errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "Could not reach Telegram") {
		t.Fatalf("timed out: %v", err)
	}
	for _, kept := range []error{nil, context.Canceled, telegram.ErrWebhook, &telegram.APIError{Method: "getMe", Code: 401, Description: "Unauthorized"}} {
		if got := unreachable(kept); got != kept {
			t.Errorf("%v became %v", kept, got)
		}
	}
}

// Entering the Setup page checks that Telegram can be reached, once, and
// shows what the check found.
func TestReachCheckedOnEnteringSetup(t *testing.T) {
	a := testApp(t)
	a.view.setup.checked = true
	if err := a.proxy.set("127.0.0.1:7890"); err != nil {
		t.Fatal(err)
	}
	a.view.setup.telegram.proxy = a.proxy.String()
	calls, returned := make(chan struct{}, 4), make(chan struct{}, 4)
	a.reach = func(ctx context.Context) error {
		defer func() { returned <- struct{}{} }()
		calls <- struct{}{}
		<-ctx.Done()
		return ctx.Err()
	}
	r := &a.view.setup.telegram.reach
	// A check still under way if the test ends early is dropped, so that
	// it leaves the UI alone.
	t.Cleanup(func() {
		if r.cancel != nil {
			r.cancel()
		}
	})
	// found stands in for the check under way finding took and err: it
	// ends the check, which then leaves the UI alone, as one dropped does.
	found := func(took time.Duration, err error) {
		t.Helper()
		r.cancel()
		select {
		case <-returned:
		case <-time.After(time.Second):
			t.Fatal("the check did not end")
		}
		a.reached(r.gen, took, err)
	}
	called := func() bool {
		select {
		case <-calls:
			return true
		case <-time.After(time.Second):
			return false
		}
	}
	tt := ui.NewTester(a.mainView, 960, 640)
	if err := tt.Click("Setup"); err != nil {
		t.Fatal(err)
	}
	tt.Frame()
	if !called() {
		t.Fatal("not checked on entering")
	}
	if !tt.HasText("Checking that Telegram can be reached through 127.0.0.1:7890") {
		t.Fatalf("%q", tt.Texts())
	}
	tt.Frame()
	select {
	case <-calls:
		t.Fatal("checked again without leaving")
	default:
	}

	a.reached(r.gen-1, time.Second, errors.New("an older check's"))
	if !r.checking {
		t.Fatal("an older check's result taken")
	}
	found(230*time.Millisecond, nil)
	tt.Frame()
	if !tt.HasText("Telegram is reachable through 127.0.0.1:7890, in 230ms") {
		t.Fatalf("reached: %q", tt.Texts())
	}

	if err := tt.Click("Activities"); err != nil {
		t.Fatal(err)
	}
	tt.Frame()
	if err := tt.Click("Setup"); err != nil {
		t.Fatal(err)
	}
	tt.Frame()
	if !called() {
		t.Fatal("not checked on entering again")
	}
	found(15*time.Second, errors.New("proxyconnect tcp: connection refused"))
	tt.Frame()
	if !tt.HasText("Telegram can't be reached through 127.0.0.1:7890: proxyconnect tcp: connection refused") {
		t.Fatalf("not reached: %q", tt.Texts())
	}
	snapshot(t, tt, "setup-unreachable")
}
