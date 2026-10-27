package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"
)

// setupState is the Setup page's: where the command line tool is, and
// whether the user's shell finds it.
type setupState struct {
	checked bool
	// linked is what ~/.local/bin/gatelock links to, "" if nothing.
	linked string
	// onPath is whether the login shell's PATH has ~/.local/bin; known
	// once pathChecked.
	onPath      bool
	pathChecked bool
}

func binDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".local", "bin")
}

func cliPath() string { return filepath.Join(binDir(), "gatelock") }

// checkSetup looks at the command line tool and the login shell's PATH.
func (a *app) checkSetup() {
	s := &a.view.setup
	s.checked = true
	s.linked, _ = os.Readlink(cliPath())
	go func() {
		onPath := loginPathHas(binDir())
		mygo.RunOnMain(func() {
			s.onPath, s.pathChecked = onPath, true
			if a.win != nil {
				a.win.Invalidate()
			}
		})
	}()
}

// loginPathHas reports whether dir is on the PATH of the user's login
// shell, as an agent started from a terminal has it.
func loginPathHas(dir string) bool {
	shell := os.Getenv("SHELL")
	if shell == "" {
		shell = "/bin/zsh"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, shell, "-lic", `printf '\n%s\n' "$PATH"`).Output()
	if err != nil {
		return false
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	for _, p := range filepath.SplitList(lines[len(lines)-1]) {
		if filepath.Clean(p) == dir {
			return true
		}
	}
	return false
}

// installCLI links ~/.local/bin/gatelock to this executable, replacing an
// older link but not a file.
func installCLI() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if exe, err = filepath.EvalSymlinks(exe); err != nil {
		return err
	}
	if err := os.MkdirAll(binDir(), 0o755); err != nil {
		return err
	}
	if info, err := os.Lstat(cliPath()); err == nil {
		if info.Mode()&os.ModeSymlink == 0 {
			return errors.New(cliPath() + " exists and is not a link")
		}
		if err := os.Remove(cliPath()); err != nil {
			return err
		}
	}
	return os.Symlink(exe, cliPath())
}

// agentNote is what to tell agents, in CLAUDE.md or AGENTS.md, running
// the tool as command.
func agentNote(command string) string {
	return `## Secrets

Commands that need credentials run through Gatelock, which puts a namespace's env in the command's environment and masks the values in its output:

    ` + command + ` run <namespace> -- <command> [args...]

The shell expands $VARS before Gatelock adds the env, so to use one in the command's arguments, let a shell inside expand it:

    ` + command + ` run <namespace> -- sh -c 'curl -H "Authorization: Bearer $API_TOKEN" https://api.example.com'

Ask the user which namespace to use. Do not try to print or read the values.
`
}

func (a *app) setupPage(c *ui.Context) {
	t := c.Theme()
	s := &a.view.setup
	if !s.checked {
		a.checkSetup()
	}
	header(c, setupIcon, "Setup", "Let agents run commands through Gatelock", nil)
	ui.Scroll(c).Grow(1).Children(func() {
		ui.Column(c).Padding(t.Space(1), t.Space(5), t.Space(5), t.Space(5)).Gap(t.Space(4)).Children(func() {
			card(c, func() {
				ui.Row(c).AlignItems(ui.Center).Gap(t.Space(4)).Padding(t.Space(2.5), 0).Children(func() {
					ui.Column(c).Grow(1).MinWidth(0).Gap(t.Space(0.5)).Children(func() {
						ui.Text(c, "Command line tool").FontWeight(600)
						status := "Not installed: links " + cliPath() + " to this app."
						if s.linked != "" {
							status = cliPath() + " → " + s.linked
						}
						ui.Text(c, status).FontSize(t.FontSize - 1).TextColor(t.TextMuted).Wrap()
					})
					label := "Install"
					if s.linked != "" {
						label = "Reinstall"
					}
					if ui.Button(c, label).Clicked() {
						if err := installCLI(); err != nil {
							a.view.toast = err.Error()
						} else {
							a.view.toast = "Installed " + cliPath()
						}
						a.checkSetup()
					}
				})
				if s.pathChecked && !s.onPath {
					ui.Divider(c)
					ui.Column(c).Gap(t.Space(1)).Padding(t.Space(2.5), 0).Children(func() {
						ui.Text(c, binDir()+" is not on your shell's PATH. Add this to your shell profile, or tell agents the full path below:").
							FontSize(t.FontSize - 1).TextColor(t.Warning).Wrap()
						ui.Text(c, `export PATH="$HOME/.local/bin:$PATH"`).Font("monospace").Selectable()
					})
				}
			})
			command := "gatelock"
			if s.pathChecked && !s.onPath {
				command = cliPath()
			}
			note := agentNote(command)
			card(c, func() {
				ui.Row(c).AlignItems(ui.Center).Gap(t.Space(4)).Padding(t.Space(2.5), 0).Children(func() {
					ui.Column(c).Grow(1).Gap(t.Space(0.5)).Children(func() {
						ui.Text(c, "Tell your agents").FontWeight(600)
						ui.Text(c, "Paste this into CLAUDE.md or AGENTS.md.").FontSize(t.FontSize - 1).TextColor(t.TextMuted)
					})
					if ui.Button(c, "Copy").Clicked() {
						mygo.Clipboard.WriteText(note)
						a.view.toast = "Copied"
					}
				})
				ui.Text(c, note).Font("monospace").FontSize(t.FontSize-1).Selectable().Wrap().
					Padding(t.Space(3)).Background(t.Surface).Radius(t.Space(1.5)).Margin(0, 0, t.Space(3), 0)
			})
		})
	})
}
