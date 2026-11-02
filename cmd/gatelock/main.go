// Gatelock keeps the secrets commands need, encrypted, and runs commands
// with them: `gatelock run <vault> -- <command>` in a shell, which asks
// the app, and the app, which holds the vaults and the record of the
// activities.
package main

import (
	"fmt"
	"os"
	"path/filepath"
)

const usage = `usage: gatelock run [--no-record-output] <vault> [--] <command> [args...]

Runs the command with the vault's env, once you authorize it in
Gatelock, and masks their values in its output.

  --no-record-output  keep the command's output out of Gatelock's record
                      of activities, as for a dev server; the activity
                      still shows there, and can be stopped`

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "run":
			os.Exit(runCommand(os.Args[2:]))
		case "help", "-h", "--help":
			fmt.Println(usage)
			return
		}
	}
	runApp()
}

// home is where Gatelock keeps its data and its socket: $GATELOCK_HOME, or
// Gatelock in the user's Application Support. The CLI and the app find it
// the same way.
func home() (string, error) {
	if dir := os.Getenv("GATELOCK_HOME"); dir != "" {
		return dir, nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "Gatelock"), nil
}

func socketPath(home string) string { return filepath.Join(home, "gatelock.sock") }
