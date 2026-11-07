# AGENTS.md

Gatelock is a macOS menu bar app that keeps the credentials commands need, encrypted with [age](https://filippo.io/age), and a CLI that runs commands with them: `gatelock run <vault> -- <command> [args...]`. An agent runs the CLI in its own shell; the CLI asks the app for the vault's env, the app asks the user (Touch ID or the passphrase, as the vault's policy says), and the CLI runs the command with the env added and masks the values, and their common encodings, in its output. The app also keeps a record of the commands run, the activities, which the user can watch and stop. It guards against credentials leaking by accident, not against an agent working around it. Written in Go with [MyGo](https://github.com/egoist/mygo)'s native `ui` package; the app and the CLI are one binary.

## Commands

```sh
go tool mygo dev                          # run a development build with live reload
go tool mygo build                        # package the app (.app and .dmg on macOS, into build/)
go tool mygo vet .                        # go vet plus checks for stored UI build values
CGO_ENABLED=0 go test ./...               # all tests
go test ./internal/vault -run TestDenied  # a single test
GATELOCK_DIALOG_TESTS=1 go test ./internal/macauth -v   # the tests that show the system's Touch ID dialog, skipped otherwise
GATELOCK_SNAPSHOTS=<dir> go test ./cmd/gatelock         # also write the UI tests' frames into <dir> as PNGs
scripts/make-icon.sh                      # render resources/icon.png from the artwork in design/ (needs ImageMagick with librsvg)
scripts/make-tray-icon.sh                 # render cmd/gatelock/icons/tray.png, the menu bar icon, from design/tray.svg (likewise)
```

`mygo` is pinned through the `tool` directive in `go.mod`; nothing to install separately. App settings (name, identifier `dev.callcc.gatelock`, entry `./cmd/gatelock`) live in `mygo.config.ts`, which MyGo evaluates with Bun or Node.js 22.6+; it sets `CFBundleVersion` to the short commit hash, and for `build` the signing identity: `MACOS_SIGNING_IDENTITY` if set (`-` for ad hoc), else the first Developer ID Application or Apple Development certificate that `security find-identity` lists, else ad hoc.

`GATELOCK_HOME` moves the data directory and the socket (default `~/Library/Application Support/Gatelock`); the CLI and the app read it the same way, so set it for both to work against a scratch vault rather than the user's own.

## CLI contract

This is the interface agents and users' scripts depend on; keep it stable.

- `gatelock run <vault> [--] <command> [args...]` execs the command directly, not through a shell. The env is the caller's, with the vault's laid over it.
- stdin passes through; stdout and stderr stay apart, each masked as `[REDACTED:<vault>/<KEY>]`.
- Exit code: the command's own; 128 plus the signal that killed it; 125 for Gatelock's own failures (unknown vault, denied, can't reach the app, lost the app while running), with the reason on stderr; 127 when the command can't be started.
- SIGINT, SIGTERM and SIGHUP are passed on to the command's process group, which is killed 5s later if still there, or at once on a second signal.
- If the app isn't running, the CLI starts it in the background (`open -g <the .app it is in> --args --background`, else `open -b <bundle id>`), and retries for 10s. Under `mygo dev` there is no `.app`, so start the app first.

## Modules

Dependencies run `main` → `ipc` → `vault`, `history`, `caller`; `main` → `launch` → `redact`; `macauth` uses `vault` only for `ErrDenied`. Only `main` imports MyGo: the core packages stay free of it, so that the UI framework can change.

### `cmd/gatelock/` (package `main`)

The entry point, the CLI side of `gatelock run`, and the app's UI.

- `main.go`: `gatelock run` goes to `runCommand` before MyGo starts; anything else runs the app. `home()` resolves the data directory (`GATELOCK_HOME`).
- `cli.go`: `runCommand`: dials the app, sends the run request, lays the env over `os.Environ()`, builds the masks from the sensitive envs, and calls `launch.Run` with the `ipc.Session` as its record and stop channel. Also starting the app from the CLI (`startApp`, `appBundle`). `bundleID` repeats the identifier in `mygo.config.ts`; keep them in sync.
- `app.go`: the app: one instance (`RequestSingleInstanceLock`), opening the vault store, the history and the socket, and serving it in the background. It lives in the menu bar (Accessory policy, Regular while the main window is open; `--background` skips opening the window). The tray shows the number running and Lock All Vaults. Quitting with commands running asks first, then stops them. `refreshLoop` picks up changes from the vaults and the history (flagged through `dirty`) at most ten times a second and rereads them on the main thread; `refresh` also sets a timer for the first unlock with a TTL to end, which nothing else would report, and hides the values shown of a vault no longer unlocked (but not under `Every`). `app` is the vault store's `Authorizer`: `ConfirmUser` goes to `macauth`, `AskPassphrase` opens a window of its own. `keychain` keeps passphrases with `mygo.Secrets`.
- `view.go`: the main window: a collapsible sidebar (Cmd+B) with Activities, Setup and the vaults; a vault's page (envs added and edited, key and value, in a row of the list, the value kept if left as it was, values shown after authorizing and hidden again on locking, a value's copy clearing the clipboard after a minute if it still holds the value, `.env` import that offers to remove the file, export to a 0600 `.env.<vault>` after authorizing, or of the keys alone to a `.env.example` without asking; a click on a key, or a value shown, copies it); the lock shown open while a vault is unlocked or its values are shown (under `Every` it is never kept unlocked), in the sidebar, the page's title and its Lock Now button, which is disabled while locked; the create, settings and delete dialogs; the Activities page, an accordion of activities with status icons (an exit code only in the tooltip), the program that ran each (with its mark, from `icons/agents/`, for Claude Code and Codex), and their output, stop, delete (one ended) and clear (all ended). Work that may block on the vault (authorizing, deleting) runs through `a.background`, since the passphrase window needs the main thread.
- `setup.go`: the Setup page: links `~/.local/bin/gatelock` to this executable, checks the login shell's PATH (`$SHELL -lic`), and the note for agents to paste into their CLAUDE.md or AGENTS.md (`agentNote`).
- `theme.go`: the colors in light and dark, the app colors of [Vellum](https://github.com/nomyfan/vellum-theme) (its web preview's, `preview/src/vellum.css`); with `Spacing = 3` (compact); the icons, embedded from `icons/ui/<name>.svg` (`icon(name)`), one file each on a 16px grid, stroked in `currentColor` so the theme colors them; and controls sized to match each other: `primaryButton`, `confirmDialog` (a 400px modal standing in for `ui.AlertDialog`, too narrow at this spacing), `toggle`, `iconButton`.
- `main_test.go`: UI tests with `ui.NewTester`, over a vault store in a temporary directory with a fake Keychain and an Authorizer that denies everything.

### `internal/vault`

`Store` holds the vaults; `Vault` is what is known of one without unlocking it. The vaults and their envs on disk, encryption, the Keychain, authorization policies and the unlock cache. Safe from several goroutines.

- Each vault has an age hybrid key pair: `identity.age` is the private key encrypted with the passphrase (scrypt), `env/<hex(KEY)>.age` one value each encrypted to the public key, so envs can be added, changed or renamed without unlocking (hex because the file system ignores case). `RenameEnv` links the value under the new name, saves the meta, then removes the old file, so the file the meta names is always there. `meta.json` (with `version`) holds the name, recipient, policy, Keychain flag and the env keys; key names are not secret. Meta is written to a temporary file and renamed.
- Unlocking means holding the decrypted identity; the policies (`Every`, `TTL`, `Session`) differ only in how long it is cached, which `Vault.Unlocked` and `Vault.Expires` report. `Resolve` reads the env files with the store's lock held, so a rename or delete can't remove one it is about to read, and decrypts after. `Resolve` checks the cache, then takes the `prompting` lock, which also keeps the user asked one thing at a time, and checks again, so concurrent requests under TTL and Session share one authorization. With the Keychain on, `ConfirmUser` comes first, then the passphrase is read from the Keychain (account: the vault's id); a missing or stale entry falls back to asking and is repaired.
- Turning the Keychain on or off and deleting a vault hold `prompting` throughout, so that an unlock waiting for the user can't write the passphrase back afterwards. `ChangePassphrase` returns `ErrKeychainStale` when the identity was rewritten but the Keychain wasn't; the next unlock repairs it.
- `Import` reads `.env` with godotenv; `Dotenv` writes it back with every value quoted, so that it reads back as it was (`0042`, quotes, `$`, newlines); `DotenvExample` writes the keys with no values.

### `internal/redact`

A streaming `io.Writer` that masks each secret's raw value, base64 (std and URL, with and without padding, and fragments of 8 bytes or more at the other two offsets), hex in both cases, URL query and path escaping, and JSON escaping. Every secret is masked however short. A secret that is a URL-style DSN with a password (`dsn.go`: in its userinfo, or a query parameter named in `passwordParams`) is still matched whole, but only its passwords are replaced where it shows as written or URL- or JSON-escaped; its base64 and hex forms are masked whole. Matches span writes: only trailing bytes that could begin a pattern are held back, never released on a timer, and `Close` masks whatever is still held, whole.

### `internal/launch`

The CLI's side of running the command: its own process group, stdin through, stdout and stderr each through a `redact.Writer`, and both together in order to `Spec.Record`. Signal forwarding, the stop channel, the kill delay (`killDelay`, shortened in tests) and the shell-style exit codes.

### `internal/ipc`

The protocol between the CLI and the app over the Unix socket `<home>/gatelock.sock` (0600): one connection per run, one JSON frame per line. The CLI sends `run`; the app answers `granted` with the env, or `error` (`not_found`, `denied`, `invalid`, `stopped`, `internal`); then the CLI sends `started`, `output` (at most 64KB each), `exit` or `failed`, and the app may send `stop`.

- `Serve` is the trust boundary: the peer must be the same uid, the vault must exist, argv must not be empty, cwd must be an absolute path that exists. `vault` and `history` trust what it passes on. It registers the activity as `authorizing` before asking, with the program that ran the peer (`caller.Of` its pid, from `LOCAL_PEERPID`), which the question names too; stopping it then dismisses the question.
- If the connection breaks, each side stops the command: the app kills the registered process group and marks the activity `lost`; the CLI stops the command and exits 125. So a running command is always visible in the app.
- `Session` (CLI side) is the record writer and never blocks: when the app falls behind, output is dropped from the record (not from the CLI's own stdout and stderr) and a `[gatelock: output dropped]` line marks the gap.
- The CLI and the app are the same binary and upgrade together, so the protocol has no versioning.

### `internal/history`

The record of activities, owned by the app: each activity's meta and its masked stdout and stderr together, past 4MB cut back to the last 2MB. Statuses: `authorizing`, `running`, `exited`, `stopped`, `denied`, `failed`, `lost`. An activity's meta also has its `caller`, empty in those recorded before it. On opening, activities left unfinished are marked `lost`; only the last 200 are kept. `Store.Stop` asks the activity's CLI to stop; `Store.Delete` and `Store.Clear` remove ended activities, one or all; `onChange` tells the app to refresh.

### `internal/caller`

`Of(pid)` names the program that ran a process, from the processes above it (`kern.proc.pid` for the parent, `kern.procargs2` for the executable and argv): Claude Code or Codex if either is among them, else the first that is not a shell or the like (`passThrough`), by the outermost `.app` it is in or its file name. What processes say of themselves can be made up, so it is a hint shown to the user, never a check.

### `internal/macauth`

`ConfirmUser`: Touch ID or the login password through LocalAuthentication, called with purego (no cgo). The user canceling is `vault.ErrDenied`; a canceled context invalidates the dialog.

### Other directories

`resources/` holds assets shipped inside the app bundle (the app icon, `icon.png`, which MyGo picks up by that name); `design/` holds source files that are not shipped, the icon's artwork `icon.svg` and the menu bar icon's `tray.svg`, the same hedgehog as a silhouette with its paths copied from `icon.svg`; `scripts/` holds tools for maintaining the repository, such as `make-icon.sh`, which renders `resources/icon.png` from `design/icon.svg` on the macOS icon grid, and `make-tray-icon.sh`, which renders `design/tray.svg` into `cmd/gatelock/icons/tray.png`, which the app embeds (`trayIcon`) as a template image for macOS to tint.

`build/` holds `go tool mygo build`'s output and `.mygo/` its development builds (both ignored); `.scratchpad/` (ignored) holds throwaway experiments.

## Notes

- Keep this file current. When a change adds, removes, renames or moves a module or file listed above, shifts a module's responsibility, or changes the commands, the CLI contract or the disk format, update this file in the same change.
- Changing the on-disk format (`meta.json`'s `version`, file layout, encryption) needs a migration for existing data.
- Before changing UI code, read `.agents/skills/mygo-maintenance/SKILL.md` for MyGo's lifetime, identity, threading and testing rules. UI tests use `ui.NewTester`. `.agents/skills/` is ignored; `go tool mygo install-skills` installs it, and `.agents/skills.toml`, which is committed, records the version installed.
- Ad-hoc builds make the Keychain ask twice per vault after each rebuild: its item's access list and its partition list both name the app by its CDHash, which every rebuild changes. A self-signed certificate settles only the first, since the partition list names apps by Team ID. An Apple Development certificate (free, from Xcode's Personal Team) settles both; after switching to it each vault asks once more, then not again. `mygo dev` ignores `signingIdentity` and signs ad hoc unless given `-sign` (e.g. `-sign "Apple Development"`, which codesign matches by prefix); its app's identifier is `dev.callcc.gatelock.dev`, so its Keychain items are apart from the installed app's.
