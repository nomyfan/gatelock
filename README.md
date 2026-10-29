<p align="center">
  <img src="resources/icon.png" width="128" alt="">
</p>

<h1 align="center">Gatelock</h1>

<p align="center">A macOS app that keeps the credentials commands need, encrypted with <a href="https://filippo.io/age">age</a>, and hands them to coding agents one command at a time.</p>

```sh
gatelock run <vault> -- <command> [args...]
```

The command runs with the vault's env added, after Touch ID or the passphrase, and the values are masked in its output. The app records each command run, so you can watch and stop it.

```sh
go tool mygo dev     # run
go tool mygo build   # package into build/
```
