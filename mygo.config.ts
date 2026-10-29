import { execSync } from "node:child_process";

const commit = execSync("git rev-parse --short HEAD", { encoding: "utf8" }).trim();

// The identity to sign with: MACOS_SIGNING_IDENTITY if set ("-" for ad hoc),
// else a Developer ID Application or Apple Development certificate in the
// Keychain, else ad hoc. A certificate with a Team ID keeps the Keychain
// from asking for each vault again after every rebuild, as it does for
// ad-hoc builds. The Keychain knows the app by the certificate's name, so
// certificates of one name (an old one and its renewal) are as good as each
// other and are picked by hash, which codesign doesn't find ambiguous; when
// the names differ, the build says which it took.
function signingIdentity(): string {
  const env = process.env.MACOS_SIGNING_IDENTITY;
  if (env !== undefined) return env;
  if (process.platform !== "darwin") return "";
  let out: string;
  try {
    out = execSync("security find-identity -v -p codesigning", {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    });
  } catch {
    return "";
  }
  const found = [...out.matchAll(/^\s*\d+\) ([0-9A-F]{40}) "(.+)"$/gm)].map((m) => ({ hash: m[1], name: m[2] }));
  for (const kind of ["Developer ID Application: ", "Apple Development: "]) {
    const of = found.filter((c) => c.name.startsWith(kind));
    if (of.length === 0) continue;
    const names = [...new Set(of.map((c) => c.name))];
    if (names.length > 1) {
      console.log(`Signing with "${names[0]}", one of:\n${names.map((n) => `  ${n}`).join("\n")}\nSet MACOS_SIGNING_IDENTITY to choose.`);
    }
    return of[0].hash;
  }
  return "";
}

export default ({ command }: { command: string }) => ({
  name: "Gatelock",
  identifier: "dev.callcc.gatelock",
  version: "0.1.0",
  main: "./cmd/gatelock",
  out: "build",
  macos: {
    infoPlist: { CFBundleVersion: commit },
    signingIdentity: command === "build" ? signingIdentity() : "",
  },
});
