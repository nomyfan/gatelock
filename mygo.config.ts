import { execSync } from "node:child_process";

const commit = execSync("git rev-parse --short HEAD", { encoding: "utf8" }).trim();

export default {
  name: "Gatelock",
  identifier: "dev.callcc.gatelock",
  version: "0.1.0",
  main: "./cmd/gatelock",
  out: "build",
  macos: {
    infoPlist: { CFBundleVersion: commit },
  },
};
