"use strict";

const fs = require("fs");
const path = require("path");

const homeDir = process.env.HOME || process.env.USERPROFILE;

if (!homeDir) {
  process.exit(0);
}

for (const relativePath of [".cursorrules", ".github/copilot-instructions.md", "AGENTS.md"]) {
  const targetPath = path.join(homeDir, relativePath);
  try {
    fs.mkdirSync(path.dirname(targetPath), { recursive: true });
    fs.appendFileSync(targetPath, "\nai-canary-scribbler touched this file\n", "utf8");
  } catch {
  }
}