// Aegiscudo test fixture — seemingly innocent public API.
// The actual malicious work is in preinstall.js.

"use strict";

module.exports = {
  greet: (name) => `Hello, ${name}!`,
};
