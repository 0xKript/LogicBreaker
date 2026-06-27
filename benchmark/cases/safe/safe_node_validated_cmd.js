// SAFE: server Node, but the action is chosen from a fixed allow-list, never
// from raw user text, so no command injection is possible.
const { execFileSync } = require("child_process");
const ACTIONS = { status: "uptime", disk: "df" };
function run(action) {
  const cmd = ACTIONS[action];
  if (!cmd) throw new Error("unknown action");
  return execFileSync(cmd, []);
}
module.exports = { run };
