/* SlopBro
 * by throwaway96
 * https://github.com/throwaway96/slopbro
 * Copyright 2026. Licensed under AGPL v3 or later. No warranties.
 */

const child_process = require("child_process");
const fs = require("fs");

function log() {
  const args = Array.prototype.slice.call(arguments);
  const message = args.join(" ");
  console.log(message);
  try {
    fs.appendFileSync("/tmp/slopbro.log", message + "\n");
  } catch (err) {
    // Logging must never prevent the payload from running.
  }
}

function escapeHtml(text) {
  return String(text)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

function notifyFailure(message) {
  try {
    const payload = JSON.stringify({
      sourceId: "com.webos.service.secondscreen.gateway",
      message: "<h3>SlopBro</h3>Rooting failed: " + escapeHtml(message),
      buttons: [{ label: "OK" }],
    });
    child_process.execFileSync("luna-send", [
      "-w", "2000", "-n", "1",
      "-a", "com.webos.service.secondscreen.gateway",
      "luna://com.webos.notification/createAlert",
      payload,
    ]);
  } catch (err) {
    // Notifications are best-effort.
  }
}

function run() {
  log("entered run()");

  if (process.argv.length < 3) {
    log("error: missing script path");
    process.exit(1);
  }

  const scriptPath = process.argv[2];
  const args = process.argv.slice(3);

  log("scriptPath:", scriptPath);
  log("args:", args.join(" "));

  var status = "unknown error";

  try {
    child_process.execFileSync("/bin/sh", [scriptPath].concat(args));

    status = "success";
  } catch (err) {
    status = "error: " + err.message;
    process.exitCode = 1;
    notifyFailure(err.message);
  } finally {
    log("result:", status);

    if (status !== "success") {
      process.exitCode = 1;
    }

    // Leave the service process running; failures are reported through the
    // alert, the log, and the exit code if the process exits on its own.
  }
}

module.exports = { run: run };
