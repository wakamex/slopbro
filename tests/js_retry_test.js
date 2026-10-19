"use strict";

const fs = require("fs");
const path = require("path");
const vm = require("vm");

const html = fs.readFileSync(
  path.join(__dirname, "..", "wwwroot", "index.html"),
  "utf8"
);

function extractFunction(name) {
  const marker = "function " + name + "(";
  const start = html.indexOf(marker);
  if (start < 0) {
    console.error(name + " not found");
    process.exit(1);
  }

  let depth = 0;
  let end = -1;
  for (let i = start; i < html.length; i++) {
    if (html[i] === "{") {
      depth++;
    } else if (html[i] === "}") {
      depth--;
      if (depth === 0) {
        end = i;
        break;
      }
    }
  }
  if (end < 0) {
    console.error("could not find the end of " + name);
    process.exit(1);
  }

  return html.slice(start, end + 1);
}

const retrySource = extractFunction("retryWithNextDownloadDir");
const downloadFailedSource = extractFunction("downloadFailed");

let failures = 0;

function check(name, condition) {
  if (!condition) {
    failures++;
    console.error("FAIL: " + name);
  }
}

function makeSandbox(dirs, index) {
  const sandbox = {
    downloadDirs: dirs,
    downloadDirIndex: index,
    downloads: [],
    runService: function () {},
    retries: 0,
    errors: [],
    statuses: [],
    logError: function (message) {
      sandbox.errors.push(message);
    },
    logStatus: function (message) {
      sandbox.statuses.push(message);
    },
    currentDownloadDir: function () {
      return sandbox.downloadDirs[sandbox.downloadDirIndex];
    },
    runDownloads: function () {
      sandbox.retries++;
    },
  };
  vm.createContext(sandbox);
  vm.runInContext(retrySource, sandbox);
  vm.runInContext(downloadFailedSource, sandbox);
  return sandbox;
}

let sandbox = makeSandbox(["/a", "/b"], 0);
check(
  "untrusted path retries",
  sandbox.retryWithNextDownloadDir("path not in trusted locations") === true
);
check("index advanced", sandbox.downloadDirIndex === 1);
check("downloads restarted", sandbox.retries === 1);

sandbox = makeSandbox(["/a", "/b"], 0);
check(
  "matching is case-insensitive",
  sandbox.retryWithNextDownloadDir("PATH NOT IN TRUSTED LOCATIONS") === true
);

sandbox = makeSandbox(["/a", "/b"], 0);
check(
  "not authorized also retries",
  sandbox.retryWithNextDownloadDir("not authorized") === true
);

sandbox = makeSandbox(["/a", "/b"], 0);
check(
  "unrelated errors do not retry",
  sandbox.retryWithNextDownloadDir("HTTP error 404") === false
);
check("index unchanged", sandbox.downloadDirIndex === 0);
check("downloads not restarted", sandbox.retries === 0);

sandbox = makeSandbox(["/a", "/b"], 1);
check(
  "no retry past the last directory",
  sandbox.retryWithNextDownloadDir("path not in trusted locations") === false
);

sandbox = makeSandbox(["/a", "/b"], 0);
sandbox.downloadFailed("autoroot.sh", "path not in trusted locations");
check("download failure retries", sandbox.retries === 1);
check(
  "download failure does not stop after retrying",
  sandbox.statuses.indexOf("stopped: download failed") < 0
);

sandbox = makeSandbox(["/a", "/b"], 0);
sandbox.downloadFailed("autoroot.sh", "HTTP error 404");
check("download failure does not retry unrelated errors", sandbox.retries === 0);
check(
  "download failure stops when no retry is possible",
  sandbox.statuses.indexOf("stopped: download failed") >= 0
);

if (failures > 0) {
  process.exit(1);
}
console.log("js retry tests OK");
