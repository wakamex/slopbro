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

const sources = [
  "retryWithNextDownloadDir",
  "downloadFailed",
  "runService",
  "requestDownload",
].map(extractFunction);

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
    retries: 0,
    cancelled: false,
    completed: 0,
    errors: [],
    statuses: [],
    statusBeacons: [],
    baseUrl: "",
    shellScriptName: "autoroot.sh",
    fakeServicePath: null,
    optTelnet: false,
    optDebug: false,
    optCurlInsecure: false,
    optLeaveScript: false,
    optNoIpkChecksum: false,
    DOWNLOAD_TIMEOUT_MS: 30000,
    SERVICE_TIMEOUT_MS: 30000,
    serviceResponse: JSON.stringify({ returnValue: true }),
    downloadResponses: [],
    setTimeout: function () {
      return 0;
    },
    clearTimeout: function () {},
    logDebug: function () {},
    logError: function (message) {
      sandbox.errors.push(message);
    },
    logStatus: function (message) {
      sandbox.statuses.push(message);
    },
    sendStatus: function (status) {
      sandbox.statusBeacons.push(status);
    },
    currentDownloadDir: function () {
      return sandbox.downloadDirs[sandbox.downloadDirIndex];
    },
    runDownloads: function () {
      sandbox.retries++;
    },
    parse: function (message) {
      try {
        return JSON.parse(message);
      } catch (err) {
        return null;
      }
    },
    checkValidResponse: function () {
      return true;
    },
    getErrorText: function (response) {
      if (response && typeof response.errorText === "string" && response.errorText) {
        return response.errorText;
      }
      return "unknown error";
    },
  };

  sandbox.bridge = {
    onservicecallback: null,
    cancel: function () {
      sandbox.cancelled = true;
    },
    call: function (uri) {
      if (uri.indexOf("jsserver") >= 0) {
        sandbox.bridge.onservicecallback(sandbox.serviceResponse);
        return;
      }
      sandbox.downloadResponses.forEach(function (response) {
        sandbox.bridge.onservicecallback(response);
      });
    },
  };
  sandbox.createServiceBridge = function () {
    return sandbox.bridge;
  };

  vm.createContext(sandbox);
  sources.forEach(function (source) {
    vm.runInContext(source, sandbox);
  });
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
  "invalid path also retries",
  sandbox.retryWithNextDownloadDir("invalid path") === true
);

sandbox = makeSandbox(["/a", "/b"], 0);
check(
  "not permitted also retries",
  sandbox.retryWithNextDownloadDir("not permitted") === true
);

sandbox = makeSandbox(["/a", "/b"], 0);
check(
  "not allowed also retries",
  sandbox.retryWithNextDownloadDir("not allowed") === true
);

sandbox = makeSandbox(["/a", "/b"], 0);
check(
  "security check also retries",
  sandbox.retryWithNextDownloadDir("failed security check") === true
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
check("download failure retry sends no status", sandbox.statusBeacons.length === 0);

sandbox = makeSandbox(["/a", "/b"], 0);
sandbox.downloadFailed("autoroot.sh", "HTTP error 404");
check("download failure does not retry unrelated errors", sandbox.retries === 0);
check(
  "download failure stops when no retry is possible",
  sandbox.statuses.indexOf("stopped: download failed") >= 0
);
check(
  "terminal download failure reports failed",
  sandbox.statusBeacons.indexOf("failed") >= 0
);

sandbox = makeSandbox(["/a", "/b"], 0);
sandbox.downloadResponses = [
  JSON.stringify({
    completed: true,
    httpStatus: 200,
    aborted: false,
    interrupted: false,
  }),
];
sandbox.requestDownload("autoroot.sh", function () {
  sandbox.completed++;
});
check("completion as the first message succeeds", sandbox.completed === 1);
check("download bridge cancelled", sandbox.cancelled);

sandbox = makeSandbox(["/a", "/b"], 0);
sandbox.downloadResponses = [
  JSON.stringify({ returnValue: true }),
  JSON.stringify({
    completed: true,
    httpStatus: 200,
    aborted: false,
    interrupted: false,
  }),
];
sandbox.requestDownload("autoroot.sh", function () {
  sandbox.completed++;
});
check("start followed by completion succeeds", sandbox.completed === 1);

sandbox = makeSandbox(["/a", "/b"], 0);
sandbox.downloadResponses = [
  JSON.stringify({
    returnValue: false,
    errorText: "path not in trusted locations",
  }),
];
sandbox.requestDownload("autoroot.sh", function () {
  sandbox.completed++;
});
check("download start failure does not complete", sandbox.completed === 0);
check("download start failure retries", sandbox.retries === 1);
check("download start failure cancels the bridge", sandbox.cancelled);
check("download start failure retry sends no status", sandbox.statusBeacons.length === 0);

sandbox = makeSandbox(["/a", "/b"], 0);
sandbox.downloadResponses = [
  JSON.stringify({
    completed: true,
    httpStatus: 200,
    aborted: true,
    interrupted: false,
  }),
];
sandbox.requestDownload("autoroot.sh", function () {
  sandbox.completed++;
});
check("aborted download does not complete", sandbox.completed === 0);
check(
  "aborted download stops",
  sandbox.statuses.indexOf("stopped: download failed") >= 0
);

sandbox = makeSandbox(["/a", "/b"], 0);
sandbox.downloadResponses = [
  JSON.stringify({
    completed: true,
    httpStatus: 200,
    aborted: false,
    interrupted: true,
  }),
];
sandbox.requestDownload("autoroot.sh", function () {
  sandbox.completed++;
});
check("interrupted download does not complete", sandbox.completed === 0);
check(
  "interrupted download stops",
  sandbox.statuses.indexOf("stopped: download failed") >= 0
);

sandbox = makeSandbox(["/a", "/b"], 0);
sandbox.downloadResponses = [
  JSON.stringify({
    completed: true,
    httpStatus: 404,
    aborted: false,
    interrupted: false,
  }),
];
sandbox.requestDownload("autoroot.sh", function () {
  sandbox.completed++;
});
check("HTTP-error download does not complete", sandbox.completed === 0);
check(
  "HTTP-error download stops",
  sandbox.statuses.indexOf("stopped: download failed") >= 0
);

sandbox = makeSandbox(["/a", "/b"], 0);
sandbox.serviceResponse = JSON.stringify({
  returnValue: false,
  errorText: "path not in trusted locations",
});
sandbox.runService();
check("service failure retries", sandbox.retries === 1);
check("service failure cancels the bridge", sandbox.cancelled);
check(
  "service failure does not stop after retrying",
  sandbox.statuses.indexOf("stopped: service failed to start") < 0
);
check("service failure retry sends no status", sandbox.statusBeacons.length === 0);

sandbox = makeSandbox(["/a"], 0);
sandbox.serviceResponse = JSON.stringify({
  returnValue: false,
  errorText: "path not in trusted locations",
});
sandbox.runService();
check(
  "service failure stops when no retry is possible",
  sandbox.statuses.indexOf("stopped: service failed to start") >= 0
);
check(
  "terminal service failure reports failed",
  sandbox.statusBeacons.indexOf("failed") >= 0
);

sandbox = makeSandbox(["/a", "/b"], 0);
sandbox.serviceResponse = JSON.stringify({ returnValue: true });
sandbox.runService();
check(
  "service success reports ok",
  sandbox.statusBeacons.length === 1 && sandbox.statusBeacons[0] === "ok"
);

if (failures > 0) {
  process.exit(1);
}
console.log("js retry tests OK");
