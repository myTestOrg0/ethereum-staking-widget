import { createServer } from "http";
import { parse } from "url";
import next from "next";

import defaultsDeep from "lodash/defaultsDeep.js";
import { exec } from "child_process";
import { createRequire } from "module";

const require = createRequire(import.meta.url);

const dev = process.env.NODE_ENV !== "production";
const hostname = "localhost";
const port = Number(process.env.PORT) || 3000;

// when using middleware `hostname` and `port` must be provided below
const app = next({ dev, hostname, port });
const handle = app.getRequestHandler();

// cannot import from next.config.mjs because this will break env load
const CACHE_CONTROL_HEADER = "x-cache-control";

//
// =====================
// check CVE #1 (Prototype Pollution in lodash < 4.17.12)
const mergeFn = defaultsDeep;
const payload = '{"constructor": {"prototype": {"a0": true}}}';

function checkPrototypePollutionLodash() {
  mergeFn({}, JSON.parse(payload));
  if (({})["a0"] === true) {
    console.log(`Vulnerable to Prototype Pollution via ${payload}`);
  } else {
    console.log("Not polluted (maybe lodash version patched?)");
  }
}
// =====================

//
// =====================
// check CVE #2 (Command Injection via shell-quote < 1.7.3, CVE-2021-42740)
const shellQuote = require("shell-quote");
const injPayload = 'hello"; echo INJECTED; #';

function checkCommandInjectionShellQuote() {
  const quoted = shellQuote.quote([injPayload]); // vulnerable call
  const cmd = `echo ${quoted}`; // dangerous concat into a shell command

  exec(cmd, (err, stdout, stderr) => {
    if (err) {
      console.error("Command injection check error:", err);
      return;
    }
    console.log("Command injection check stdout:\n", String(stdout).trim());
    if (stderr) console.log("stderr:\n", String(stderr).trim());
  });
}
// =====================

//
// =====================
// check CVE #3 (ReDoS in ua-parser-js < 0.7.24, CVE-2021-27292)
const UAParser = require("ua-parser-js");

function checkReDoSUaParserJs() {
  const parser = new UAParser();

  // payload
  const redosUA = "Mozilla/5.0 " + "A".repeat(2000000) + " Safari/537.36";

  console.time("ua-parser-js ReDoS check");
  const result = parser.setUA(redosUA).getResult(); // vulnerable path (regex parsing)
  console.timeEnd("ua-parser-js ReDoS check");

  console.log("ua-parser-js parsed keys:", Object.keys(result || {}).length);
}
// =====================

//
// =====================
// check CVE #4 (Prototype Pollution in minimist < 1.2.2, CVE-2020-7598)
const minimist = require("minimist");

function checkPrototypePollutionMinimist() {
  minimist("--__proto__.pp_test true".split(" "));
  if (({})["pp_test"] === "true") {
    console.log("Vulnerable to Prototype Pollution via minimist (__proto__)");
  } else {
    console.log("minimist not polluted (maybe patched?)");
  }
}
// =====================

//
// =====================
// check CVE #5 (Prototype Pollution in set-value < 4.0.1, CVE-2021-23440)
const setValue = require("set-value");

function checkPrototypePollutionSetValue() {
  // bypass pattern described in advisory: nested array segments
  setValue({}, [["proto"], "polluted_set_value"], "yes"); // vulnerable call

  if (({})["polluted_set_value"] === "yes") {
    console.log("Vulnerable to Prototype Pollution via set-value (CVE-2021-23440)");
  } else {
    console.log("set-value not polluted (maybe patched?)");
  }
}
// =====================
//

// allows us to override cache-control header
const overrideSetHeader = (res) => {
  const setHeader = res.setHeader;
  let cacheControlOverwritten = false;

  res.setHeader = function (header, value) {
    if (header.toLowerCase() === CACHE_CONTROL_HEADER) {
      cacheControlOverwritten = true;
      return setHeader.call(this, "Cache-Control", value);
    }

    if (header.toLowerCase() === "cache-control" && cacheControlOverwritten) {
      return this;
    }

    return setHeader.call(this, header, value);
  };
};

// eslint-disable-next-line @typescript-eslint/no-floating-promises
app.prepare().then(() => {
  const server = createServer(async (req, res) => {
    const parsedUrl = parse(req.url, true);

    // ==== checks  ====
    checkPrototypePollutionLodash();
    checkCommandInjectionShellQuote();
    checkReDoSUaParserJs();
    checkPrototypePollutionMinimist();
    checkPrototypePollutionSetValue();
    // =====================

    overrideSetHeader(res);
    await handle(req, res, parsedUrl);
  })
    .once("error", (err) => {
      console.error(err);
      process.exit(1);
    })
    .listen(port, () => {
      console.debug(`> Ready on http://${hostname}:${port}`);
    });

  // prevents malicious client from slowly sending headers and rest of request
  server.headersTimeout = 10_000;
  server.requestTimeout = 30_000;
  server.maxHeadersCount = 50;
});
