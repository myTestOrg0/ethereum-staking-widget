import { createServer } from "http";
import { parse } from "url";
import next from "next";

import defaultsDeep from "lodash/defaultsDeep.js";
import shellQuote from "shell-quote";       

import { exec } from "child_process";      

const dev = process.env.NODE_ENV !== "production";
const hostname = "localhost";
const port = Number(process.env.PORT) || 3000;

// when using middleware `hostname` and `port` must be provided below
const app = next({ dev, hostname, port });
const handle = app.getRequestHandler();

// cannot import from next.config.mjs because this will break env load
const CACHE_CONTROL_HEADER = "x-cache-control";


// =====================
// check CVE (Prototype Pollution in lodash < 4.17.12)
const mergeFn = defaultsDeep;
const payload = '{"constructor": {"prototype": {"a0": true}}}';

function checkPrototypePollution() {
  mergeFn({}, JSON.parse(payload));
  if (({})["a0"] === true) {
    console.log(`Vulnerable to Prototype Pollution via ${payload}`);
  } else {
    console.log("Not polluted (maybe lodash version patched?)");
  }
}
// =====================


// =====================
// check CVE (Command Injection via shell-quote < 1.7.3, CVE-2021-42740)
const injPayload = 'hello"; echo INJECTED; #';

function checkCommandInjection() {
  const quoted = shellQuote.quote([injPayload]); // <-- vuln call
  const cmd = `echo ${quoted}`;                 

  exec(cmd, (err, stdout, stderr) => {          // <-- sink: exec()
    if (err) {
      console.error("Command injection check error:", err);
      return;
    }
    console.log("Command injection check stdout:\n", stdout.trim());
    if (stderr) console.log("stderr:\n", stderr.trim());
  });
}
// =====================


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

    // ==== CVE checks ====
    checkPrototypePollution();
    checkCommandInjection();
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
