// Force any Node HTTP server to bind ONLY to 127.0.0.1, regardless of how the
// app calls .listen(). Loaded via `node --require ./loopback-shim.js app.js`.
//
// Rationale: several vulnerable apps (Juice Shop) call server.listen(port) with
// no host, which binds 0.0.0.0 (all interfaces). This lab must never expose a
// deliberately vulnerable service beyond loopback, so we intercept listen() and
// pin the host to 127.0.0.1 whenever a bare port (or a port + options without an
// explicit host) is requested.
'use strict';
const net = require('net');
// Bind to the app's assigned loopback address (127.0.0.0/8 is all loopback on
// Linux). Defaults to 127.0.0.1 so the shim is safe even if LAB_BIND_IP is unset.
const LOOPBACK = (process.env.LAB_BIND_IP && /^127\.\d+\.\d+\.\d+$/.test(process.env.LAB_BIND_IP))
  ? process.env.LAB_BIND_IP : '127.0.0.1';
const origListen = net.Server.prototype.listen;

net.Server.prototype.listen = function patchedListen(...args) {
  // Signatures we care about:
  //   listen(port[, host][, backlog][, cb])
  //   listen(options[, cb])  where options = { port, host, ... }
  if (typeof args[0] === 'object' && args[0] !== null && !(args[0] instanceof Function)) {
    const opts = args[0];
    if (opts.port !== undefined && (opts.host === undefined || opts.host === '0.0.0.0' || opts.host === '::')) {
      opts.host = LOOPBACK;
    }
    return origListen.apply(this, args);
  }
  if (typeof args[0] === 'number' || (typeof args[0] === 'string' && /^\d+$/.test(args[0]))) {
    // Bare port form. Inject host as arg[1] if it's missing or is a wildcard.
    const host = args[1];
    if (host === undefined || typeof host === 'function' || host === '0.0.0.0' || host === '::') {
      const rest = typeof host === 'function' ? args.slice(1) : args.slice(1).filter((a) => a !== '0.0.0.0' && a !== '::');
      return origListen.call(this, args[0], LOOPBACK, ...rest);
    }
  }
  return origListen.apply(this, args);
};

process.env.HOST = process.env.HOST || LOOPBACK;
process.env.HOSTNAME = process.env.HOSTNAME || LOOPBACK;
