/*!
 * tcp.js - tcp backend for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const ProxySocket = require('./proxysocket');
const EventEmitter = require('events');
const tcp = exports;

tcp.createSocket = function createSocket(port, host, proxy) {
  return ProxySocket.connect(proxy, port, host);
};

tcp.createServer = function createServer() {
  let server = new EventEmitter();

  server.listen = async function listen(port, host) {
    server.emit('listening');
    return;
  };

  server.close = async function close() {
    return;
  };

  server.address = function address() {
    return {
      address: '127.0.0.1',
      port: 0
    };
  };

  server.maxConnections = undefined;

  return server;
};
