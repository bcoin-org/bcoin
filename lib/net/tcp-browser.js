/*!
 * tcp.js - tcp backend for bcoin
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var ProxySocket = require('./proxysocket');
var EventEmitter = require('events').EventEmitter;
var tcp = exports;

tcp.createSocket = function createSocket(port, host, proxy) {
  return ProxySocket.connect(proxy, port, host);
};

tcp.createServer = function createServer() {
  var server = new EventEmitter();
  server.listen = function listen(port, host, callback) {
    callback();
    server.emit('listening');
  };
  server.close = function close(callback) {
    callback();
  };
  server.address = function address() {
    return {
      address: '127.0.0.1',
      port: 0
    };
  };
  return server;
};
