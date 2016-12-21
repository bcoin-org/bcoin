/*!
 * tcp.js - tcp backend for bcoin
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var net = require('net');
var tcp = exports;

tcp.createSocket = function createSocket(port, host, proxy) {
  return net.connect(port, host);
};

tcp.createServer = function createServer() {
  return new net.Server();
};
