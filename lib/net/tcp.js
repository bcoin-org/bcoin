/*!
 * tcp.js - tcp backend for bcoin
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var net = require('net');
var tcp = exports;

tcp.connect = function connect(port, host) {
  return net.connect(port, host);
};

tcp.Server = net.Server;
