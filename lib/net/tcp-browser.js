/*!
 * tcp.js - tcp backend for bcoin
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var ProxySocket = require('./proxysocket');
var tcp = exports;

tcp.connect = function connect(port, host, uri) {
  return ProxySocket.connect(uri, port, host);
};

tcp.Server = null;
