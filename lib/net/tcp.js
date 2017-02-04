/*!
 * tcp.js - tcp backend for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var EventEmitter = require('events').EventEmitter;
var net = require('net');
var socks = require('./socks');

/**
 * @exports net/tcp
 */

var tcp = exports;

/**
 * Create a TCP socket and connect.
 * @param {Number} port
 * @param {String} host
 * @param {String?} proxy
 * @returns {Object}
 */

tcp.createSocket = function createSocket(port, host, proxy) {
  if (proxy)
    return socks.connect(proxy, port, host);
  return net.connect(port, host);
};

/**
 * Create a TCP server.
 * @returns {Object}
 */

tcp.createServer = function createServer() {
  var server = new net.Server();
  var ee = new EventEmitter();

  ee.listen = function listen(port, host) {
    return new Promise(function(resolve, reject) {
      server.listen(port, host, wrap(resolve, reject));
    });
  };

  ee.close = function close() {
    return new Promise(function(resolve, reject) {
      server.close(wrap(resolve, reject));
    });
  };

  ee.address = function address() {
    return server.address();
  };

  ee.__defineGetter__('maxConnections', function() {
    return server.maxConnections;
  });

  ee.__defineSetter__('maxConnections', function(value) {
    server.maxConnections = value;
    return server.maxConnections;
  });

  server.on('listening', function() {
    ee.emit('listening');
  });

  server.on('connection', function(socket) {
    ee.emit('connection', socket);
  });

  server.on('error', function(err) {
    ee.emit('error', err);
  });

  return ee;
};

/*
 * Helpers
 */

function wrap(resolve, reject) {
  return function(err, result) {
    if (err) {
      reject(err);
      return;
    }
    resolve(result);
  };
}
