/*!
 * tcp.js - tcp backend for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const EventEmitter = require('events');
const net = require('net');
const socks = require('./socks');

/**
 * @exports net/tcp
 */

const tcp = exports;

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
  let server = new net.Server();
  let ee = new EventEmitter();

  ee.listen = function listen(port, host) {
    return new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(port, host, () => {
        server.removeListener('error', reject);
        resolve();
      });
    });
  };

  ee.close = function close() {
    return new Promise((resolve, reject) => {
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

  server.on('listening', () => {
    ee.emit('listening');
  });

  server.on('connection', (socket) => {
    ee.emit('connection', socket);
  });

  server.on('error', (err) => {
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
