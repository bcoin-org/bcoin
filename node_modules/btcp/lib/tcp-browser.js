/*!
 * tcp.js - tcp backend for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

/* eslint prefer-arrow-callback: "off" */

'use strict';

const EventEmitter = require('events');

/**
 * Socket
 * @extends EventEmitter
 */

class Socket extends EventEmitter {
  /**
   * Create a TCP server.
   * @constructor
   * @param {Function?} handler
   */

  constructor() {
    super();
    this.readable = true;
    this.writable = true;
    this.encrypted = false;
    this.bufferSize = 0;
    this.bytesRead = 0;
    this.bytesWritten = 0;
    this.connecting = false;
    this.destroyed = false;
    this.localAddress = '127.0.0.1';
    this.localPort = 0;
    this.remoteAddress = '127.0.0.1';
    this.remoteFamily = 'IPv4';
    this.remotePort = 0;
  }

  address() {
    return {
      address: '127.0.0.1',
      family: 'IPv4',
      port: 0
    };
  }

  connect(port, host) {
    throw new Error('Unsupported.');
  }

  destroy(err) {
    return this;
  }

  end(data, enc) {
    throw new Error('Unsupported.');
  }

  pause() {
    return this;
  }

  ref() {
    return this;
  }

  resume() {
    return this;
  }

  setEncoding(enc) {
    return this;
  }

  setKeepAlive(enable, delay) {
    return this;
  }

  setNoDelay(value) {
    return this;
  }

  setTimeout(timeout, callback) {
    return this;
  }

  unref() {
    return this;
  }

  write(data, enc) {
    throw new Error('Unsupported.');
  }
}

/**
 * Server
 * @extends EventEmitter
 */

class Server extends EventEmitter {
  /**
   * Create a TCP server.
   * @constructor
   * @param {Function?} handler
   */

  constructor(handler) {
    super();
  }

  address() {
    return {
      address: '127.0.0.1',
      family: 'IPv4',
      port: 0
    };
  }

  async close() {
    return;
  }

  async getConnections() {
    return 0;
  }

  async listen(...args) {
    const address = this.address();
    this.emit('listening', address);
    return address;
  }

  get listening() {
    return false;
  }

  set listening(value) {}

  get maxConnections() {
    return undefined;
  }

  set maxConnections(value) {}

  ref() {
    return this;
  }

  unref() {
    return this;
  }
}

/*
 * Constants
 */

exports.unsupported = true;

/**
 * Socket
 * @constructor
 */

exports.Socket = Socket;

/**
 * Server
 * @constructor
 */

exports.Server = Server;

/**
 * Create a TCP socket and connect.
 * @param {Number} port
 * @param {String} host
 * @returns {Object}
 */

exports.connect = function(port, host) {
  throw new Error('Unsupported.');
};

/**
 * Create a TCP socket and connect.
 * @param {Number} port
 * @param {String} host
 * @returns {Object}
 */

exports.createSocket = exports.connect;

/**
 * Create a TCP socket and connect.
 * @param {Number} port
 * @param {String} host
 * @returns {Object}
 */

exports.createConnection = exports.connect;

/**
 * Create a TCP server.
 * @param {Function?} handler
 * @returns {Object}
 */

exports.createServer = function createServer(handler) {
  return new Server(handler);
};
