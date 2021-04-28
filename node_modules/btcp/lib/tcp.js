/*!
 * tcp.js - tcp backend for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

/* eslint prefer-arrow-callback: "off" */

'use strict';

const EventEmitter = require('events');
const net = require('net');

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

    this.server = new net.Server(handler);
    this._reject = null;

    this.server.on('close', () => {
      this.emit('close');
    });

    this.server.on('connection', (socket) => {
      this.emit('connection', socket);
    });

    this.server.on('error', (err) => {
      const reject = this._reject;

      if (reject) {
        this._reject = null;
        reject(err);
        return;
      }

      this.emit('error', err);
    });

    this.server.on('listening', () => {
      this.emit('listening', this.address());
    });
  }

  address() {
    return this.server.address();
  }

  close() {
    return new Promise((resolve, reject) => {
      this._reject = reject;

      const cb = (err) => {
        this._reject = null;

        if (err) {
          reject(err);
          return;
        }

        resolve();
      };

      try {
        this.server.close(cb);
      } catch (e) {
        this._reject = null;
        reject(e);
      }
    });
  }

  getConnections() {
    return new Promise((resolve, reject) => {
      this.server.getConnections((err, count) => {
        if (err) {
          reject(err);
          return;
        }
        resolve(count);
      });
    });
  }

  listen(...args) {
    return new Promise((resolve, reject) => {
      this._reject = reject;

      args.push(() => {
        this._reject = null;
        resolve(this.address());
      });

      try {
        this.server.listen(...args);
      } catch (e) {
        this._reject = null;
        reject(e);
      }
    });
  }

  get listening() {
    return this.server.listening;
  }

  set listening(value) {}

  get maxConnections() {
    return this.server.maxConnections;
  }

  set maxConnections(value) {
    this.server.maxConnections = value;
  }

  ref() {
    this.server.ref();
    return this;
  }

  unref() {
    this.server.unref();
    return this;
  }
}

/*
 * Constants
 */

exports.unsupported = false;

/**
 * Socket
 * @constructor
 */

exports.Socket = net.Socket;

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

exports.connect = net.connect;

/**
 * Create a TCP socket and connect.
 * @param {Number} port
 * @param {String} host
 * @returns {Object}
 */

exports.createSocket = net.connect;

/**
 * Create a TCP socket and connect.
 * @param {Number} port
 * @param {String} host
 * @returns {Object}
 */

exports.createConnection = net.connect;

/**
 * Create a TCP server.
 * @param {Function?} handler
 * @returns {Object}
 */

exports.createServer = function createServer(handler) {
  return new Server(handler);
};
