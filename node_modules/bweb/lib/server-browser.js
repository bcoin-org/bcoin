/*!
 * server.js - http server for bweb
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bweb
 */

'use strict';

const EventEmitter = require('events');
const RPC = require('./rpc');

/**
 * HTTP Server
 * @extends EventEmitter
 */

class Server extends EventEmitter {
  /**
   * Create an http server.
   * @constructor
   * @param {Object?} options
   */

  constructor(options) {
    super();
    this.options = options;
    this.config = {};
    this.server = new EventEmitter();
    this.io = new EventEmitter();
    this.rpc = new RPC();
  }

  async open() {
    this.emit('listening', this.address());
  }

  async close() {}

  error() {}

  mount() {}

  use() {}

  hook() {}

  get() {}

  post() {}

  put() {}

  del() {}

  patch() {}

  channel() {
    return null;
  }

  join() {}

  leave() {}

  to() {}

  all() {}

  async execute() {}

  add() {}

  address() {
    return { address: 'localhost', port: 80 };
  }

  router() {
    return async () => {};
  }

  cors() {
    return async () => {};
  }

  basicAuth() {
    return async () => {};
  }

  bodyParser() {
    return async () => {};
  }

  jsonRPC() {
    return async () => {};
  }

  fileServer() {
    return async () => {};
  }

  cookieParser() {
    return async () => {};
  }
}

/*
 * Expose
 */

module.exports = Server;
