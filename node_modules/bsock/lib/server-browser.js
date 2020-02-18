'use strict';

const EventEmitter = require('events');

class Server extends EventEmitter {
  constructor(options) {
    super();

    this.sockets = new Set();
    this.channels = new Map();
    this.mounts = [];
  }

  attach() {
    return this;
  }

  mount() {}

  async open() {}

  async close() {}

  join() {
    return true;
  }

  leave() {
    return true;
  }

  channel() {
    return null;
  }

  to() {}

  all() {}

  static attach(parent, options) {
    const server = new this(options);
    return server.attach(parent);
  }

  static createServer(options) {
    return new this(options);
  }
}

module.exports = Server;
