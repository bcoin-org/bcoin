/*!
 * child.js - child processes for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const EventEmitter = require('events');

/**
 * Child
 * Represents a child process.
 * @alias module:workers.Child
 * @extends EventEmitter
 * @ignore
 */

class Child extends EventEmitter {
  /**
   * Represents a child process.
   * @constructor
   * @param {String} file
   */

  constructor(file) {
    super();

    this.init(file);
  }

  /**
   * Test whether child process support is available.
   * @returns {Boolean}
   */

  static hasSupport() {
    return typeof global.postMessage === 'function';
  }

  /**
   * Initialize child process. Bind to events.
   * @private
   * @param {String} file
   */

  init(file) {
    this.child = new global.Worker(file);

    this.child.onerror = (event) => {
      this.emit('error', new Error('Child error.'));
      this.emit('exit', 1, null);
    };

    this.child.onmessage = (event) => {
      let data;
      if (typeof event.data === 'string') {
        data = Buffer.from(event.data, 'hex');
        assert(data.length === event.data.length / 2);
      } else {
        assert(event.data && typeof event.data === 'object');
        assert(event.data.data && typeof event.data.data.length === 'number');
        data = event.data.data;
        data.__proto__ = Buffer.prototype;
      }
      this.emit('data', data);
    };
  }

  /**
   * Send data to child process.
   * @param {Buffer} data
   * @returns {Boolean}
   */

  write(data) {
    if (this.child.postMessage.length === 2) {
      data.__proto__ = Uint8Array.prototype;
      this.child.postMessage({ data }, [data]);
    } else {
      this.child.postMessage(data.toString('hex'));
    }
    return true;
  }

  /**
   * Destroy the child process.
   */

  destroy() {
    this.child.terminate();
    this.emit('exit', 15 | 0x80, 'SIGTERM');
  }
}

/*
 * Expose
 */

module.exports = Child;
