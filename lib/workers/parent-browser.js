/*!
 * parent.js - worker processes for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const EventEmitter = require('events');

/**
 * Parent
 * Represents the parent process.
 * @alias module:workers.Parent
 * @extends EventEmitter
 * @ignore
 */

class Parent extends EventEmitter {
  /**
   * Create the parent process.
   * @constructor
   */

  constructor() {
    super();

    this.init();
  }

  /**
   * Initialize master (web workers).
   * @private
   */

  init() {
    global.onerror = (event) => {
      this.emit('error', new Error('Worker error.'));
    };

    global.onmessage = (event) => {
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
   * Send data to parent process.
   * @param {Buffer} data
   * @returns {Boolean}
   */

  write(data) {
    if (global.postMessage.length === 2) {
      data.__proto__ = Uint8Array.prototype;
      global.postMessage({ data }, [data]);
    } else {
      global.postMessage(data.toString('hex'));
    }
    return true;
  }

  /**
   * Destroy the parent process.
   */

  destroy() {
    global.close();
  }
}

/*
 * Expose
 */

module.exports = Parent;
