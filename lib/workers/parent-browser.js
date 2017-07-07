/*!
 * parent.js - worker processes for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const EventEmitter = require('events');
const util = require('../utils/util');

/**
 * Represents the parent process.
 * @alias module:workers.Parent
 * @constructor
 * @ignore
 */

function Parent() {
  if (!(this instanceof Parent))
    return new Parent();

  EventEmitter.call(this);

  this.init();
}

util.inherits(Parent, EventEmitter);

/**
 * Initialize master (web workers).
 * @private
 */

Parent.prototype.init = function init() {
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
};

/**
 * Send data to parent process.
 * @param {Buffer} data
 * @returns {Boolean}
 */

Parent.prototype.write = function write(data) {
  if (global.postMessage.length === 2) {
    data.__proto__ = Uint8Array.prototype;
    global.postMessage({ data }, [data]);
  } else {
    global.postMessage(data.toString('hex'));
  }
  return true;
};

/**
 * Destroy the parent process.
 */

Parent.prototype.destroy = function destroy() {
  global.close();
};

/*
 * Expose
 */

module.exports = Parent;
