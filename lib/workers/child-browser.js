/*!
 * child.js - child processes for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const EventEmitter = require('events');
const util = require('../utils/util');

/**
 * Represents a worker.
 * @alias module:workers.Child
 * @constructor
 * @param {String} file
 * @param {Object} env
 */

function Child(file, env) {
  if (!(this instanceof Child))
    return new Child(file, env);

  EventEmitter.call(this);

  this.init(file, env);
}

util.inherits(Child, EventEmitter);

/**
 * Test whether worker support is available.
 * @returns {Boolean}
 */

Child.hasSupport = function hasSupport() {
  return typeof global.postMessage === 'function';
};

/**
 * Initialize worker. Bind to events.
 * @private
 */

Child.prototype.init = function init(file, env) {
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

  this.child.postMessage(JSON.stringify(env));
};

/**
 * Send data to worker.
 * @param {Buffer} data
 * @returns {Boolean}
 */

Child.prototype.write = function write(data) {
  if (this.child.postMessage.length === 2) {
    data.__proto__ = Uint8Array.prototype;
    this.child.postMessage({ data }, [data]);
  } else {
    this.child.postMessage(data.toString('hex'));
  }
  return true;
};

/**
 * Destroy the worker.
 */

Child.prototype.destroy = function destroy() {
  this.child.terminate();
  this.emit('exit', 15 | 0x80, 'SIGTERM');
};

/*
 * Expose
 */

module.exports = Child;
