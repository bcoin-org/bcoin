/*!
 * parent.js - worker processes for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const EventEmitter = require('events');
const util = require('../utils/util');

/**
 * Represents the parent process.
 * @alias module:workers.Parent
 * @constructor
 */

function Parent() {
  if (!(this instanceof Parent))
    return new Parent();

  EventEmitter.call(this);

  this.init();
}

util.inherits(Parent, EventEmitter);

/**
 * Initialize master (node.js).
 * @private
 */

Parent.prototype.init = function init() {
  process.stdin.on('data', (data) => {
    this.emit('data', data);
  });

  // Nowhere to send these errors:
  process.stdin.on('error', () => {});
  process.stdout.on('error', () => {});
  process.stderr.on('error', () => {});

  process.on('uncaughtException', (err) => {
    this.emit('exception', err);
  });
};

/**
 * Send data to parent process.
 * @param {Buffer} data
 * @returns {Boolean}
 */

Parent.prototype.write = function write(data) {
  return process.stdout.write(data);
};

/**
 * Destroy the parent process.
 */

Parent.prototype.destroy = function destroy() {
  return process.exit(0);
};

/*
 * Expose
 */

module.exports = Parent;
