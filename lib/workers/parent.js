/*!
 * parent.js - worker processes for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const EventEmitter = require('events');

/**
 * Parent
 * Represents the parent process.
 * @alias module:workers.Parent
 * @extends EventEmitter
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
   * Initialize master (node.js).
   * @private
   */

  init() {
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
  }

  /**
   * Send data to parent process.
   * @param {Buffer} data
   * @returns {Boolean}
   */

  write(data) {
    return process.stdout.write(data);
  }

  /**
   * Destroy the parent process.
   */

  destroy() {
    process.exit(0);
  }
}

/*
 * Expose
 */

module.exports = Parent;
