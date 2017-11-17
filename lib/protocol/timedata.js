/*!
 * timedata.js - time management for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const EventEmitter = require('events');
const util = require('../utils/util');
const binary = require('../utils/binary');

/**
 * Time Data
 * An object which handles "adjusted time". This may not
 * look it, but this is actually a semi-consensus-critical
 * piece of code. It handles version packets from peers
 * and calculates what to offset our system clock's time by.
 * @alias module:protocol.TimeData
 * @extends EventEmitter
 * @property {Array} samples
 * @property {Object} known
 * @property {Number} limit
 * @property {Number} offset
 */

class TimeData extends EventEmitter {
  /**
   * Create time data.
   * @constructor
   * @param {Number} [limit=200]
   */

  constructor(limit) {
    super();

    if (limit == null)
      limit = 200;

    this.samples = [];
    this.known = new Map();
    this.limit = limit;
    this.offset = 0;
    this.checked = false;
  }

  /**
   * Add time data.
   * @param {String} id
   * @param {Number} time
   */

  add(id, time) {
    if (this.samples.length >= this.limit)
      return;

    if (this.known.has(id))
      return;

    const sample = time - util.now();

    this.known.set(id, sample);

    binary.insert(this.samples, sample, compare);

    this.emit('sample', sample, this.samples.length);

    if (this.samples.length >= 5 && this.samples.length % 2 === 1) {
      let median = this.samples[this.samples.length >>> 1];

      if (Math.abs(median) >= 70 * 60) {
        if (!this.checked) {
          let match = false;

          for (const offset of this.samples) {
            if (offset !== 0 && Math.abs(offset) < 5 * 60) {
              match = true;
              break;
            }
          }

          if (!match) {
            this.checked = true;
            this.emit('mismatch');
          }
        }

        median = 0;
      }

      this.offset = median;
      this.emit('offset', this.offset);
    }
  }

  /**
   * Get the current adjusted time.
   * @returns {Number} Adjusted Time.
   */

  now() {
    return util.now() + this.offset;
  }

  /**
   * Adjust a timestamp.
   * @param {Number} time
   * @returns {Number} Adjusted Time.
   */

  adjust(time) {
    return time + this.offset;
  }

  /**
   * Unadjust a timestamp.
   * @param {Number} time
   * @returns {Number} Local Time.
   */

  local(time) {
    return time - this.offset;
  }

  /**
   * Get the current adjusted time in milliseconds.
   * @returns {Number} Adjusted Time.
   */

  ms() {
    return Date.now() + this.offset * 1000;
  }
}

/*
 * Helpers
 */

function compare(a, b) {
  return a - b;
}

/*
 * Expose
 */

module.exports = TimeData;
