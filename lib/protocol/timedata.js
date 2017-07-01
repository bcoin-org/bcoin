/*!
 * time.js - time management for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const util = require('../utils/util');
const EventEmitter = require('events');

/**
 * An object which handles "adjusted time". This may not
 * look it, but this is actually a semi-consensus-critical
 * piece of code. It handles version packets from peers
 * and calculates what to offset our system clock's time by.
 * @alias module:protocol.TimeData
 * @constructor
 * @param {Number} [limit=200]
 * @property {Array} samples
 * @property {Object} known
 * @property {Number} limit
 * @property {Number} offset
 */

function TimeData(limit) {
  if (!(this instanceof TimeData))
    return new TimeData(limit);

  EventEmitter.call(this);

  if (limit == null)
    limit = 200;

  this.samples = [];
  this.known = new Map();
  this.limit = limit;
  this.offset = 0;
  this._checked = false;
}

util.inherits(TimeData, EventEmitter);

/**
 * Add time data.
 * @param {String} id
 * @param {Number} time
 */

TimeData.prototype.add = function add(id, time) {
  let sample = time - util.now();

  if (this.samples.length >= this.limit)
    return;

  if (this.known.has(id))
    return;

  this.known.set(id, sample);

  util.binaryInsert(this.samples, sample, compare);

  this.emit('sample', sample, this.samples.length);

  if (this.samples.length >= 5 && this.samples.length % 2 === 1) {
    let median = this.samples[this.samples / 2 | 0];

    if (Math.abs(median) < 70 * 60) {
      this.offset = median;
    } else {
      this.offset = 0;
      if (!this._checked) {
        let match = false;
        for (let offset of this.samples) {
          if (offset !== 0 && Math.abs(offset) < 5 * 60) {
            match = true;
            break;
          }
        }
        if (!match) {
          this._checked = true;
          this.emit('mismatch');
        }
      }
    }

    this.emit('offset', this.offset);
  }
};

/**
 * Get the current adjusted time.
 * @returns {Number} Adjusted Time.
 */

TimeData.prototype.now = function now() {
  return util.now() + this.offset;
};

/**
 * Adjust a timestamp.
 * @param {Number} time
 * @returns {Number} Adjusted Time.
 */

TimeData.prototype.adjust = function adjust(time) {
  return time + this.offset;
};

/**
 * Unadjust a timestamp.
 * @param {Number} time
 * @returns {Number} Local Time.
 */

TimeData.prototype.local = function local(time) {
  return time - this.offset;
};

/**
 * Get the current adjusted time in milliseconds.
 * @returns {Number} Adjusted Time.
 */

TimeData.prototype.ms = function ms() {
  return util.ms() + this.offset * 1000;
};

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
