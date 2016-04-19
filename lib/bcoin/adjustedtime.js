/*!
 * adjustedtime.js - time management for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/indutny/bcoin
 */

module.exports = function(bcoin) {

var EventEmitter = require('events').EventEmitter;
var utils = require('./utils');
var assert = utils.assert;

/**
 * An object which handles "adjusted time". This may not
 * look it, but this is actually a semi-consensus-critical
 * piece of code. It handles version packets from peers
 * and calculates what to offset our system clock's time by.
 * @exports AdjustedTime
 * @constructor
 * @param {Number} [limit=200]
 * @property {Array} samples
 * @property {Object} known
 */

function AdjustedTime(limit) {
  if (!(this instanceof AdjustedTime))
    return new AdjustedTime(limit);

  EventEmitter.call(this);

  if (limit == null)
    limit = 200;

  this.samples = [];
  this.known = {};
  this._checked = false;
}

utils.inherits(AdjustedTime, EventEmitter);

/**
 * Add time data.
 * @param {String} host
 * @param {Number} time
 */

AdjustedTime.prototype.add = function add(host, time) {
  var sample = time - utils.now();
  var i, median, match, offset;

  if (this.samples.length >= 200)
    return;

  if (this.known[host])
    return;

  this.known[host] = sample;

  i = utils.binarySearch(this.samples, sample, true, compare);
  this.samples.splice(i + 1, 0, sample);

  bcoin.debug('Added time data: samples=%d, offset=%d (%d minutes)',
    this.samples.length, sample, sample / 60 | 0);

  if (this.samples.length >= 5 && this.samples.length % 2 === 1) {
    median = this.samples[this.samples / 2 | 0];

    if (Math.abs(median) < 70 * 60) {
      this.offset = median;
    } else {
      this.offset = 0;
      if (!this._checked) {
        match = false;
        for (i = 0; i < this.samples.length; i++) {
          offset = this.samples[i];
          if (offset !== 0 && Math.abs(offset) < 5 * 60) {
            match = true;
            break;
          }
          if (!match) {
            this._checked = true;
            bcoin.debug('Please make sure your system clock is correct!');
          }
        }
      }
    }

    bcoin.debug('Time offset: %d (%d minutes)',
      this.offset, this.offset / 60 | 0);
  }
};

/**
 * Get the current adjusted time.
 * @returns {Number} Time.
 */

AdjustedTime.prototype.now = function now() {
  return utils.now() + this.offset;
};

function compare(a, b) {
  return a - b;
}

return AdjustedTime;
};
