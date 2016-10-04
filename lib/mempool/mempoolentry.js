/*!
 * mempoolentry.js - mempool entry object for bcoin
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var constants = require('../protocol/constants');
var utils = require('../utils/utils');
var TX = require('../primitives/tx');

/**
 * Represents a mempool entry.
 * @exports MempoolEntry
 * @constructor
 * @param {Object} options
 * @param {TX} options.tx - Transaction in mempool.
 * @param {Number} options.height - Entry height.
 * @param {Number} options.priority - Entry priority.
 * @param {Number} options.ts - Entry time.
 * @param {Amount} options.chainValue - Value of on-chain coins.
 * @param {Number} options.count - Number of descendants (includes tx).
 * @param {Number} options.size - TX and descendant modified size.
 * @param {Amount} options.fees - TX and descendant delta-applied fees.
 * @property {TX} tx
 * @property {Number} height
 * @property {Number} priority
 * @property {Number} ts
 * @property {Amount} chainValue
 * @property {Number} count
 * @property {Number} size
 * @property {Amount} fees
 */

function MempoolEntry(options) {
  if (!(this instanceof MempoolEntry))
    return new MempoolEntry(options);

  this.tx = null;
  this.height = -1;
  this.size = 0;
  this.priority = 0;
  this.fee = 0;
  this.ts = 0;

  this.chainValue = 0;
  this.count = 0;
  this.sizes = 0;
  this.fees = 0;
  this.dependencies = false;

  if (options)
    this.fromOptions(options);
}

/**
 * Inject properties from options object.
 * @private
 * @param {Object} options
 */

MempoolEntry.prototype.fromOptions = function fromOptions(options) {
  this.tx = options.tx;
  this.height = options.height;
  this.size = options.size;
  this.priority = options.priority;
  this.fee = options.fee;
  this.ts = options.ts;

  this.chainValue = options.chainValue;
  this.count = options.count;
  this.sizes = options.sizes;
  this.fees = options.fees;
  this.dependencies = options.dependencies;

  return this;
};

/**
 * Instantiate mempool entry from options.
 * @param {Object} options
 * @returns {MempoolEntry}
 */

MempoolEntry.fromOptions = function fromOptions(options) {
  return new MempoolEntry().fromOptions(options);
};

/**
 * Inject properties from transaction.
 * @private
 * @param {TX} tx
 * @param {Number} height
 */

MempoolEntry.prototype.fromTX = function fromTX(tx, height) {
  var priority = tx.getPriority(height);
  var value = tx.getChainValue(height);
  var dependencies = false;
  var size = tx.getVirtualSize();
  var fee = tx.getFee();
  var i;

  for (i = 0; i < tx.inputs.length; i++) {
    if (tx.inputs[i].coin.height === -1) {
      dependencies = true;
      break;
    }
  }

  this.tx = tx;
  this.height = height;
  this.size = size;
  this.priority = priority;
  this.fee = fee;
  this.chainValue = value;
  this.ts = utils.now();
  this.count = 1;
  this.sizes = size;
  this.fees = fee;
  this.dependencies = dependencies;

  return this;
};

/**
 * Create a mempool entry from a TX.
 * @param {TX} tx
 * @param {Number} height - Entry height.
 * @returns {MempoolEntry}
 */

MempoolEntry.fromTX = function fromTX(tx, height) {
  return new MempoolEntry().fromTX(tx, height);
};

/**
 * Calculate priority, taking into account
 * the entry height delta, modified size,
 * and chain value.
 * @param {Number} height
 * @returns {Number} Priority.
 */

MempoolEntry.prototype.getPriority = function getPriority(height) {
  var heightDelta = height - this.height;
  var modSize = this.tx.getModifiedSize(this.size);
  var deltaPriority = (heightDelta * this.chainValue) / modSize;
  var result = this.priority + Math.floor(deltaPriority);
  if (result < 0)
    result = 0;
  return result;
};

/**
 * Get fee.
 * @returns {Amount}
 */

MempoolEntry.prototype.getFee = function getFee() {
  return this.fee;
};

/**
 * Calculate fee rate.
 * @returns {Rate}
 */

MempoolEntry.prototype.getRate = function getRate() {
  return TX.getRate(this.size, this.fee);
};

/**
 * Test whether the entry is free with
 * the current priority (calculated by
 * current height).
 * @param {Number} height
 * @returns {Boolean}
 */

MempoolEntry.prototype.isFree = function isFree(height) {
  var priority = this.getPriority(height);
  return priority > constants.tx.FREE_THRESHOLD;
};

/*
 * Expose
 */

module.exports = MempoolEntry;
