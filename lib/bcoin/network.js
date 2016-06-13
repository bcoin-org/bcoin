/*!
 * network.js - network object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var utils = require('./utils');
var assert = utils.assert;
var constants = require('./protocol/constants');
var network = require('./protocol/network');
var PolicyEstimator = require('./fees');

/**
 * Represents a network.
 * @exports Network
 * @constructor
 * @param {Object|NetworkType} options - See {@link module:network}.
 * @property {Number} height
 * @property {Rate} feeRate
 * @property {Rate} minRelay
 */

function Network(options) {
  var i, keys, key, value;

  if (!(this instanceof Network))
    return new Network(options);

  if (typeof options === 'string')
    options = network[options];

  assert(options, 'Unknown network.');

  if (Network[options.type])
    return Network[options.type];

  keys = Object.keys(options);

  for (i = 0; i < keys.length; i++) {
    key = keys[i];
    value = options[key];
    this[key] = value;
  }

  this.fees = new PolicyEstimator(constants.tx.MIN_RELAY, this);

  if (!Network[this.type])
    Network[this.type] = this;

  if (!Network.primary)
    Network.primary = this.type;
}

/**
 * Default network.
 * @type {String}
 */

Network.primary = null;

/**
 * Update the height of the network.
 * @param {Number} height
 */

Network.prototype.updateHeight = function updateHeight(height) {
  this.height = height;
};

/**
 * Update the estimated fee rate of the network.
 * @param {Rate} rate
 */

Network.prototype.updateRate = function updateRate(rate) {
  this.feeRate = rate;
};

/**
 * Update the minimum relay rate (reject rate) of the network.
 * @param {Rate} rate
 */

Network.prototype.updateMinRelay = function updateMinRelay(rate) {
  this.minRelay = rate;
};

/**
 * Calculate the minimum relay rate. If the network is
 * inactive (height=-1), return the default minimum relay.
 * @return {Rate} Rate
 */

Network.prototype.getMinRelay = function getMinRelay() {
  if (this.height === -1)
    return this.minRate;

  return Math.min(this.minRelay, this.maxRate);
};

/**
 * Calculate the normal relay rate. If the network is
 * inactive (height=-1), return the default rate.
 * @return {Rate} Rate
 */

Network.prototype.getRate = function getRate() {
  if (this.height === -1)
    return this.maxRate;

  return Math.min(this.feeRate, this.maxRate);
};

/**
 * Set the default network. This network will be used
 * if nothing is passed as the `network` option for
 * certain objects.
 * @param {NetworkType} type - Network type.
 * @returns {Network}
 */

Network.set = function set(type) {
  assert(typeof type === 'string', 'Bad network.');
  Network.primary = type;
  return Network(network[type]);
};

/**
 * Get a network with a string or a Network object.
 * @param {NetworkType|Network} options - Network type.
 * @returns {Network}
 */

Network.get = function get(options) {
  if (!options) {
    assert(Network.primary, 'No default network.');
    return Network[Network.primary];
  }

  if (options instanceof Network)
    return options;

  if (typeof options === 'string')
    return Network(network[options]);

  assert(false, 'Unknown network.');
};

/**
 * Get a network by its magic number.
 * @returns {Network}
 */

Network.fromMagic = function fromMagic(magic) {
  var i, type;

  for (i = 0; i < network.types.length; i++) {
    type = network.types[i];
    if (magic === network[type].magic)
      break;
  }

  assert(i < network.types.length, 'Network not found.');

  return Network.get(type);
};

/**
 * Convert the network to a string.
 * @returns {String}
 */

Network.prototype.toString = function toString() {
  return this.type;
};

/**
 * Inspect the network.
 * @returns {String}
 */

Network.prototype.inspect = function inspect() {
  return '<Network: ' + this.type + '>';
};

/**
 * Test an object to see if it is a Network.
 * @param {Object} obj
 * @returns {Boolean}
 */

Network.isNetwork = function isNetwork(obj) {
  return obj
    && typeof obj.getMinRelay === 'function'
    && typeof obj.genesisBlock === 'string'
    && typeof obj.pow === 'object';
};

/*
 * Expose
 */

module.exports = Network;
