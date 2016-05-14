/*!
 * network.js - network object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/indutny/bcoin
 */

var utils = require('./utils');
var assert = utils.assert;
var network = require('./protocol/network');

/**
 * Represents a key ring which amounts to an address. Used for {@link Wallet}.
 * @exports Address
 * @constructor
 * @param {Object} options
 * @param {String?} options.label
 * @param {Boolean?} options.derived
 * @param {HDPrivateKey|HDPublicKey} options.key
 * @param {String?} options.path
 * @param {Boolean?} options.change
 * @param {Number?} options.index
 * @param {String?} options.type - `"pubkeyhash"` or `"multisig"`.
 * @param {Buffer[]} options.keys - Shared multisig keys.
 * @param {Number?} options.m - Multisig `m` value.
 * @param {Number?} options.n - Multisig `n` value.
 * @param {Boolean?} options.witness - Whether witness programs are enabled.
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

  if (!Network[this.type])
    Network[this.type] = this;

  if (!Network.primary)
    Network.primary = this.type;
}

Network.primary = null;

/**
 * Test an object to see if it is an Address.
 * @param {Object} obj
 * @returns {Boolean}
 */

Network.prototype.updateHeight = function updateHeight(height) {
  this.height = height;
};

/**
 * Return address ID (pubkeyhash address of pubkey).
 * @returns {Base58Address}
 */

Network.prototype.updateRate = function updateRate(rate) {
  this.feeRate = rate;
};

Network.prototype.updateMinRelay = function updateMinRelay(rate) {
  this.minRelay = rate;
};

Network.prototype.getMinRelay = function getMinRelay() {
  if (this.height === -1)
    return this.minRate;

  return Math.min(this.minRelay, this.maxRate);
};

Network.prototype.getRate = function getRate() {
  if (this.height === -1)
    return this.maxRate;

  return Math.min(this.feeRate, this.maxRate);
};

/**
 * Test an object to see if it is an Address.
 * @param {Object} obj
 * @returns {Boolean}
 */

Network.set = function set(type) {
  assert(typeof type === 'string', 'Bad network.');
  Network.primary = type;
  return Network(network[type]);
};

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

Network.prototype.inspect = function inspect() {
  return '<Network: ' + this.type + '>';
};

module.exports = Network;
