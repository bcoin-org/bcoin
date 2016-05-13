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

  if (typeof options === 'string')
    options = network[options];

  assert(options, 'Network requires a type or options.');

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
  this.rate = rate;
};

/**
 * Test an object to see if it is an Address.
 * @param {Object} obj
 * @returns {Boolean}
 */

Network.set = function set(type) {
  assert(type, 'Bad network.');

  if (!Network[type])
    Network[type] = new Network(type);

  if (!Network.primary)
    Network.primary = type;

  return Network[type];
};

Network.get = function get(options) {
  var net;

  if (!options) {
    assert(Network.primary, 'No default network.');
    return Network[Network.primary];
  }

  if (options instanceof Network)
    return options;

  if (typeof options === 'string') {
    assert(Network[options], 'Network not created.');
    return Network[options];
  }

  assert(false, 'Unknown network.');
};

module.exports = Network;
