/*!
 * network.js - network object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var assert = require('assert');
var util = require('../utils/util');
var networks = require('./networks');
var constants = require('./constants');
var TimeData = require('./timedata');

/**
 * Represents a network.
 * @exports Network
 * @constructor
 * @param {Object|NetworkType} options - See {@link module:network}.
 */

function Network(options) {
  if (!(this instanceof Network))
    return new Network(options);

  assert(!Network[options.type], 'Cannot create two networks.');

  this.type = options.type;
  this.seeds = options.seeds;
  this.magic = options.magic;
  this.port = options.port;
  this.alertKey = options.alertKey;
  this.checkpoints = options.checkpoints;
  this.halvingInterval = options.halvingInterval;
  this.genesis = options.genesis;
  this.genesisBlock = options.genesisBlock;
  this.pow = options.pow;
  this.block = options.block;
  this.witness = options.witness;
  this.oldWitness = options.oldWitness;
  this.activationThreshold = options.activationThreshold;
  this.minerWindow = options.minerWindow;
  this.deployments = options.deployments;
  this.deploys = options.deploys;
  this.unknownBits = ~constants.versionbits.TOP_MASK;
  this.keyPrefix = options.keyPrefix;
  this.addressPrefix = options.addressPrefix;
  this.requireStandard = options.requireStandard;
  this.rpcPort = options.rpcPort;
  this.minRelay = options.minRelay;
  this.feeRate = options.feeRate;
  this.maxFeeRate = options.maxFeeRate;
  this.selfConnect = options.selfConnect;
  this.requestMempool = options.requestMempool;
  this.batchSize = options.batchSize;
  this.time = new TimeData();

  this._init();
}

/**
 * Default network.
 * @type {Network}
 */

Network.primary = null;

/**
 * Default network type.
 * @type {String}
 */

Network.type = null;

/*
 * Networks (to avoid hash table mode).
 */

Network.main = null;
Network.testnet = null;
Network.regtest = null;
Network.segnet3 = null;
Network.segnet4 = null;
Network.simnet = null;

/**
 * Get a deployment by bit index.
 * @param {Number} bit
 * @returns {Object}
 */

Network.prototype._init = function _init() {
  var bits = 0;
  var i, deployment;

  for (i = 0; i < this.deploys.length; i++) {
    deployment = this.deploys[i];
    bits |= 1 << deployment.bit;
  }

  bits |= constants.versionbits.TOP_MASK;

  this.unknownBits = ~bits;
};

/**
 * Get a deployment by bit index.
 * @param {Number} bit
 * @returns {Object}
 */

Network.prototype.byBit = function byBit(bit) {
  var index = util.binarySearch(this.deploys, bit, cmpBit);
  if (index === -1)
    return null;
  return this.deploys[index];
};

/**
 * Determine how many blocks to request
 * based on current height of the chain.
 * @param {Number} height
 * @returns {Number}
 */

Network.prototype.getBatchSize = function getBatchSize(height) {
  var batch = this.batchSize;
  var last = batch.length - 1;
  var i;

  for (i = 0; i < last; i++) {
    if (height <= batch[i][0])
      return batch[i][1];
  }

  return batch[last][0];
};

/**
 * Get network adjusted time.
 * @returns {Number}
 */

Network.prototype.now = function now() {
  return this.time.now();
};

/**
 * Create a network. Get existing network if possible.
 * @param {NetworkType|Object} options
 * @returns {Network}
 */

Network.create = function create(options) {
  var network;

  if (typeof options === 'string')
    options = networks[options];

  assert(options, 'Unknown network.');

  if (Network[options.type])
    return Network[options.type];

  network = new Network(options);

  Network[network.type] = network;

  if (!Network.primary)
    Network.primary = network;

  return network;
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
  Network.primary = Network.get(type);
  Network.type = type;
  return Network.primary;
};

/**
 * Get a network with a string or a Network object.
 * @param {NetworkType|Network} type - Network type.
 * @returns {Network}
 */

Network.get = function get(type) {
  if (!type) {
    assert(Network.primary, 'No default network.');
    return Network.primary;
  }

  if (type instanceof Network)
    return type;

  if (typeof type === 'string')
    return Network.create(type);

  assert(false, 'Unknown network.');
};

/**
 * Get a network with a string or a Network object.
 * @param {NetworkType|Network} type - Network type.
 * @returns {Network}
 */

Network.ensure = function ensure(type) {
  if (!type) {
    assert(Network.primary, 'No default network.');
    return Network.primary;
  }

  if (type instanceof Network)
    return type;

  if (typeof type === 'string') {
    if (networks[type])
      return Network.create(type);
  }

  assert(Network.primary, 'No default network.');

  return Network.primary;
};

/**
 * Get a network by its magic number.
 * @returns {Network}
 */

Network.fromMagic = function fromMagic(magic) {
  var i, type;

  for (i = 0; i < networks.types.length; i++) {
    type = networks.types[i];
    if (magic === networks[type].magic)
      break;
  }

  assert(i < networks.types.length, 'Network not found.');

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
 * Set initial network.
 */

Network.set(process.env.BCOIN_NETWORK || 'main');

/*
 * Helpers
 */

function cmpBit(a, b) {
  return a.bit - b;
}

/*
 * Expose
 */

module.exports = Network;
