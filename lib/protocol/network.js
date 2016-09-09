/*!
 * network.js - network object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var utils = require('../utils/utils');
var assert = utils.assert;
var networks = require('./networks');

/**
 * Represents a network.
 * @exports Network
 * @constructor
 * @param {Object|NetworkType} options - See {@link module:network}.
 * @property {Number} height
 * @property {Rate} feeRate
 * @property {Rate} minRelay
 * @property {PolicyEstimator} fees
 */

function Network(options) {
  if (!(this instanceof Network))
    return new Network(options);

  assert(!Network[options.type], 'Cannot create two networks.');

  this.type = options.type;
  this.height = options.height;
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
  this.keyPrefix = options.keyPrefix;
  this.addressPrefix = options.addressPrefix;
  this.requireStandard = options.requireStandard;
  this.rpcPort = options.rpcPort;
  this.minRelay = options.minRelay;
  this.feeRate = options.feeRate;
  this.minRate = options.minRate;
  this.maxRate = options.maxRate;
  this.selfConnect = options.selfConnect;
  this.requestMempool = options.requestMempool;
  this.batchSize = options.batchSize;
}

/**
 * Default network.
 * @type {String}
 */

Network.primary = null;

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
 * Expose
 */

module.exports = Network;
