/*!
 * nodeclient.js - node client for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const AsyncObject = require('../utils/asyncobject');

/**
 * NodeClient
 * Sort of a fake local client for separation of concerns.
 * @alias module:node.NodeClient
 * @constructor
 */

function NodeClient(node) {
  if (!(this instanceof NodeClient))
    return new NodeClient(node);

  AsyncObject.call(this);

  this.node = node;
  this.network = node.network;
  this.filter = null;
  this.listen = false;

  this._init();
}

Object.setPrototypeOf(NodeClient.prototype, AsyncObject.prototype);

/**
 * Initialize the client.
 * @returns {Promise}
 */

NodeClient.prototype._init = function _init() {
  this.node.on('connect', (entry, block) => {
    if (!this.listen)
      return;

    this.emit('block connect', entry, block.txs);
  });

  this.node.on('disconnect', (entry, block) => {
    if (!this.listen)
      return;

    this.emit('block disconnect', entry);
  });

  this.node.on('tx', (tx) => {
    if (!this.listen)
      return;

    this.emit('tx', tx);
  });

  this.node.on('reset', (tip) => {
    if (!this.listen)
      return;

    this.emit('chain reset', tip);
  });
};

/**
 * Open the client.
 * @returns {Promise}
 */

NodeClient.prototype._open = function _open(options) {
  this.listen = true;
  return Promise.resolve();
};

/**
 * Close the client.
 * @returns {Promise}
 */

NodeClient.prototype._close = function _close() {
  this.listen = false;
  return Promise.resolve();
};

/**
 * Get chain tip.
 * @returns {Promise}
 */

NodeClient.prototype.getTip = function getTip() {
  return Promise.resolve(this.node.chain.tip);
};

/**
 * Get chain entry.
 * @param {Hash} hash
 * @returns {Promise}
 */

NodeClient.prototype.getEntry = async function getEntry(hash) {
  const entry = await this.node.chain.getEntry(hash);

  if (!entry)
    return null;

  if (!await this.node.chain.isMainChain(entry))
    return null;

  return entry;
};

/**
 * Send a transaction. Do not wait for promise.
 * @param {TX} tx
 * @returns {Promise}
 */

NodeClient.prototype.send = function send(tx) {
  this.node.relay(tx);
  return Promise.resolve();
};

/**
 * Set bloom filter.
 * @param {Bloom} filter
 * @returns {Promise}
 */

NodeClient.prototype.setFilter = function setFilter(filter) {
  this.filter = filter;
  this.node.pool.setFilter(filter);
  return Promise.resolve();
};

/**
 * Add data to filter.
 * @param {Buffer} data
 * @returns {Promise}
 */

NodeClient.prototype.addFilter = function addFilter(data) {
  this.node.pool.queueFilterLoad();
  return Promise.resolve();
};

/**
 * Reset filter.
 * @returns {Promise}
 */

NodeClient.prototype.resetFilter = function resetFilter() {
  this.node.pool.queueFilterLoad();
  return Promise.resolve();
};

/**
 * Esimate smart fee.
 * @param {Number?} blocks
 * @returns {Promise}
 */

NodeClient.prototype.estimateFee = async function estimateFee(blocks) {
  if (!this.node.fees)
    return this.network.feeRate;

  return this.node.fees.estimateFee(blocks);
};

/**
 * Rescan for any missed transactions.
 * @param {Number|Hash} start - Start block.
 * @param {Bloom} filter
 * @param {Function} iter - Iterator.
 * @returns {Promise}
 */

NodeClient.prototype.rescan = function rescan(start) {
  return this.node.chain.scan(start, this.filter, (entry, txs) => {
    return this.fire('block rescan', entry, txs);
  });
};

/*
 * Expose
 */

module.exports = NodeClient;
