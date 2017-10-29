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
  this.listening = false;

  this._init();
}

Object.setPrototypeOf(NodeClient.prototype, AsyncObject.prototype);

/**
 * Initialize the client.
 * @returns {Promise}
 */

NodeClient.prototype._init = function _init() {
  this.node.on('connect', (entry, block) => {
    if (!this.listening)
      return;

    this.emit('block connect', entry, block.txs);
  });

  this.node.on('disconnect', (entry, block) => {
    if (!this.listening)
      return;

    this.emit('block disconnect', entry);
  });

  this.node.on('tx', (tx) => {
    if (!this.listening)
      return;

    this.emit('tx', tx);
  });

  this.node.on('reset', (tip) => {
    if (!this.listening)
      return;

    this.emit('chain reset', tip);
  });
};

/**
 * Open the client.
 * @returns {Promise}
 */

NodeClient.prototype._open = async function _open(options) {
  this.listening = true;
  setImmediate(() => this.emit('connect'));
};

/**
 * Close the client.
 * @returns {Promise}
 */

NodeClient.prototype._close = async function _close() {
  this.listening = false;
  setImmediate(() => this.emit('disconnect'));
};

/**
 * Get chain tip.
 * @returns {Promise}
 */

NodeClient.prototype.getTip = async function getTip() {
  return this.node.chain.tip;
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

NodeClient.prototype.send = async function send(tx) {
  this.node.relay(tx);
};

/**
 * Set bloom filter.
 * @param {Bloom} filter
 * @returns {Promise}
 */

NodeClient.prototype.setFilter = async function setFilter(filter) {
  this.filter = filter;
  this.node.pool.setFilter(filter);
};

/**
 * Add data to filter.
 * @param {Buffer} data
 * @returns {Promise}
 */

NodeClient.prototype.addFilter = async function addFilter(data) {
  this.node.pool.queueFilterLoad();
};

/**
 * Reset filter.
 * @returns {Promise}
 */

NodeClient.prototype.resetFilter = async function resetFilter() {
  this.node.pool.queueFilterLoad();
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
 * Get hash range.
 * @param {Number} start
 * @param {Number} end
 * @returns {Promise}
 */

NodeClient.prototype.getHashes = async function getHashes(start = -1, end = -1) {
  return this.node.chain.getHashes(start, end);
};

/**
 * Rescan for any missed transactions.
 * @param {Number|Hash} start - Start block.
 * @param {Bloom} filter
 * @param {Function} iter - Iterator.
 * @returns {Promise}
 */

NodeClient.prototype.rescan = async function rescan(start) {
  return this.node.chain.scan(start, this.filter, (entry, txs) => {
    return this.call('block rescan', entry, txs);
  });
};

/*
 * Expose
 */

module.exports = NodeClient;
