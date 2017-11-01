/*!
 * nullclient.js - node client for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const EventEmitter = require('events');

/**
 * NullClient
 * Sort of a fake local client for separation of concerns.
 * @alias module:node.NullClient
 * @constructor
 */

function NullClient(wdb) {
  if (!(this instanceof NullClient))
    return new NullClient(wdb);

  EventEmitter.call(this);

  this.wdb = wdb;
  this.network = wdb.network;
  this.opened = false;
}

Object.setPrototypeOf(NullClient.prototype, EventEmitter.prototype);

/**
 * Open the client.
 * @returns {Promise}
 */

NullClient.prototype.open = async function open(options) {
  assert(!this.opened, 'NullClient is already open.');
  this.opened = true;
  setImmediate(() => this.emit('connect'));
};

/**
 * Close the client.
 * @returns {Promise}
 */

NullClient.prototype.close = async function close() {
  assert(this.opened, 'NullClient is not open.');
  this.opened = false;
  setImmediate(() => this.emit('disconnect'));
};

/**
 * Add a listener.
 * @param {String} type
 * @param {Function} handler
 */

NullClient.prototype.bind = function bind(type, handler) {
  return this.on(type, handler);
};

/**
 * Add a listener.
 * @param {String} type
 * @param {Function} handler
 */

NullClient.prototype.hook = function hook(type, handler) {
  return this.on(type, handler);
};

/**
 * Get chain tip.
 * @returns {Promise}
 */

NullClient.prototype.getTip = async function getTip() {
  const {hash, height, time} = this.network.genesis;
  return { hash, height, time };
};

/**
 * Get chain entry.
 * @param {Hash} hash
 * @returns {Promise}
 */

NullClient.prototype.getEntry = async function getEntry(hash) {
  return { hash, height: 0, time: 0 };
};

/**
 * Send a transaction. Do not wait for promise.
 * @param {TX} tx
 * @returns {Promise}
 */

NullClient.prototype.send = async function send(tx) {
  this.wdb.emit('send', tx);
};

/**
 * Set bloom filter.
 * @param {Bloom} filter
 * @returns {Promise}
 */

NullClient.prototype.setFilter = async function setFilter(filter) {
  this.wdb.emit('set filter', filter);
};

/**
 * Add data to filter.
 * @param {Buffer} data
 * @returns {Promise}
 */

NullClient.prototype.addFilter = async function addFilter(data) {
  this.wdb.emit('add filter', data);
};

/**
 * Reset filter.
 * @returns {Promise}
 */

NullClient.prototype.resetFilter = async function resetFilter() {
  this.wdb.emit('reset filter');
};

/**
 * Esimate smart fee.
 * @param {Number?} blocks
 * @returns {Promise}
 */

NullClient.prototype.estimateFee = async function estimateFee(blocks) {
  return this.network.feeRate;
};

/**
 * Get hash range.
 * @param {Number} start
 * @param {Number} end
 * @returns {Promise}
 */

NullClient.prototype.getHashes = async function getHashes(start = -1, end = -1) {
  return [this.network.genesis.hash];
};

/**
 * Rescan for any missed transactions.
 * @param {Number|Hash} start - Start block.
 * @param {Bloom} filter
 * @param {Function} iter - Iterator.
 * @returns {Promise}
 */

NullClient.prototype.rescan = async function rescan(start) {
  ;
};

/*
 * Expose
 */

module.exports = NullClient;
