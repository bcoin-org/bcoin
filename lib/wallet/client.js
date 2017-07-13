/*!
 * client.js - http client for wallets
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const IOClient = require('socket.io-client');
const Network = require('../protocol/network');
const AsyncObject = require('../utils/asyncobject');
const TX = require('../primitives/tx');
const {BlockMeta} = require('./records');
const Headers = require('../primitives/headers');
const util = require('../utils/util');
const BufferReader = require('../utils/reader');

/**
 * Bcoin HTTP client.
 * @alias module:wallet.WalletClient
 * @constructor
 * @param {Object|String} options
 */

function WalletClient(options) {
  if (!(this instanceof WalletClient))
    return new WalletClient(options);

  if (!options)
    options = {};

  if (typeof options === 'string')
    options = { uri: options };

  AsyncObject.call(this);

  this.options = options;
  this.network = Network.get(options.network);

  this.uri = options.uri || `http://localhost:${this.network.rpcPort}`;
  this.apiKey = options.apiKey;

  this.socket = null;
}

util.inherits(WalletClient, AsyncObject);

/**
 * Open the client, wait for socket to connect.
 * @alias WalletClient#open
 * @returns {Promise}
 */

WalletClient.prototype._open = async function _open() {
  this.socket = new IOClient(this.uri, {
    transports: ['websocket'],
    forceNew: true
  });

  this.socket.on('error', (err) => {
    this.emit('error', err);
  });

  this.socket.on('version', (info) => {
    if (info.network !== this.network.type)
      this.emit('error', new Error('Wrong network.'));
  });

  this.socket.on('block connect', (entry, txs) => {
    let block;

    try {
      block = parseBlock(entry, txs);
    } catch (e) {
      this.emit('error', e);
      return;
    }

    this.emit('block connect', block.entry, block.txs);
  });

  this.socket.on('block disconnect', (entry) => {
    let block;

    try {
      block = parseEntry(entry);
    } catch (e) {
      this.emit('error', e);
      return;
    }

    this.emit('block disconnect', block);
  });

  this.socket.on('block rescan', (entry, txs, cb) => {
    let block;

    try {
      block = parseBlock(entry, txs);
    } catch (e) {
      this.emit('error', e);
      return cb();
    }

    this.fire('block rescan', block.entry, block.txs).then(cb, cb);
  });

  this.socket.on('chain reset', (tip) => {
    let block;

    try {
      block = parseEntry(tip);
    } catch (e) {
      this.emit('error', e);
      return;
    }

    this.emit('chain reset', block);
  });

  this.socket.on('tx', (tx) => {
    try {
      tx = parseTX(tx);
    } catch (e) {
      this.emit('error', e);
      return;
    }
    this.emit('tx', tx);
  });

  await this.onConnect();
  await this.sendAuth();
  await this.watchChain();
  await this.watchMempool();
};

/**
 * Close the client, wait for the socket to close.
 * @alias WalletClient#close
 * @returns {Promise}
 */

WalletClient.prototype._close = function close() {
  if (!this.socket)
    return Promise.resolve();

  this.socket.disconnect();
  this.socket = null;

  return Promise.resolve();
};

/**
 * Wait for websocket connection.
 * @private
 * @returns {Promise}
 */

WalletClient.prototype.onConnect = function onConnect() {
  return new Promise((resolve, reject) => {
    this.socket.once('connect', resolve);
  });
};

/**
 * Wait for websocket auth.
 * @private
 * @returns {Promise}
 */

WalletClient.prototype.sendAuth = function sendAuth() {
  return new Promise((resolve, reject) => {
    this.socket.emit('auth', this.apiKey, wrap(resolve, reject));
  });
};

/**
 * Watch the blockchain.
 * @private
 * @returns {Promise}
 */

WalletClient.prototype.watchChain = function watchChain() {
  return new Promise((resolve, reject) => {
    this.socket.emit('watch chain', wrap(resolve, reject));
  });
};

/**
 * Watch the blockchain.
 * @private
 * @returns {Promise}
 */

WalletClient.prototype.watchMempool = function watchMempool() {
  return new Promise((resolve, reject) => {
    this.socket.emit('watch mempool', wrap(resolve, reject));
  });
};

/**
 * Get chain tip.
 * @returns {Promise}
 */

WalletClient.prototype.getTip = function getTip() {
  return new Promise((resolve, reject) => {
    this.socket.emit('get tip', wrap(resolve, reject, parseEntry));
  });
};

/**
 * Get chain entry.
 * @param {Hash} hash
 * @returns {Promise}
 */

WalletClient.prototype.getEntry = function getEntry(block) {
  return new Promise((resolve, reject) => {
    if (typeof block === 'string')
      block = util.revHex(block);

    this.socket.emit('get entry', block, wrap(resolve, reject, parseEntry));
  });
};

/**
 * Send a transaction. Do not wait for promise.
 * @param {TX} tx
 * @returns {Promise}
 */

WalletClient.prototype.send = function send(tx) {
  return new Promise((resolve, reject) => {
    this.socket.emit('send', tx.toRaw(), wrap(resolve, reject));
  });
};

/**
 * Set bloom filter.
 * @param {Bloom} filter
 * @returns {Promise}
 */

WalletClient.prototype.setFilter = function setFilter(filter) {
  return new Promise((resolve, reject) => {
    this.socket.emit('set filter', filter.toRaw(), wrap(resolve, reject));
  });
};

/**
 * Add data to filter.
 * @param {Buffer} data
 * @returns {Promise}
 */

WalletClient.prototype.addFilter = function addFilter(chunks) {
  if (!Array.isArray(chunks))
    chunks = [chunks];

  return new Promise((resolve, reject) => {
    this.socket.emit('add filter', chunks, wrap(resolve, reject));
  });
};

/**
 * Reset filter.
 * @returns {Promise}
 */

WalletClient.prototype.resetFilter = function resetFilter() {
  return new Promise((resolve, reject) => {
    this.socket.emit('reset filter', wrap(resolve, reject));
  });
};

/**
 * Esimate smart fee.
 * @param {Number?} blocks
 * @returns {Promise}
 */

WalletClient.prototype.estimateFee = function estimateFee(blocks) {
  return new Promise((resolve, reject) => {
    this.socket.emit('estimate fee', blocks, wrap(resolve, reject));
  });
};

/**
 * Rescan for any missed transactions.
 * @param {Number|Hash} start - Start block.
 * @param {Bloom} filter
 * @param {Function} iter - Iterator.
 * @returns {Promise}
 */

WalletClient.prototype.rescan = function rescan(start) {
  return new Promise((resolve, reject) => {
    if (typeof start === 'string')
      start = util.revHex(start);

    this.socket.emit('rescan', start, wrap(resolve, reject));
  });
};

/*
 * Helpers
 */

function parseEntry(data, enc) {
  let br, block, hash, height;

  if (typeof data === 'string')
    data = Buffer.from(data, 'hex');

  block = Headers.fromAbbr(data);

  br = new BufferReader(data);
  br.seek(80);
  height = br.readU32();
  hash = block.hash('hex');

  return new BlockMeta(hash, height, block.ts);
}

function parseBlock(entry, txs) {
  let block = parseEntry(entry);
  let out = [];

  for (let tx of txs) {
    tx = parseTX(tx);
    out.push(tx);
  }

  return new BlockResult(block, out);
}

function parseTX(data) {
  return TX.fromRaw(data, 'hex');
}

function BlockResult(entry, txs) {
  this.entry = entry;
  this.txs = txs;
}

function wrap(resolve, reject, parse) {
  return function(err, result) {
    if (err) {
      reject(new Error(err.message));
      return;
    }

    if (!result) {
      resolve(null);
      return;
    }

    if (!parse) {
      resolve(result);
      return;
    }

    try {
      result = parse(result);
    } catch (e) {
      reject(e);
      return;
    }

    resolve(result);
  };
}

/*
 * Expose
 */

module.exports = WalletClient;
