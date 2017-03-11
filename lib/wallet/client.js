/*!
 * client.js - http client for wallets
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var Network = require('../protocol/network');
var AsyncObject = require('../utils/asyncobject');
var TX = require('../primitives/tx');
var BlockMeta = require('./records').BlockMeta;
var Headers = require('../primitives/headers');
var Amount = require('../btc/amount');
var util = require('../utils/util');
var BufferReader = require('../utils/reader');
var co = require('../utils/co');
var IOClient = require('socket.io-client');

/**
 * Bcoin HTTP client.
 * @alias module:wallet.WalletClient
 * @constructor
 * @param {String} uri
 * @param {Object?} options
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

  this.uri = options.uri || 'http://localhost:' + this.network.rpcPort;
  this.apiKey = options.apiKey;

  this.socket = null;
}

util.inherits(WalletClient, AsyncObject);

/**
 * Open the client, wait for socket to connect.
 * @alias WalletClient#open
 * @returns {Promise}
 */

WalletClient.prototype._open = co(function* _open() {
  var self = this;

  this.socket = new IOClient(this.uri, {
    transports: ['websocket'],
    forceNew: true
  });

  this.socket.on('error', function(err) {
    self.emit('error', err);
  });

  this.socket.on('version', function(info) {
    if (info.network !== self.network.type)
      self.emit('error', new Error('Wrong network.'));
  });

  this.socket.on('block connect', function(entry, txs) {
    var block;

    try {
      block = parseBlock(entry, txs);
    } catch (e) {
      self.emit('error', e);
      return;
    }

    self.emit('block connect', block.entry, block.txs);
  });

  this.socket.on('block disconnect', function(entry) {
    var block;

    try {
      block = parseEntry(entry);
    } catch (e) {
      self.emit('error', e);
      return;
    }

    self.emit('block disconnect', block);
  });

  this.socket.on('block rescan', function(entry, txs, cb) {
    var block;

    try {
      block = parseBlock(entry, txs);
    } catch (e) {
      self.emit('error', e);
      return cb();
    }

    self.fire('block rescan', block.entry, block.txs).then(cb, cb);
  });

  this.socket.on('chain reset', function(tip) {
    var block;

    try {
      block = parseEntry(tip);
    } catch (e) {
      self.emit('error', e);
      return;
    }

    self.emit('chain reset', block);
  });

  this.socket.on('tx', function(tx) {
    try {
      tx = parseTX(tx);
    } catch (e) {
      self.emit('error', e);
      return;
    }
    self.emit('tx', tx);
  });

  yield this.onConnect();
  yield this.sendAuth();
  yield this.watchChain();
  yield this.watchMempool();
});

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
  var self = this;
  return new Promise(function(resolve, reject) {
    self.socket.once('connect', resolve);
  });
};

/**
 * Wait for websocket auth.
 * @private
 * @returns {Promise}
 */

WalletClient.prototype.sendAuth = function sendAuth() {
  var self = this;
  return new Promise(function(resolve, reject) {
    self.socket.emit('auth', self.apiKey, wrap(resolve, reject));
  });
};

/**
 * Watch the blockchain.
 * @private
 * @returns {Promise}
 */

WalletClient.prototype.watchChain = function watchChain() {
  var self = this;
  return new Promise(function(resolve, reject) {
    self.socket.emit('watch chain', wrap(resolve, reject));
  });
};

/**
 * Watch the blockchain.
 * @private
 * @returns {Promise}
 */

WalletClient.prototype.watchMempool = function watchMempool() {
  var self = this;
  return new Promise(function(resolve, reject) {
    self.socket.emit('watch mempool', wrap(resolve, reject));
  });
};

/**
 * Get chain tip.
 * @returns {Promise}
 */

WalletClient.prototype.getTip = function getTip() {
  var self = this;
  return new Promise(function(resolve, reject) {
    self.socket.emit('get tip', wrap(resolve, reject, parseEntry));
  });
};

/**
 * Get chain entry.
 * @param {Hash} hash
 * @returns {Promise}
 */

WalletClient.prototype.getEntry = function getEntry(block) {
  var self = this;
  return new Promise(function(resolve, reject) {
    if (typeof block === 'string')
      block = util.revHex(block);

    self.socket.emit('get entry', block, wrap(resolve, reject, parseEntry));
  });
};

/**
 * Send a transaction. Do not wait for promise.
 * @param {TX} tx
 * @returns {Promise}
 */

WalletClient.prototype.send = function send(tx) {
  var self = this;
  return new Promise(function(resolve, reject) {
    var raw = tx.toRaw();
    self.socket.emit('send', raw, wrap(resolve, reject));
  });
};

/**
 * Set bloom filter.
 * @param {Bloom} filter
 * @returns {Promise}
 */

WalletClient.prototype.setFilter = function setFilter(filter) {
  var self = this;
  return new Promise(function(resolve, reject) {
    var raw = filter.toRaw();
    self.socket.emit('set filter', raw, wrap(resolve, reject));
  });
};

/**
 * Add data to filter.
 * @param {Buffer} data
 * @returns {Promise}
 */

WalletClient.prototype.addFilter = function addFilter(chunks) {
  var self = this;
  var out = [];
  var i;

  if (!Array.isArray(chunks))
    chunks = [chunks];

  for (i = 0; i < chunks.length; i++)
    out.push(chunks[i]);

  return new Promise(function(resolve, reject) {
    self.socket.emit('add filter', out, wrap(resolve, reject));
  });
};

/**
 * Reset filter.
 * @returns {Promise}
 */

WalletClient.prototype.resetFilter = function resetFilter() {
  var self = this;
  return new Promise(function(resolve, reject) {
    self.socket.emit('reset filter', wrap(resolve, reject));
  });
};

/**
 * Esimate smart fee.
 * @param {Number?} blocks
 * @returns {Promise}
 */

WalletClient.prototype.estimateFee = function estimateFee(blocks) {
  var self = this;
  return new Promise(function(resolve, reject) {
    self.socket.emit('estimate fee', blocks,
      wrap(resolve, reject, Amount.value));
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
  var self = this;
  return new Promise(function(resolve, reject) {
    if (typeof start === 'string')
      start = util.revHex(start);

    self.socket.emit('rescan', start, wrap(resolve, reject));
  });
};

/*
 * Helpers
 */

function parseEntry(data, enc) {
  var br, block, hash, height;

  if (typeof data === 'string')
    data = new Buffer(data, 'hex');

  block = Headers.fromAbbr(data);

  br = new BufferReader(data);
  br.seek(80);
  height = br.readU32();
  hash = block.hash('hex');

  return new BlockMeta(hash, height, block.ts);
}

function parseBlock(entry, txs) {
  var block = parseEntry(entry);
  var out = [];
  var i, tx;

  for (i = 0; i < txs.length; i++) {
    tx = txs[i];
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
