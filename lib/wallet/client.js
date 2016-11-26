/*!
 * client.js - http client for wallets
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var Network = require('../protocol/network');
var AsyncObject = require('../utils/async');
var TX = require('../primitives/tx');
var BlockMeta = require('./records').BlockMeta;
var Headers = require('../primitives/headers');
var Amount = require('../btc/amount');
var util = require('../utils/util');
var BufferReader = require('../utils/reader');
var co = require('../utils/co');
var IOClient = require('socket.io-client');

/**
 * BCoin HTTP client.
 * @exports WalletClient
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
    var data;

    try {
      data = parseBlock(entry, txs);
    } catch (e) {
      self.emit('error', e);
      return;
    }

    self.emit('block connect', data.entry, data.txs);
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
    var data;

    try {
      data = parseBlock(entry, txs);
    } catch (e) {
      self.emit('error', e);
      return cb();
    }

    self.emit('block rescan', data.entry, data.txs, cb);
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
    tx = parseTX(tx);
    self.emit('tx', tx);
  });

  yield this.onConnect();
  yield this.sendAuth();
  yield this.sendOptions({ raw: true });
  yield this.watchChain();
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
    self.socket.emit('auth', self.apiKey, function(err) {
      if (err)
        return reject(new Error(err.error));
      resolve();
    });
  });
};

/**
 * Wait for websocket options.
 * @private
 * @returns {Promise}
 */

WalletClient.prototype.sendOptions = function sendOptions(options) {
  var self = this;
  return new Promise(function(resolve, reject) {
    self.socket.emit('options', options, function(err) {
      if (err)
        return reject(new Error(err.error));
      resolve();
    });
  });
};

/**
 * Wait for websocket options.
 * @private
 * @returns {Promise}
 */

WalletClient.prototype.watchChain = function watchChain() {
  var self = this;
  return new Promise(function(resolve, reject) {
    self.socket.emit('watch chain', function(err) {
      if (err)
        return reject(new Error(err.error));
      resolve();
    });
  });
};

/**
 * Get chain tip.
 * @returns {Promise}
 */

WalletClient.prototype.getTip = function getTip() {
  var self = this;
  return new Promise(function(resolve, reject) {
    self.socket.emit('get tip', function(err, tip) {
      if (err)
        return reject(new Error(err.error));
      resolve(parseEntry(tip));
    });
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

    self.socket.emit('get entry', block, function(err, entry) {
      if (err)
        return reject(new Error(err.error));

      if (!entry)
        return resolve(null);

      resolve(parseEntry(entry));
    });
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
    self.socket.emit('send', raw, function(err) {
      if (err)
        return reject(new Error(err.error));
      resolve();
    });
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
    self.socket.emit('set filter', raw, function(err) {
      if (err)
        return reject(new Error(err.error));
      resolve();
    });
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
    self.socket.emit('add filter', out, function(err) {
      if (err)
        return reject(new Error(err.error));
      resolve();
    });
  });
};

/**
 * Reset filter.
 * @returns {Promise}
 */

WalletClient.prototype.resetFilter = function resetFilter() {
  var self = this;
  return new Promise(function(resolve, reject) {
    self.socket.emit('reset filter', function(err) {
      if (err)
        return reject(new Error(err.error));
      resolve();
    });
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
    self.socket.emit('estimate fee', blocks, function(err, rate) {
      if (err)
        return reject(new Error(err.error));
      resolve(Amount.value(rate));
    });
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

    self.socket.emit('rescan', start, function(err) {
      if (err)
        return reject(new Error(err.error));
      resolve();
    });
  });
};

/*
 * Helpers
 */

function parseEntry(data, enc) {
  var br, block, hash;

  if (typeof data === 'string')
    data = new Buffer(data, 'hex');

  br = new BufferReader(data);

  block = Headers.fromAbbr(br);
  block.height = br.readU32();

  hash = block.hash('hex');

  return new BlockMeta(hash, block.height, block.ts);
}

function parseBlock(entry, txs) {
  var block = parseEntry(entry);
  var out = [];
  var i, tx;

  for (i = 0; i < txs.length; i++) {
    tx = txs[i];
    tx = parseTX(tx);
    tx.block = block.hash;
    tx.height = block.height;
    tx.ts = block.ts;
    tx.index = -1;
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

/*
 * Expose
 */

module.exports = WalletClient;
