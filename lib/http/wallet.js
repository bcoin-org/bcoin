/*!
 * wallet.js - http wallet for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var Network = require('../protocol/network');
var EventEmitter = require('events').EventEmitter;

var utils = require('../utils/utils');
var co = require('../utils/co');
var Client = require('./client');

/**
 * HTTPWallet
 * @exports HTTPWallet
 * @constructor
 * @param {String} uri
 */

function HTTPWallet(options) {
  if (!(this instanceof HTTPWallet))
    return new HTTPWallet(options);

  EventEmitter.call(this);

  if (!options)
    options = {};

  if (typeof options === 'string')
    options = { uri: options };

  this.options = options;
  this.network = Network.get(options.network);

  this.client = new Client(options);
  this.uri = options.uri;
  this.id = null;
  this.token = null;

  this._init();
}

utils.inherits(HTTPWallet, EventEmitter);

/**
 * Initialize the wallet.
 * @private
 */

HTTPWallet.prototype._init = function _init() {
  var self = this;

  this.client.on('tx', function(details) {
    self.emit('tx', details);
  });

  this.client.on('confirmed', function(details) {
    self.emit('confirmed', details);
  });

  this.client.on('unconfirmed', function(tx, details) {
    self.emit('unconfirmed', details);
  });

  this.client.on('conflict', function(tx, details) {
    self.emit('conflict', details);
  });

  this.client.on('balance', function(balance) {
    self.emit('balance', balance);
  });

  this.client.on('address', function(receive) {
    self.emit('address', receive);
  });

  this.client.on('error', function(err) {
    self.emit('error', err);
  });
};

/**
 * Open the client and get a wallet.
 * @alias HTTPWallet#open
 * @returns {Promise}
 */

HTTPWallet.prototype.open = co(function* open(options) {
  var wallet;

  this.id = options.id;

  if (options.token) {
    this.token = options.token;
    if (Buffer.isBuffer(this.token))
      this.token = this.token.toString('hex');
    this.client.token = this.token;
  }

  yield this.client.open();

  wallet = yield this.client.getWallet(this.id);

  yield this.client.join(this.id, wallet.token);

  return wallet;
});

/**
 * Open the client and create a wallet.
 * @alias HTTPWallet#open
 * @returns {Promise}
 */

HTTPWallet.prototype.create = co(function* create(options) {
  var wallet;
  yield this.client.open();
  wallet = yield this.client.createWallet(options);
  return yield this.open({
    id: wallet.id,
    token: wallet.token
  });
});

/**
 * Close the client, wait for the socket to close.
 * @alias HTTPWallet#close
 * @returns {Promise}
 */

HTTPWallet.prototype.close = function close() {
  return this.client.close();
};

/**
 * @see Wallet#getHistory
 */

HTTPWallet.prototype.getHistory = function getHistory(account) {
  return this.client.getHistory(this.id, account);
};

/**
 * @see Wallet#getCoins
 */

HTTPWallet.prototype.getCoins = function getCoins(account) {
  return this.client.getCoins(this.id, account);
};

/**
 * @see Wallet#getUnconfirmed
 */

HTTPWallet.prototype.getUnconfirmed = function getUnconfirmed(account) {
  return this.client.getUnconfirmed(this.id, account);
};

/**
 * @see Wallet#getBalance
 */

HTTPWallet.prototype.getBalance = function getBalance(account) {
  return this.client.getBalance(this.id, account);
};

/**
 * @see Wallet#getLast
 */

HTTPWallet.prototype.getLast = function getLast(account, limit) {
  return this.client.getLast(this.id, account, limit);
};

/**
 * @see Wallet#getRange
 */

HTTPWallet.prototype.getRange = function getRange(account, options) {
  return this.client.getRange(this.id, account, options);
};

/**
 * @see Wallet#getTX
 */

HTTPWallet.prototype.getTX = function getTX(account, hash) {
  return this.client.getWalletTX(this.id, account, hash);
};

/**
 * @see Wallet#getCoin
 */

HTTPWallet.prototype.getCoin = function getCoin(account, hash, index) {
  return this.client.getWalletCoin(this.id, account, hash, index);
};

/**
 * @see Wallet#zap
 */

HTTPWallet.prototype.zap = function zap(account, age) {
  return this.client.zap(this.id, account, age);
};

/**
 * @see Wallet#createTX
 */

HTTPWallet.prototype.createTX = function createTX(options, outputs) {
  return this.client.createTX(this.id, options, outputs);
};

/**
 * @see HTTPClient#walletSend
 */

HTTPWallet.prototype.send = function send(options) {
  return this.client.send(this.id, options);
};

/**
 * @see Wallet#sign
 */

HTTPWallet.prototype.sign = function sign(tx, options) {
  return this.client.sign(this.id, tx, options);
};

/**
 * @see Wallet#fillCoins
 */

HTTPWallet.prototype.fillCoins = function fillCoins(tx) {
  return this.client.fillCoins(tx);
};

/**
 * @see HTTPClient#getWallet
 */

HTTPWallet.prototype.getInfo = function getInfo(callback) {
  return this.client.getWallet(this.id);
};

/**
 * @see Wallet#getAccounts
 */

HTTPWallet.prototype.getAccounts = function getAccounts(callback) {
  return this.client.getAccounts(this.id);
};

/**
 * @see Wallet#getAccount
 */

HTTPWallet.prototype.getAccount = function getAccount(account) {
  return this.client.getAccount(this.id, account);
};

/**
 * @see Wallet#createAccount
 */

HTTPWallet.prototype.createAccount = function createAccount(options) {
  return this.client.createAccount(this.id, options);
};

/**
 * @see Wallet#createAddress
 */

HTTPWallet.prototype.createAddress = function createAddress(account) {
  return this.client.createAddress(this.id, account);
};

/**
 * @see Wallet#createAddress
 */

HTTPWallet.prototype.createNested = function createNested(account) {
  return this.client.createNested(this.id, account);
};

/**
 * @see Wallet#setPassphrase
 */

HTTPWallet.prototype.setPassphrase = function setPassphrase(old, new_) {
  return this.client.setPassphrase(this.id, old, new_);
};

/**
 * @see Wallet#retoken
 */

HTTPWallet.prototype.retoken = co(function* retoken(passphrase) {
  var token = yield this.client.retoken(this.id, passphrase);

  this.token = token;
  this.client.token = token;

  return token;
});

/**
 * Import private key.
 * @param {Number|String} account
 * @param {String} key
 * @returns {Promise}
 */

HTTPWallet.prototype.importPrivate = function importPrivate(id, account, key) {
  return this.client.importPrivate(this.id, account, key);
};

/**
 * Import public key.
 * @param {Number|String} account
 * @param {String} key
 * @returns {Promise}
 */

HTTPWallet.prototype.importPublic = function importPublic(id, account, key) {
  return this.client.importPublic(this.id, account, key);
};

/**
 * Import address.
 * @param {Number|String} account
 * @param {String} address
 * @returns {Promise}
 */

HTTPWallet.prototype.importAddress = function importAddress(id, account, address) {
  return this.client.importAddress(this.id, account, address);
};

/**
 * Lock a coin.
 * @param {String} hash
 * @param {Number} index
 * @returns {Promise}
 */

HTTPWallet.prototype.lockCoin = function lockCoin(id, hash, index) {
  return this.client.lockCoin(this.id, hash, index);
};

/**
 * Unlock a coin.
 * @param {String} hash
 * @param {Number} index
 * @returns {Promise}
 */

HTTPWallet.prototype.unlockCoin = function unlockCoin(id, hash, index) {
  return this.client.unlockCoin(this.id, hash, index);
};

/**
 * Get locked coins.
 * @returns {Promise}
 */

HTTPWallet.prototype.getLocked = function getLocked(id) {
  return this.client.getLocked(this.id);
};

/**
 * Lock wallet.
 * @returns {Promise}
 */

HTTPWallet.prototype.lock = function lock(id) {
  return this.client.lock(this.id);
};

/**
 * Unlock wallet.
 * @param {String} passphrase
 * @param {Number} timeout
 * @returns {Promise}
 */

HTTPWallet.prototype.unlock = function unlock(id, passphrase, timeout) {
  return this.client.unlock(this.id, passphrase, timeout);
};

/*
 * Expose
 */

module.exports = HTTPWallet;
