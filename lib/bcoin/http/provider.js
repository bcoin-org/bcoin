/*!
 * provider.js - http provider for wallets
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/indutny/bcoin
 */

module.exports = function(bcoin) {

var EventEmitter = require('events').EventEmitter;

var utils = require('../utils');
var assert = utils.assert;
var HTTPClient = bcoin.http.client;

/**
 * HTTPProvider
 * @exports HTTPProvider
 * @constructor
 * @param {String} uri
 */

function HTTPProvider(uri) {
  if (!(this instanceof HTTPProvider))
    return new HTTPProvider(uri);

  EventEmitter.call(this);

  this.client = new HTTPClient(uri);
  this.uri = uri;
  this.id = null;
  this._init();
}

utils.inherits(HTTPProvider, EventEmitter);

HTTPProvider.prototype._init = function _init() {
  var self = this;

  this.client.on('tx', function(tx) {
    self.emit('tx', tx);
  });

  this.client.on('confirmed', function(tx) {
    self.emit('confirmed', tx);
  });

  this.client.on('updated', function(tx) {
    self.emit('updated', tx);
  });

  this.client.on('balance', function(balance) {
    self.emit('balance', balance);
  });

  this.client.on('error', function(err) {
    self.emit('error', err);
  });
};

/**
 * @see HTTPProvider#setID
 */

HTTPProvider.prototype.setID = function setID(id) {
  assert(!this.id, 'ID has already been set.');
  this.id = id;
  this.client.listenWallet(id);
};

/**
 * @see HTTPProvider#open
 */

HTTPProvider.prototype.open = function open(callback) {
  this.client.open(callback);
};

/**
 * @see HTTPProvider#close
 */

HTTPProvider.prototype.close =
HTTPProvider.prototype.destroy = function destroy(callback) {
  callback = utils.ensure(callback);

  if (!this.client)
    return utils.nextTick(callback);

  this.client.destroy(callback);
  this.client = null;
};

/**
 * @see HTTPProvider#getHistory
 */

HTTPProvider.prototype.getHistory = function getHistory(callback) {
  return this.client.getWalletHistory(this.id, callback);
};

/**
 * @see HTTPProvider#getCoins
 */

HTTPProvider.prototype.getCoins = function getCoins(callback) {
  return this.client.getWalletCoins(this.id, callback);
};

/**
 * @see HTTPProvider#getUnconfirmed
 */

HTTPProvider.prototype.getUnconfirmed = function getUnconfirmed(callback) {
  return this.client.getWalletUnconfirmed(this.id, callback);
};

/**
 * @see HTTPProvider#getBalance
 */

HTTPProvider.prototype.getBalance = function getBalance(callback) {
  return this.client.getWalletBalance(this.id, callback);
};

/**
 * @see HTTPProvider#getLastTime
 */

HTTPProvider.prototype.getLastTime = function getLastTime(callback) {
  assert(false);
};

/**
 * @see HTTPProvider#getLast
 */

HTTPProvider.prototype.getLast = function getLast(limit, callback) {
  return this.client.getWalletLast(this.id, limit, callback);
};

/**
 * @see HTTPProvider#getRange
 */

HTTPProvider.prototype.getRange = function getRange(options, callback) {
  return this.client.getWalletRange(this.id, options, callback);
};

/**
 * @see HTTPProvider#getTX
 */

HTTPProvider.prototype.getTX = function getTX(hash, callback) {
  return this.client.getWalletTX(this.id, hash, callback);
};

/**
 * @see HTTPProvider#getCoin
 */

HTTPProvider.prototype.getCoin = function getCoin(hash, index, callback) {
  return this.client.getWalletCoin(this.id, hash, index, callback);
};

/**
 * @see HTTPProvider#fillHistory
 */

HTTPProvider.prototype.fillHistory = function fillHistory(tx, callback) {
  assert(false);
};

/**
 * @see HTTPProvider#fillCoins
 */

HTTPProvider.prototype.fillCoins = function fillCoins(tx, callback) {
  assert(false);
};

/**
 * Sync wallet address depths with server.
 * @param {Wallet} wallet
 * @param {Address?} address - Newly allocated address if available.
 */

HTTPProvider.prototype.sync = function sync(wallet, address) {
  var self = this;
  return this.client.syncWallet(this.id, wallet, function(err) {
    if (err)
      self.emit('error', err);
  });
};

/**
 * @see HTTPProvider#zap
 */

HTTPProvider.prototype.zap = function zap(now, age, callback) {
  return this.client.zapWallet(this.id, now, age, callback);
};

return HTTPProvider;
};
