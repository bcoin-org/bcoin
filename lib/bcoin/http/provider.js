/**
 * provider.js - http provider for wallets
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

var EventEmitter = require('events').EventEmitter;

var utils = require('../utils');
var assert = utils.assert;
var Client = require('./client');

/**
 * Provider
 */

function Provider(url) {
  if (!(this instanceof Provider))
    return new Provider(url);

  EventEmitter.call(this);

  this.client = new Client(url);
  this.url = url;
  this.id = null;
  this._init();
}

utils.inherits(Provider, EventEmitter);

Provider.prototype._init = function _init() {
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

Provider.prototype.setID = function setID(id) {
  assert(!this.id)
  this.id = id;
  this.client.listenWallet(id);
};

Provider.prototype.destroy = function destroy() {
  this.client.destroy();
  this.client = null;
};

Provider.prototype.getAll = function getAll(callback) {
  return this.client.getWalletAll(this.id, callback);
};

Provider.prototype.getCoins = function getCoins(callback) {
  return this.client.getWalletCoins(this.id, callback);
};

Provider.prototype.getPending = function getPending(callback) {
  return this.client.getWalletPending(this.id, callback);
};

Provider.prototype.getBalance = function getBalance(callback) {
  return this.client.getWalletBalance(this.id, callback);
};

Provider.prototype.getLastTime = function getLastTime(callback) {
  assert(false);
};

Provider.prototype.getLast = function getLast(limit, callback) {
  return this.client.getWalletLast(this.id, limit, callback);
};

Provider.prototype.getRange = function getRange(options, callback) {
  return this.client.getWalletRange(this.id, options, callback);
};

Provider.prototype.getTX = function getTX(hash, callback) {
  return this.client.getWalletTX(this.id, hash, callback);
};

Provider.prototype.getCoin = function getCoin(hash, index, callback) {
  return this.client.getWalletCoin(this.id, hash, index, callback);
};

Provider.prototype.fillTX = function fillTX(tx, callback) {
  assert(false);
};

Provider.prototype.fillCoins = function fillCoins(tx, callback) {
  assert(false);
};

Provider.prototype.sync = function sync(wallet, address) {
  var self = this;
  return this.client.syncWallet(this.id, wallet, function(err) {
    if (err)
      self.emit('error', err);
  });
};

/**
 * Expose
 */

module.exports = Provider;
