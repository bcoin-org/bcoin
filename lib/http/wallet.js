/*!
 * wallet.js - http wallet for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const EventEmitter = require('events');
const Network = require('../protocol/network');
const util = require('../utils/util');
const Client = require('./client');

/**
 * HTTPWallet
 * @alias module:http.Wallet
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

  if (options.id)
    this.id = options.id;

  if (options.token) {
    this.token = options.token;
    if (Buffer.isBuffer(this.token))
      this.token = this.token.toString('hex');
    this.client.token = this.token;
  }

  this._init();
}

util.inherits(HTTPWallet, EventEmitter);

/**
 * Initialize the wallet.
 * @private
 */

HTTPWallet.prototype._init = function _init() {
  this.client.on('tx', (details) => {
    this.emit('tx', details);
  });

  this.client.on('confirmed', (details) => {
    this.emit('confirmed', details);
  });

  this.client.on('unconfirmed', (tx, details) => {
    this.emit('unconfirmed', details);
  });

  this.client.on('conflict', (tx, details) => {
    this.emit('conflict', details);
  });

  this.client.on('balance', (balance) => {
    this.emit('balance', balance);
  });

  this.client.on('address', (receive) => {
    this.emit('address', receive);
  });

  this.client.on('error', (err) => {
    this.emit('error', err);
  });
};

/**
 * Open the client and get a wallet.
 * @alias HTTPWallet#open
 * @returns {Promise}
 */

HTTPWallet.prototype.open = async function open(options) {
  if (options) {
    if (options.id)
      this.id = options.id;

    if (options.token) {
      this.token = options.token;
      if (Buffer.isBuffer(this.token))
        this.token = this.token.toString('hex');
      this.client.token = this.token;
    }
  }

  assert(this.id, 'No ID provided.');

  await this.client.open();
  await this.client.sendWalletAuth();
  await this.client.join(this.id, this.token);
};

/**
 * Open the client and create a wallet.
 * @alias HTTPWallet#open
 * @returns {Promise}
 */

HTTPWallet.prototype.create = async function create(options) {
  let wallet;

  await this.client.open();
  await this.client.sendWalletAuth();

  wallet = await this.client.createWallet(options);

  this.id = wallet.id;
  this.token = wallet.token;
  this.client.token = this.token;

  await this.client.join(this.id, this.token);

  return wallet;
};

/**
 * Close the client, wait for the socket to close.
 * @alias HTTPWallet#close
 * @returns {Promise}
 */

HTTPWallet.prototype.close = function close() {
  return this.client.close();
};

/**
 * Wait for websocket disconnection.
 * @private
 * @returns {Promise}
 */

HTTPWallet.prototype.onDisconnect = function onDisconnect() {
  return this.client.onDisconnect();
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
 * @see Wallet#getPending
 */

HTTPWallet.prototype.getPending = function getPending(account) {
  return this.client.getPending(this.id, account);
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

HTTPWallet.prototype.getTX = function getTX(hash) {
  return this.client.getWalletTX(this.id, hash);
};

/**
 * @see Wallet#getBlocks
 */

HTTPWallet.prototype.getBlocks = function getBlocks() {
  return this.client.getWalletBlocks(this.id);
};

/**
 * @see Wallet#getBlock
 */

HTTPWallet.prototype.getBlock = function getBlock(height) {
  return this.client.getWalletBlock(this.id, height);
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
  return this.client.zapWallet(this.id, account, age);
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
 * @see HTTPClient#getWallet
 */

HTTPWallet.prototype.getInfo = function getInfo() {
  return this.client.getWallet(this.id);
};

/**
 * @see Wallet#getAccounts
 */

HTTPWallet.prototype.getAccounts = function getAccounts() {
  return this.client.getAccounts(this.id);
};

/**
 * @see Wallet#master
 */

HTTPWallet.prototype.getMaster = function getMaster() {
  return this.client.getMaster(this.id);
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

HTTPWallet.prototype.createAccount = function createAccount(name, options) {
  return this.client.createAccount(this.id, name, options);
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

HTTPWallet.prototype.createChange = function createChange(account) {
  return this.client.createChange(this.id, account);
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

HTTPWallet.prototype.retoken = async function retoken(passphrase) {
  let token = await this.client.retoken(this.id, passphrase);

  this.token = token;
  this.client.token = token;

  return token;
};

/**
 * Import private key.
 * @param {Number|String} account
 * @param {String} key
 * @returns {Promise}
 */

HTTPWallet.prototype.importPrivate = function importPrivate(account, key) {
  return this.client.importPrivate(this.id, account, key);
};

/**
 * Import public key.
 * @param {Number|String} account
 * @param {String} key
 * @returns {Promise}
 */

HTTPWallet.prototype.importPublic = function importPublic(account, key) {
  return this.client.importPublic(this.id, account, key);
};

/**
 * Import address.
 * @param {Number|String} account
 * @param {String} address
 * @returns {Promise}
 */

HTTPWallet.prototype.importAddress = function importAddress(account, address) {
  return this.client.importAddress(this.id, account, address);
};

/**
 * Lock a coin.
 * @param {String} hash
 * @param {Number} index
 * @returns {Promise}
 */

HTTPWallet.prototype.lockCoin = function lockCoin(hash, index) {
  return this.client.lockCoin(this.id, hash, index);
};

/**
 * Unlock a coin.
 * @param {String} hash
 * @param {Number} index
 * @returns {Promise}
 */

HTTPWallet.prototype.unlockCoin = function unlockCoin(hash, index) {
  return this.client.unlockCoin(this.id, hash, index);
};

/**
 * Get locked coins.
 * @returns {Promise}
 */

HTTPWallet.prototype.getLocked = function getLocked() {
  return this.client.getLocked(this.id);
};

/**
 * Lock wallet.
 * @returns {Promise}
 */

HTTPWallet.prototype.lock = function lock() {
  return this.client.lock(this.id);
};

/**
 * Unlock wallet.
 * @param {String} passphrase
 * @param {Number} timeout
 * @returns {Promise}
 */

HTTPWallet.prototype.unlock = function unlock(passphrase, timeout) {
  return this.client.unlock(this.id, passphrase, timeout);
};

/**
 * Get wallet key.
 * @param {String} address
 * @returns {Promise}
 */

HTTPWallet.prototype.getKey = function getKey(address) {
  return this.client.getKey(this.id, address);
};

/**
 * Get wallet key WIF dump.
 * @param {String} address
 * @param {String?} passphrase
 * @returns {Promise}
 */

HTTPWallet.prototype.getWIF = function getWIF(address, passphrase) {
  return this.client.getWIF(this.id, address, passphrase);
};

/**
 * Add a public account/purpose key to the wallet for multisig.
 * @param {(String|Number)?} account
 * @param {Base58String} key - Account (bip44) or
 * Purpose (bip45) key (can be in base58 form).
 * @returns {Promise}
 */

HTTPWallet.prototype.addSharedKey = function addSharedKey(account, key) {
  return this.client.addSharedKey(this.id, account, key);
};

/**
 * Remove a public account/purpose key to the wallet for multisig.
 * @param {(String|Number)?} account
 * @param {Base58String} key - Account (bip44) or Purpose
 * (bip45) key (can be in base58 form).
 * @returns {Promise}
 */

HTTPWallet.prototype.removeSharedKey = function removeSharedKey(account, key) {
  return this.client.removeSharedKey(this.id, account, key);
};

/**
 * Resend wallet transactions.
 * @returns {Promise}
 */

HTTPWallet.prototype.resend = function resend() {
  return this.client.resendWallet(this.id);
};

/*
 * Expose
 */

module.exports = HTTPWallet;
