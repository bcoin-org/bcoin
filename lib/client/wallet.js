/*!
 * wallet.js - http wallet client for bcoin
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('bsert');
const EventEmitter = require('events');
const {Client} = require('bcurl');

/**
 * Wallet Client
 * @alias module:client.WalletClient
 * @extends {bcurl.Client}
 */

class WalletClient extends Client {
  /**
   * Create a wallet client.
   * @param {Object?} options
   */

  constructor(options) {
    super(options);
    this.wallets = new Map();
  }

  /**
   * Open the client.
   * @private
   * @returns {Promise}
   */

  init() {
    this.bind('tx', (id, details) => {
      this.dispatch(id, 'tx', details);
    });

    this.bind('confirmed', (id, details) => {
      this.dispatch(id, 'confirmed', details);
    });

    this.bind('unconfirmed', (id, details) => {
      this.dispatch(id, 'unconfirmed', details);
    });

    this.bind('conflict', (id, details) => {
      this.dispatch(id, 'conflict', details);
    });

    this.bind('updated', (id, details) => {
      this.dispatch(id, 'updated', details);
    });

    this.bind('address', (id, receive) => {
      this.dispatch(id, 'address', receive);
    });

    this.bind('balance', (id, balance) => {
      this.dispatch(id, 'balance', balance);
    });
  }

  /**
   * Dispatch event.
   * @param {Number} id
   * @param {String} event
   * @param {...Object} args
   * @private
   */

  dispatch(id, event, ...args) {
    const wallet = this.wallets.get(id);

    if (wallet)
      wallet.emit(event, ...args);
  }

  /**
   * Open the client.
   * @returns {Promise}
   */

  async open() {
    await super.open();
    this.init();
  }

  /**
   * Close the client.
   * @returns {Promise}
   */

  async close() {
    await super.close();
    this.wallets = new Map();
  }

  /**
   * Auth with server.
   * @returns {Promise}
   */

  async auth() {
    await this.call('auth', this.password);
  }

  /**
   * Make an RPC call.
   * @returns {Promise}
   */

  execute(name, params) {
    return super.execute('/', name, params);
  }

  /**
   * Create a wallet object.
   * @param {Number} id
   * @param {String} token
   */

  wallet(id, token) {
    return new Wallet(this, id, token);
  }

  /**
   * Join a wallet.
   * @param {String} token
   */

  all(token) {
    return this.call('join', '*', token);
  }

  /**
   * Leave a wallet.
   */

  none() {
    return this.call('leave', '*');
  }

  /**
   * Join a wallet.
   * @param {Number} id
   * @param {String} token
   */

  join(id, token) {
    return this.call('join', id, token);
  }

  /**
   * Leave a wallet.
   * @param {Number} id
   */

  leave(id) {
    return this.call('leave', id);
  }

  /**
   * Rescan the chain.
   * @param {Number} height
   * @returns {Promise}
   */

  rescan(height) {
    return this.post('/rescan', { height });
  }

  /**
   * Resend pending transactions.
   * @returns {Promise}
   */

  resend() {
    return this.post('/resend');
  }

  /**
   * Backup the walletdb.
   * @param {String} path
   * @returns {Promise}
   */

  backup(path) {
    return this.post('/backup', { path });
  }

  /**
   * Get list of all wallet IDs.
   * @returns {Promise}
   */

  getWallets() {
    return this.get('/wallet');
  }

  /**
   * Create a wallet.
   * @param {Number} id
   * @param {Object} options
   * @returns {Promise}
   */

  createWallet(id, options) {
    return this.put(`/wallet/${id}`, options);
  }

  /**
   * Get wallet transaction history.
   * @param {Number} id
   * @param {String} account
   * @returns {Promise}
   */

  getHistory(id, account) {
    return this.get(`/wallet/${id}/tx/history`, { account });
  }

  /**
   * Get wallet coins.
   * @param {Number} id
   * @param {String} account
   * @returns {Promise}
   */

  getCoins(id, account) {
    return this.get(`/wallet/${id}/coin`, { account });
  }

  /**
   * Get all unconfirmed transactions.
   * @param {Number} id
   * @param {String} account
   * @returns {Promise}
   */

  getPending(id, account) {
    return this.get(`/wallet/${id}/tx/unconfirmed`, { account });
  }

  /**
   * Calculate wallet balance.
   * @param {Number} id
   * @param {String} account
   * @returns {Promise}
   */

  getBalance(id, account) {
    return this.get(`/wallet/${id}/balance`, { account });
  }

  /**
   * Get last N wallet transactions.
   * @param {Number} id
   * @param {String} account
   * @param {Number} limit - Max number of transactions.
   * @returns {Promise}
   */

  getLast(id, account, limit) {
    return this.get(`/wallet/${id}/tx/last`, { account, limit });
  }

  /**
   * Get wallet transactions by timestamp range.
   * @param {Number} id
   * @param {String} account
   * @param {Object} options
   * @param {Number} options.start - Start time.
   * @param {Number} options.end - End time.
   * @param {Number?} options.limit - Max number of records.
   * @param {Boolean?} options.reverse - Reverse order.
   * @returns {Promise}
   */

  getRange(id, account, options) {
    return this.get(`/wallet/${id}/tx/range`, {
      account: account,
      start: options.start,
      end: options.end,
      limit: options.limit,
      reverse: options.reverse
    });
  }

  /**
   * Get transaction (only possible if the transaction
   * is available in the wallet history).
   * @param {Number} id
   * @param {Hash} hash
   * @returns {Promise}
   */

  getTX(id, hash) {
    return this.get(`/wallet/${id}/tx/${hash}`);
  }

  /**
   * Get wallet blocks.
   * @param {Number} id
   * @returns {Promise}
   */

  getBlocks(id) {
    return this.get(`/wallet/${id}/block`);
  }

  /**
   * Get wallet block.
   * @param {Number} id
   * @param {Number} height
   * @returns {Promise}
   */

  getBlock(id, height) {
    return this.get(`/wallet/${id}/block/${height}`);
  }

  /**
   * Get unspent coin (only possible if the transaction
   * is available in the wallet history).
   * @param {Number} id
   * @param {Hash} hash
   * @param {Number} index
   * @returns {Promise}
   */

  getCoin(id, hash, index) {
    return this.get(`/wallet/${id}/coin/${hash}/${index}`);
  }

  /**
   * @param {Number} id
   * @param {String} account
   * @param {Number} age - Age delta.
   * @returns {Promise}
   */

  zap(id, account, age) {
    return this.post(`/wallet/${id}/zap`, { account, age });
  }

  /**
   * @param {Number} id
   * @param {Hash} hash
   * @returns {Promise}
   */

  abandon(id, hash) {
    return this.del(`/wallet/${id}/tx/${hash}`);
  }

  /**
   * Create a transaction, fill.
   * @param {Number} id
   * @param {Object} options
   * @returns {Promise}
   */

  createTX(id, options) {
    return this.post(`/wallet/${id}/create`, options);
  }

  /**
   * Create a transaction, fill, sign, and broadcast.
   * @param {Number} id
   * @param {Object} options
   * @param {String} options.address
   * @param {Amount} options.value
   * @returns {Promise}
   */

  send(id, options) {
    return this.post(`/wallet/${id}/send`, options);
  }

  /**
   * Sign a transaction.
   * @param {Number} id
   * @param {Object} options
   * @returns {Promise}
   */

  sign(id, options) {
    return this.post(`/wallet/${id}/sign`, options);
  }

  /**
   * Get the raw wallet JSON.
   * @param {Number} id
   * @returns {Promise}
   */

  getInfo(id) {
    return this.get(`/wallet/${id}`);
  }

  /**
   * Get wallet accounts.
   * @param {Number} id
   * @returns {Promise} - Returns Array.
   */

  getAccounts(id) {
    return this.get(`/wallet/${id}/account`);
  }

  /**
   * Get wallet master key.
   * @param {Number} id
   * @returns {Promise}
   */

  getMaster(id) {
    return this.get(`/wallet/${id}/master`);
  }

  /**
   * Get wallet account.
   * @param {Number} id
   * @param {String} account
   * @returns {Promise}
   */

  getAccount(id, account) {
    return this.get(`/wallet/${id}/account/${account}`);
  }

  /**
   * Create account.
   * @param {Number} id
   * @param {String} name
   * @param {Object} options
   * @returns {Promise}
   */

  createAccount(id, name, options) {
    return this.put(`/wallet/${id}/account/${name}`, options);
  }

  /**
   * Create address.
   * @param {Number} id
   * @param {String} account
   * @returns {Promise}
   */

  createAddress(id, account) {
    return this.post(`/wallet/${id}/address`, { account });
  }

  /**
   * Create change address.
   * @param {Number} id
   * @param {String} account
   * @returns {Promise}
   */

  createChange(id, account) {
    return this.post(`/wallet/${id}/change`, { account });
  }

  /**
   * Create nested address.
   * @param {Number} id
   * @param {String} account
   * @returns {Promise}
   */

  createNested(id, account) {
    return this.post(`/wallet/${id}/nested`, { account });
  }

  /**
   * Change or set master key`s passphrase.
   * @param {Number} id
   * @param {String|Buffer} passphrase
   * @param {(String|Buffer)?} old
   * @returns {Promise}
   */

  setPassphrase(id, passphrase, old) {
    return this.post(`/wallet/${id}/passphrase`, { passphrase, old });
  }

  /**
   * Generate a new token.
   * @param {Number} id
   * @param {(String|Buffer)?} passphrase
   * @returns {Promise}
   */

  retoken(id, passphrase) {
    return this.post(`/wallet/${id}/retoken`, {
      passphrase
    });
  }

  /**
   * Import private key.
   * @param {Number} id
   * @param {String} account
   * @param {String} privateKey
   * @param {String} passphrase
   * @returns {Promise}
   */

  importPrivate(id, account, privateKey, passphrase) {
    return this.post(`/wallet/${id}/import`, {
      account,
      privateKey,
      passphrase
    });
  }

  /**
   * Import public key.
   * @param {Number} id
   * @param {Number|String} account
   * @param {String} publicKey
   * @returns {Promise}
   */

  importPublic(id, account, publicKey) {
    return this.post(`/wallet/${id}/import`, {
      account,
      publicKey
    });
  }

  /**
   * Import address.
   * @param {Number} id
   * @param {String} account
   * @param {String} address
   * @returns {Promise}
   */

  importAddress(id, account, address) {
    return this.post(`/wallet/${id}/import`, { account, address });
  }

  /**
   * Lock a coin.
   * @param {Number} id
   * @param {String} hash
   * @param {Number} index
   * @returns {Promise}
   */

  lockCoin(id, hash, index) {
    return this.put(`/wallet/${id}/locked/${hash}/${index}`);
  }

  /**
   * Unlock a coin.
   * @param {Number} id
   * @param {String} hash
   * @param {Number} index
   * @returns {Promise}
   */

  unlockCoin(id, hash, index) {
    return this.del(`/wallet/${id}/locked/${hash}/${index}`);
  }

  /**
   * Get locked coins.
   * @param {Number} id
   * @returns {Promise}
   */

  getLocked(id) {
    return this.get(`/wallet/${id}/locked`);
  }

  /**
   * Lock wallet.
   * @param {Number} id
   * @returns {Promise}
   */

  lock(id) {
    return this.post(`/wallet/${id}/lock`);
  }

  /**
   * Unlock wallet.
   * @param {Number} id
   * @param {String} passphrase
   * @param {Number} timeout
   * @returns {Promise}
   */

  unlock(id, passphrase, timeout) {
    return this.post(`/wallet/${id}/unlock`, { passphrase, timeout });
  }

  /**
   * Get wallet key.
   * @param {Number} id
   * @param {String} address
   * @returns {Promise}
   */

  getKey(id, address) {
    return this.get(`/wallet/${id}/key/${address}`);
  }

  /**
   * Get wallet key WIF dump.
   * @param {Number} id
   * @param {String} address
   * @param {String?} passphrase
   * @returns {Promise}
   */

  getWIF(id, address, passphrase) {
    return this.get(`/wallet/${id}/wif/${address}`, { passphrase });
  }

  /**
   * Add a public account key to the wallet for multisig.
   * @param {Number} id
   * @param {String} account
   * @param {String} accountKey - Account (bip44) key (base58).
   * @returns {Promise}
   */

  addSharedKey(id, account, accountKey) {
    return this.put(`/wallet/${id}/shared-key`, { account, accountKey });
  }

  /**
   * Remove a public account key to the wallet for multisig.
   * @param {Number} id
   * @param {String} account
   * @param {String} accountKey - Account (bip44) key (base58).
   * @returns {Promise}
   */

  removeSharedKey(id, account, accountKey) {
    return this.del(`/wallet/${id}/shared-key`, { account, accountKey });
  }

  /**
   * Resend wallet transactions.
   * @param {Number} id
   * @returns {Promise}
   */

  resendWallet(id) {
    return this.post(`/wallet/${id}/resend`);
  }
}

/**
 * Wallet Instance
 * @extends {EventEmitter}
 */

class Wallet extends EventEmitter {
  /**
   * Create a wallet client.
   * @param {Wallet} parent
   * @param {Number} id
   * @param {String} token
   */

  constructor(parent, id, token) {
    super();
    this.parent = parent;
    this.client = parent.clone();
    this.client.token = token;
    this.id = id;
    this.token = token;
  }

  /**
   * Open wallet.
   * @returns {Promise}
   */

  async open() {
    await this.parent.join(this.id, this.token);
    this.parent.wallets.set(this.id, this);
  }

  /**
   * Close wallet.
   * @returns {Promise}
   */

  async close() {
    await this.parent.leave(this.id);
    this.parent.wallets.delete(this.id);
  }

  /**
   * Get wallet transaction history.
   * @param {String} account
   * @returns {Promise}
   */

  getHistory(account) {
    return this.client.getHistory(this.id, account);
  }

  /**
   * Get wallet coins.
   * @param {String} account
   * @returns {Promise}
   */

  getCoins(account) {
    return this.client.getCoins(this.id, account);
  }

  /**
   * Get all unconfirmed transactions.
   * @param {String} account
   * @returns {Promise}
   */

  getPending(account) {
    return this.client.getPending(this.id, account);
  }

  /**
   * Calculate wallet balance.
   * @param {String} account
   * @returns {Promise}
   */

  getBalance(account) {
    return this.client.getBalance(this.id, account);
  }

  /**
   * Get last N wallet transactions.
   * @param {String} account
   * @param {Number} limit - Max number of transactions.
   * @returns {Promise}
   */

  getLast(account, limit) {
    return this.client.getLast(this.id, account, limit);
  }

  /**
   * Get wallet transactions by timestamp range.
   * @param {String} account
   * @param {Object} options
   * @param {Number} options.start - Start time.
   * @param {Number} options.end - End time.
   * @param {Number?} options.limit - Max number of records.
   * @param {Boolean?} options.reverse - Reverse order.
   * @returns {Promise}
   */

  getRange(account, options) {
    return this.client.getRange(this.id, account, options);
  }

  /**
   * Get transaction (only possible if the transaction
   * is available in the wallet history).
   * @param {Hash} hash
   * @returns {Promise}
   */

  getTX(hash) {
    return this.client.getTX(this.id, hash);
  }

  /**
   * Get wallet blocks.
   * @returns {Promise}
   */

  getBlocks() {
    return this.client.getBlocks(this.id);
  }

  /**
   * Get wallet block.
   * @param {Number} height
   * @returns {Promise}
   */

  getBlock(height) {
    return this.client.getBlock(this.id, height);
  }

  /**
   * Get unspent coin (only possible if the transaction
   * is available in the wallet history).
   * @param {Hash} hash
   * @param {Number} index
   * @returns {Promise}
   */

  getCoin(hash, index) {
    return this.client.getCoin(this.id, hash, index);
  }

  /**
   * @param {String} account
   * @param {Number} age - Age delta.
   * @returns {Promise}
   */

  zap(account, age) {
    return this.client.zap(this.id, account, age);
  }

  /**
   * Used to remove a pending transaction from the wallet.
   * That is likely the case if it has a policy or low fee
   * that prevents it from proper network propagation.
   * @param {Hash} hash
   * @returns {Promise}
   */

  abandon(hash) {
    return this.client.abandon(this.id, hash);
  }

  /**
   * Create a transaction, fill.
   * @param {Object} options
   * @returns {Promise}
   */

  createTX(options) {
    return this.client.createTX(this.id, options);
  }

  /**
   * Create a transaction, fill, sign, and broadcast.
   * @param {Object} options
   * @param {String} options.address
   * @param {Amount} options.value
   * @returns {Promise}
   */

  send(options) {
    return this.client.send(this.id, options);
  }

  /**
   * Sign a transaction.
   * @param {Object} options
   * @returns {Promise}
   */

  sign(options) {
    return this.client.sign(this.id, options);
  }

  /**
   * Get the raw wallet JSON.
   * @returns {Promise}
   */

  getInfo() {
    return this.client.getInfo(this.id);
  }

  /**
   * Get wallet accounts.
   * @returns {Promise} - Returns Array.
   */

  getAccounts() {
    return this.client.getAccounts(this.id);
  }

  /**
   * Get wallet master key.
   * @returns {Promise}
   */

  getMaster() {
    return this.client.getMaster(this.id);
  }

  /**
   * Get wallet account.
   * @param {String} account
   * @returns {Promise}
   */

  getAccount(account) {
    return this.client.getAccount(this.id, account);
  }

  /**
   * Create account.
   * @param {String} name
   * @param {Object} options
   * @returns {Promise}
   */

  createAccount(name, options) {
    return this.client.createAccount(this.id, name, options);
  }

  /**
   * Create address.
   * @param {String} account
   * @returns {Promise}
   */

  createAddress(account) {
    return this.client.createAddress(this.id, account);
  }

  /**
   * Create change address.
   * @param {String} account
   * @returns {Promise}
   */

  createChange(account) {
    return this.client.createChange(this.id, account);
  }

  /**
   * Create nested address.
   * @param {String} account
   * @returns {Promise}
   */

  createNested(account) {
    return this.client.createNested(this.id, account);
  }

  /**
   * Change or set master key`s passphrase.
   * @param {String|Buffer} passphrase
   * @param {(String|Buffer)?} old
   * @returns {Promise}
   */

  setPassphrase(passphrase, old) {
    return this.client.setPassphrase(this.id, passphrase, old);
  }

  /**
   * Generate a new token.
   * @param {(String|Buffer)?} passphrase
   * @returns {Promise}
   */

  async retoken(passphrase) {
    const result = await this.client.retoken(this.id, passphrase);

    assert(result);
    assert(typeof result.token === 'string');

    this.token = result.token;

    return result;
  }

  /**
   * Import private key.
   * @param {Number|String} account
   * @param {String} privateKey
   * @param {String} passphrase
   * @returns {Promise}
   */

  importPrivate(account, privateKey, passphrase) {
    return this.client.importPrivate(this.id, account, privateKey, passphrase);
  }

  /**
   * Import public key.
   * @param {Number|String} account
   * @param {String} publicKey
   * @returns {Promise}
   */

  importPublic(account, publicKey) {
    return this.client.importPublic(this.id, account, publicKey);
  }

  /**
   * Import address.
   * @param {Number|String} account
   * @param {String} address
   * @returns {Promise}
   */

  importAddress(account, address) {
    return this.client.importAddress(this.id, account, address);
  }

  /**
   * Lock a coin.
   * @param {String} hash
   * @param {Number} index
   * @returns {Promise}
   */

  lockCoin(hash, index) {
    return this.client.lockCoin(this.id, hash, index);
  }

  /**
   * Unlock a coin.
   * @param {String} hash
   * @param {Number} index
   * @returns {Promise}
   */

  unlockCoin(hash, index) {
    return this.client.unlockCoin(this.id, hash, index);
  }

  /**
   * Get locked coins.
   * @returns {Promise}
   */

  getLocked() {
    return this.client.getLocked(this.id);
  }

  /**
   * Lock wallet.
   * @returns {Promise}
   */

  lock() {
    return this.client.lock(this.id);
  }

  /**
   * Unlock wallet.
   * @param {String} passphrase
   * @param {Number} timeout
   * @returns {Promise}
   */

  unlock(passphrase, timeout) {
    return this.client.unlock(this.id, passphrase, timeout);
  }

  /**
   * Get wallet key.
   * @param {String} address
   * @returns {Promise}
   */

  getKey(address) {
    return this.client.getKey(this.id, address);
  }

  /**
   * Get wallet key WIF dump.
   * @param {String} address
   * @param {String?} passphrase
   * @returns {Promise}
   */

  getWIF(address, passphrase) {
    return this.client.getWIF(this.id, address, passphrase);
  }

  /**
   * Add a public account key to the wallet for multisig.
   * @param {String} account
   * @param {String} accountKey - Account (bip44) key (base58).
   * @returns {Promise}
   */

  addSharedKey(account, accountKey) {
    return this.client.addSharedKey(this.id, account, accountKey);
  }

  /**
   * Remove a public account key to the wallet for multisig.
   * @param {String} account
   * @param {String} accountKey - Account (bip44) key (base58).
   * @returns {Promise}
   */

  removeSharedKey(account, accountKey) {
    return this.client.removeSharedKey(this.id, account, accountKey);
  }

  /**
   * Resend wallet transactions.
   * @returns {Promise}
   */

  resend() {
    return this.client.resendWallet(this.id);
  }
}

/*
 * Expose
 */

module.exports = WalletClient;
