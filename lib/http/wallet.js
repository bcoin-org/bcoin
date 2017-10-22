/*!
 * wallet.js - http wallet for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const {Client} = require('bcurl');

class HTTPWallet extends Client {
  /**
   * HTTPWallet
   * @alias module:http.Wallet
   * @constructor
   * @param {String} uri
   */

  constructor(options) {
    super(options);
  }

  /**
   * Open the client, wait for socket to connect.
   * @returns {Promise}
   */

  async init() {
    await super.open();

    this.on('error', (err) => {
      this.emit('error', err);
    });

    this.listen('wallet tx', (details) => {
      this.emit('tx', details);
    });

    this.listen('wallet confirmed', (details) => {
      this.emit('confirmed', details);
    });

    this.listen('wallet unconfirmed', (details) => {
      this.emit('unconfirmed', details);
    });

    this.listen('wallet conflict', (details) => {
      this.emit('conflict', details);
    });

    this.listen('wallet updated', (details) => {
      this.emit('updated', details);
    });

    this.listen('wallet address', (receive) => {
      this.emit('address', receive);
    });

    this.listen('wallet balance', (balance) => {
      this.emit('balance', balance);
    });
  }

  /**
   * Open the client and get a wallet.
   * @returns {Promise}
   */

  async open(options = {}) {
    if (options.id != null) {
      assert(typeof options.id === 'string');
      this.id = options.id;
    }

    if (options.token != null) {
      assert(typeof options.token === 'string');
      this.token = options.token;
    }

    if (!this.id)
      throw new Error('No ID provided.');

    await this.init();
    await this.call('wallet join', this.id, this.token);
  }

  /**
   * Open the client and create a wallet.
   * @returns {Promise}
   */

  async create(options) {
    const wallet = await this.createWallet(options);

    assert(wallet);
    assert(typeof wallet.id === 'string');
    assert(typeof wallet.token === 'string');

    this.id = wallet.id;
    this.token = wallet.token;

    await this.init();
    await this.call('wallet join', this.id, this.token);

    return wallet;
  }

  /**
   * Auth with server.
   * @returns {Promise}
   */

  async auth() {
    return this.call('wallet auth', this.password);
  }

  /**
   * Make an RPC call.
   * @returns {Promise}
   */

  execute(name, params) {
    return super.execute('/', name, params);
  }

  /**
   * Rescan the chain.
   * @param {Number} height
   * @returns {Promise}
   */

  rescan(height) {
    return this.post('/wallet/_admin/rescan', { height });
  }

  /**
   * Resend pending transactions.
   * @returns {Promise}
   */

  resend() {
    return this.post('/wallet/_admin/resend');
  }

  /**
   * Backup the walletdb.
   * @param {String} path
   * @returns {Promise}
   */

  backup(path) {
    return this.post('/wallet/_admin/backup', { path });
  }

  /**
   * Get list of all wallet IDs.
   * @returns {Promise}
   */

  getWallets() {
    return this.get('/wallet/_admin/wallets');
  }

  /**
   * Create a wallet.
   * @param {Object} options
   * @returns {Promise}
   */

  createWallet(options) {
    assert(options.id, 'Must pass an id parameter');
    return this.put(`/wallet/${options.id}`, options);
  }

  /**
   * Get wallet transaction history.
   * @returns {Promise}
   */

  getHistory(account) {
    return this.get(`/wallet/${this.id}/tx/history`, { account });
  }

  /**
   * Get wallet coins.
   * @returns {Promise}
   */

  getCoins(account) {
    return this.get(`/wallet/${this.id}/coin`, { account });
  }

  /**
   * Get all unconfirmed transactions.
   * @returns {Promise}
   */

  getPending(account) {
    return this.get(`/wallet/${this.id}/tx/unconfirmed`, { account });
  }

  /**
   * Calculate wallet balance.
   * @returns {Promise}
   */

  getBalance(account) {
    return this.get(`/wallet/${this.id}/balance`, { account });
  }

  /**
   * Get last N wallet transactions.
   * @param {Number} limit - Max number of transactions.
   * @returns {Promise}
   */

  getLast(account, limit) {
    return this.get(`/wallet/${this.id}/tx/last`, { account, limit });
  }

  /**
   * Get wallet transactions by timestamp range.
   * @param {Object} options
   * @param {Number} options.start - Start time.
   * @param {Number} options.end - End time.
   * @param {Number?} options.limit - Max number of records.
   * @param {Boolean?} options.reverse - Reverse order.
   * @returns {Promise}
   */

  getRange(account, options) {
    return this.get(`/wallet/${this.id}/tx/range`, {
      account: account,
      start: options.start,
      end: options.end ,
      limit: options.limit,
      reverse: options.reverse
    });
  }

  /**
   * Get transaction (only possible if the transaction
   * is available in the wallet history).
   * @param {Hash} hash
   * @returns {Promise}
   */

  getTX(hash) {
    return this.get(`/wallet/${this.id}/tx/${hash}`);
  }

  /**
   * Get wallet blocks.
   * @param {Number} height
   * @returns {Promise}
   */

  getBlocks() {
    return this.get(`/wallet/${this.id}/block`);
  }

  /**
   * Get wallet block.
   * @param {Number} height
   * @returns {Promise}
   */

  getBlock(height) {
    return this.get(`/wallet/${this.id}/block/${height}`);
  }

  /**
   * Get unspent coin (only possible if the transaction
   * is available in the wallet history).
   * @param {Hash} hash
   * @param {Number} index
   * @returns {Promise}
   */

  getCoin(hash, index) {
    return this.get(`/wallet/${this.id}/coin/${hash}/${index}`);
  }

  /**
   * @param {Number} now - Current time.
   * @param {Number} age - Age delta (delete transactions older than `now - age`).
   * @returns {Promise}
   */

  zap(account, age) {
    return this.post(`/wallet/${this.id}/zap`, { account, age });
  }

  /**
   * Create a transaction, fill.
   * @param {Object} options
   * @returns {Promise}
   */

  createTX(options) {
    return this.post(`/wallet/${this.id}/create`, options);
  }

  /**
   * Create a transaction, fill, sign, and broadcast.
   * @param {Object} options
   * @param {String} options.address
   * @param {Amount} options.value
   * @returns {Promise}
   */

  send(options) {
    return this.post(`/wallet/${this.id}/send`, options);
  }

  /**
   * Sign a transaction.
   * @param {Object} options
   * @returns {Promise}
   */

  sign(options) {
    return this.post(`/wallet/${this.id}/sign`, options);
  }

  /**
   * Get the raw wallet JSON.
   * @returns {Promise}
   */

  getInfo() {
    return this.get(`/wallet/${this.id}`);
  }

  /**
   * Get wallet accounts.
   * @returns {Promise} - Returns Array.
   */

  getAccounts() {
    return this.get(`/wallet/${this.id}/account`);
  }

  /**
   * Get wallet master key.
   * @returns {Promise}
   */

  getMaster() {
    return this.get(`/wallet/${this.id}/master`);
  }

  /**
   * Get wallet account.
   * @param {String} account
   * @returns {Promise}
   */

  getAccount(account) {
    return this.get(`/wallet/${this.id}/account/${account}`);
  }

  /**
   * Create account.
   * @param {String} name
   * @param {Object} options
   * @returns {Promise}
   */

  createAccount(name, options) {
    return this.put(`/wallet/${this.id}/account/${name}`, options);
  }

  /**
   * Create address.
   * @param {Object} options
   * @returns {Promise}
   */

  createAddress(account) {
    return this.post(`/wallet/${this.id}/address`, { account });
  }

  /**
   * Create change address.
   * @param {Object} options
   * @returns {Promise}
   */

  createChange(account) {
    return this.post(`/wallet/${this.id}/change`, { account });
  }

  /**
   * Create nested address.
   * @param {Object} options
   * @returns {Promise}
   */

  createNested(account) {
    return this.post(`/wallet/${this.id}/nested`, { account });
  }

  /**
   * Change or set master key's passphrase.
   * @param {String|Buffer} passphrase
   * @param {(String|Buffer)?} old
   * @returns {Promise}
   */

  setPassphrase(passphrase, old) {
    return this.post(`/wallet/${this.id}/passphrase`, { passphrase, old });
  }

  /**
   * Generate a new token.
   * @param {(String|Buffer)?} passphrase
   * @returns {Promise}
   */

  async retoken(passphrase) {
    const body = await this.post(`/wallet/${this.id}/retoken`, {
      passphrase
    });

    assert(body);
    assert(typeof body.token === 'string');

    this.token = body.token;

    return body.token;
  }

  /**
   * Import private key.
   * @param {Number|String} account
   * @param {String} key
   * @returns {Promise}
   */

  importPrivate(account, privateKey, passphrase) {
    return this.post(`/wallet/${this.id}/import`, {
      account,
      privateKey,
      passphrase
    });
  }

  /**
   * Import public key.
   * @param {Number|String} account
   * @param {String} key
   * @returns {Promise}
   */

  importPublic(account, publicKey) {
    return this.post(`/wallet/${this.id}/import`, {
      account,
      publicKey
    });
  }

  /**
   * Import address.
   * @param {Number|String} account
   * @param {String} address
   * @returns {Promise}
   */

  importAddress(account, address) {
    return this.post(`/wallet/${this.id}/import`, { account, address });
  }

  /**
   * Lock a coin.
   * @param {String} hash
   * @param {Number} index
   * @returns {Promise}
   */

  lockCoin(hash, index) {
    return this.put(`/wallet/${this.id}/locked/${hash}/${index}`);
  }

  /**
   * Unlock a coin.
   * @param {String} hash
   * @param {Number} index
   * @returns {Promise}
   */

  unlockCoin(hash, index) {
    return this.del(`/wallet/${this.id}/locked/${hash}/${index}`);
  }

  /**
   * Get locked coins.
   * @returns {Promise}
   */

  getLocked() {
    return this.get(`/wallet/${this.id}/locked`);
  }

  /**
   * Lock wallet.
   * @returns {Promise}
   */

  lock() {
    return this.post(`/wallet/${this.id}/lock`);
  }

  /**
   * Unlock wallet.
   * @param {String} passphrase
   * @param {Number} timeout
   * @returns {Promise}
   */

  unlock(passphrase, timeout) {
    return this.post(`/wallet/${this.id}/unlock`, {
      passphrase,
      timeout
    });
  }

  /**
   * Get wallet key.
   * @param {String} address
   * @returns {Promise}
   */

  getKey(address) {
    return this.get(`/wallet/${this.id}/key/${address}`);
  }

  /**
   * Get wallet key WIF dump.
   * @param {String} address
   * @param {String?} passphrase
   * @returns {Promise}
   */

  getWIF(address, passphrase) {
    return this.get(`/wallet/${this.id}/wif/${address}`, { passphrase });
  }

  /**
   * Add a public account/purpose key to the wallet for multisig.
   * @param {(String|Number)?} account
   * @param {Base58String} key - Account (bip44) or
   * Purpose (bip45) key (can be in base58 form).
   * @returns {Promise}
   */

  addSharedKey(account, accountKey) {
    return this.put(`/wallet/${this.id}/shared-key`, {
      account,
      accountKey
    });
  }

  /**
   * Remove a public account/purpose key to the wallet for multisig.
   * @param {(String|Number)?} account
   * @param {Base58String} key - Account (bip44) or Purpose
   * (bip45) key (can be in base58 form).
   * @returns {Promise}
   */

  removeSharedKey(account, accountKey) {
    return this.del(`/wallet/${this.id}/shared-key`, {
      account,
      accountKey
    });
  }

  /**
   * Resend wallet transactions.
   * @returns {Promise}
   */

  resend() {
    return this.post(`/wallet/${this.id}/resend`);
  }
}

/*
 * Expose
 */

module.exports = HTTPWallet;
