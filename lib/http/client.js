/*!
 * client.js - http client for wallets
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const Network = require('../protocol/network');
const AsyncObject = require('../utils/asyncobject');
const RPCClient = require('./rpcclient');
const util = require('../utils/util');
const request = require('./request');

/**
 * Bcoin HTTP client.
 * @alias module:http.Client
 * @constructor
 * @param {String} uri
 * @param {Object?} options
 */

function HTTPClient(options) {
  if (!(this instanceof HTTPClient))
    return new HTTPClient(options);

  if (!options)
    options = {};

  if (typeof options === 'string')
    options = { uri: options };

  AsyncObject.call(this);

  this.options = options;
  this.network = Network.get(options.network);

  this.uri = options.uri || `http://localhost:${this.network.rpcPort}`;
  this.socket = null;
  this.apiKey = options.apiKey;
  this.auth = options.auth;
  this.rpc = new RPCClient(options);
}

util.inherits(HTTPClient, AsyncObject);

/**
 * Open the client, wait for socket to connect.
 * @alias HTTPClient#open
 * @returns {Promise}
 */

HTTPClient.prototype._open = async function _open() {
  let IOClient;

  try {
    IOClient = require('socket.io-client');
  } catch (e) {
    ;
  }

  if (!IOClient)
    return;

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

  this.socket.on('wallet tx', (details) => {
    this.emit('tx', details);
  });

  this.socket.on('wallet confirmed', (details) => {
    this.emit('confirmed', details);
  });

  this.socket.on('wallet unconfirmed', (details) => {
    this.emit('unconfirmed', details);
  });

  this.socket.on('wallet conflict', (details) => {
    this.emit('conflict', details);
  });

  this.socket.on('wallet updated', (details) => {
    this.emit('updated', details);
  });

  this.socket.on('wallet address', (receive) => {
    this.emit('address', receive);
  });

  this.socket.on('wallet balance', (balance) => {
    this.emit('balance', balance);
  });

  await this.onConnect();
  await this.sendAuth();
};

/**
 * Close the client, wait for the socket to close.
 * @alias HTTPClient#close
 * @returns {Promise}
 */

HTTPClient.prototype._close = function close() {
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

HTTPClient.prototype.onConnect = function onConnect() {
  return new Promise((resolve, reject) => {
    this.socket.once('connect', resolve);
  });
};

/**
 * Wait for websocket auth.
 * @private
 * @returns {Promise}
 */

HTTPClient.prototype.sendAuth = function sendAuth() {
  return new Promise((resolve, reject) => {
    this.socket.emit('auth', this.apiKey, (err) => {
      if (err) {
        reject(new Error(err.message));
        return;
      }
      resolve();
    });
  });
};

/**
 * Wait for websocket auth.
 * @private
 * @returns {Promise}
 */

HTTPClient.prototype.sendWalletAuth = function sendWalletAuth() {
  return new Promise((resolve, reject) => {
    this.socket.emit('wallet auth', this.apiKey, (err) => {
      if (err) {
        reject(new Error(err.message));
        return;
      }
      resolve();
    });
  });
};

/**
 * Wait for websocket disconnection.
 * @private
 * @returns {Promise}
 */

HTTPClient.prototype.onDisconnect = function onDisconnect() {
  return new Promise((resolve, reject) => {
    this.socket.once('disconnect', resolve);
  });
};

/**
 * Make an http request to endpoint.
 * @private
 * @param {String} method
 * @param {String} endpoint - Path.
 * @param {Object} json - Body or query depending on method.
 * @returns {Promise} - Returns Object?.
 */

HTTPClient.prototype._request = async function _request(method, endpoint, json) {
  let query, network, res;

  if (this.token) {
    if (!json)
      json = {};
    json.token = this.token;
  }

  if (json && method === 'get') {
    query = json;
    json = null;
  }

  res = await request({
    method: method,
    uri: this.uri + endpoint,
    pool: true,
    query: query,
    json: json,
    auth: {
      username: 'bitcoinrpc',
      password: this.apiKey || ''
    }
  });

  if (res.statusCode === 404)
    return;

  if (res.statusCode === 401)
    throw new Error('Unauthorized (bad API key).');

  if (res.statusCode !== 200)
    throw new Error(`Status code: ${res.statusCode}.`);

  if (res.type !== 'json')
    throw new Error('Bad response (wrong content-type).');

  if (!res.body)
    throw new Error('Bad response (no body).');

  network = res.headers['x-bcoin-network'];

  if (network && network !== this.network.type)
    throw new Error('Bad response (wrong network).');

  if (res.body.error)
    throw new Error(res.body.error.message);

  return res.body;
};

/**
 * Make a GET http request to endpoint.
 * @private
 * @param {String} endpoint - Path.
 * @param {Object} json - Querystring.
 * @returns {Promise} - Returns Object?.
 */

HTTPClient.prototype._get = function _get(endpoint, json) {
  return this._request('get', endpoint, json);
};

/**
 * Make a POST http request to endpoint.
 * @private
 * @param {String} endpoint - Path.
 * @param {Object} json - Body.
 * @returns {Promise} - Returns Object?.
 */

HTTPClient.prototype._post = function _post(endpoint, json) {
  return this._request('post', endpoint, json);
};

/**
 * Make a PUT http request to endpoint.
 * @private
 * @param {String} endpoint - Path.
 * @param {Object} json - Body.
 * @returns {Promise} - Returns Object?.
 */

HTTPClient.prototype._put = function _put(endpoint, json) {
  return this._request('put', endpoint, json);
};

/**
 * Make a DELETE http request to endpoint.
 * @private
 * @param {String} endpoint - Path.
 * @param {Object} json - Body.
 * @returns {Promise} - Returns Object?.
 */

HTTPClient.prototype._del = function _del(endpoint, json) {
  return this._request('delete', endpoint, json);
};

/**
 * Get a mempool snapshot.
 * @returns {Promise} - Returns {@link Hash}[].
 */

HTTPClient.prototype.getMempool = function getMempool() {
  return this._get('/mempool');
};

/**
 * Get some info about the server (network and version).
 * @returns {Promise} - Returns Object.
 */

HTTPClient.prototype.getInfo = function getInfo() {
  return this._get('/');
};

/**
 * Get coins that pertain to an address from the mempool or chain database.
 * Takes into account spent coins in the mempool.
 * @param {String} address
 * @returns {Promise} - Returns {@link Coin}[].
 */

HTTPClient.prototype.getCoinsByAddress = function getCoinsByAddress(address) {
  return this._post('/coin/address', { address });
};

/**
 * Retrieve a coin from the mempool or chain database.
 * Takes into account spent coins in the mempool.
 * @param {Hash} hash
 * @param {Number} index
 * @returns {Promise} - Returns {@link Coin}.
 */

HTTPClient.prototype.getCoin = function getCoin(hash, index) {
  return this._get(`/coin/${hash}/${index}`);
};

/**
 * Retrieve transactions pertaining to an
 * address from the mempool or chain database.
 * @param {String} address
 * @returns {Promise} - Returns {@link TX}[].
 */

HTTPClient.prototype.getTXByAddress = function getTXByAddress(address) {
  return this._post('/tx/address', { address });
};

/**
 * Retrieve a transaction from the mempool or chain database.
 * @param {Hash} hash
 * @returns {Promise} - Returns {@link TX}.
 */

HTTPClient.prototype.getTX = function getTX(hash) {
  return this._get(`/tx/${hash}`);
};

/**
 * Retrieve a block from the chain database.
 * @param {Hash|Number} block
 * @returns {Promise} - Returns {@link Block}.
 */

HTTPClient.prototype.getBlock = function getBlock(block) {
  return this._get(`/block/${block}`);
};

/**
 * Add a transaction to the mempool and broadcast it.
 * @param {TX} tx
 * @returns {Promise}
 */

HTTPClient.prototype.broadcast = function broadcast(tx) {
  return this._post('/broadcast', { tx: toHex(tx) });
};

/**
 * Rescan the chain.
 * @param {Number} height
 * @returns {Promise}
 */

HTTPClient.prototype.rescan = function rescan(height) {
  return this._post('/wallet/_admin/rescan', { height });
};

/**
 * Reset the chain.
 * @param {Number} height
 * @returns {Promise}
 */

HTTPClient.prototype.reset = function reset(height) {
  return this._post('/reset', { height });
};

/**
 * Resend pending transactions.
 * @returns {Promise}
 */

HTTPClient.prototype.resend = function resend() {
  return this._post('/wallet/_admin/resend', {});
};

/**
 * Backup the walletdb.
 * @param {String} path
 * @returns {Promise}
 */

HTTPClient.prototype.backup = function backup(path) {
  return this._post('/wallet/_admin/backup', { path });
};

/**
 * Listen for events on wallet id.
 * @param {String} id
 * @param {String?} token
 * @returns {Promise}
 */

HTTPClient.prototype.join = function join(id, token) {
  if (!this.socket)
    return Promise.resolve();

  return new Promise((resolve, reject) => {
    this.socket.emit('wallet join', id, token, (err) => {
      if (err) {
        reject(new Error(err.message));
        return;
      }
      resolve();
    });
  });
};

/**
 * Unlisten for events on wallet id.
 * @param {String} id
 */

HTTPClient.prototype.leave = function leave(id) {
  if (!this.socket)
    return Promise.resolve();

  return new Promise((resolve, reject) => {
    this.socket.emit('wallet leave', id, (err) => {
      if (err) {
        reject(new Error(err.message));
        return;
      }
      resolve();
    });
  });
};

/**
 * Listen for events on all wallets.
 */

HTTPClient.prototype.all = function all(token) {
  return this.join('!all', token);
};

/**
 * Unlisten for events on all wallets.
 */

HTTPClient.prototype.none = function none() {
  return this.leave('!all');
};

/**
 * Get list of all wallet IDs.
 * @returns {Promise}
 */

HTTPClient.prototype.getWallets = function getWallets() {
  return this._get('/wallet/_admin/wallets');
};

/**
 * Create a wallet.
 * @param {Object} options
 * @returns {Promise}
 */

HTTPClient.prototype.createWallet = function createWallet(options) {
  return this._put(`/wallet/${options.id}`, options);
};

/**
 * Get the raw wallet JSON.
 * @param {String} id
 * @returns {Promise}
 */

HTTPClient.prototype.getWallet = function getWallet(id) {
  return this._get(`/wallet/${id}`);
};

/**
 * Get wallet transaction history.
 * @param {String} id
 * @returns {Promise}
 */

HTTPClient.prototype.getHistory = function getHistory(id, account) {
  return this._get(`/wallet/${id}/tx/history`, { account });
};

/**
 * Get wallet coins.
 * @param {String} id
 * @returns {Promise}
 */

HTTPClient.prototype.getCoins = function getCoins(id, account) {
  return this._get(`/wallet/${id}/coin`, { account });
};

/**
 * Get all unconfirmed transactions.
 * @param {String} id
 * @returns {Promise}
 */

HTTPClient.prototype.getPending = function getPending(id, account) {
  return this._get(`/wallet/${id}/tx/unconfirmed`, { account });
};

/**
 * Calculate wallet balance.
 * @param {String} id
 * @returns {Promise}
 */

HTTPClient.prototype.getBalance = function getBalance(id, account) {
  return this._get(`/wallet/${id}/balance`, { account });
};

/**
 * Get last N wallet transactions.
 * @param {String} id
 * @param {Number} limit - Max number of transactions.
 * @returns {Promise}
 */

HTTPClient.prototype.getLast = function getLast(id, account, limit) {
  return this._get(`/wallet/${id}/tx/last`, { account, limit });
};

/**
 * Get wallet transactions by timestamp range.
 * @param {String} id
 * @param {Object} options
 * @param {Number} options.start - Start time.
 * @param {Number} options.end - End time.
 * @param {Number?} options.limit - Max number of records.
 * @param {Boolean?} options.reverse - Reverse order.
 * @returns {Promise}
 */

HTTPClient.prototype.getRange = function getRange(id, account, options) {
  let body = {
    account: account,
    start: options.start,
    end: options.end ,
    limit: options.limit,
    reverse: options.reverse
  };
  return this._get(`/wallet/${id}/tx/range`, body);
};

/**
 * Get transaction (only possible if the transaction
 * is available in the wallet history).
 * @param {String} id
 * @param {Hash} hash
 * @returns {Promise}
 */

HTTPClient.prototype.getWalletTX = function getWalletTX(id, hash) {
  return this._get(`/wallet/${id}/tx/${hash}`);
};

/**
 * Get wallet blocks.
 * @param {String} id
 * @param {Number} height
 * @returns {Promise}
 */

HTTPClient.prototype.getWalletBlocks = function getWalletBlocks(id) {
  return this._get(`/wallet/${id}/block`);
};

/**
 * Get wallet block.
 * @param {String} id
 * @param {Number} height
 * @returns {Promise}
 */

HTTPClient.prototype.getWalletBlock = function getWalletBlock(id, height) {
  return this._get(`/wallet/${id}/block/${height}`);
};

/**
 * Get unspent coin (only possible if the transaction
 * is available in the wallet history).
 * @param {String} id
 * @param {Hash} hash
 * @param {Number} index
 * @returns {Promise}
 */

HTTPClient.prototype.getWalletCoin = function getWalletCoin(id, account, hash, index) {
  return this._get(`/wallet/${id}/coin/${hash}/${index}`, { account });
};

/**
 * Create a transaction, fill, sign, and broadcast.
 * @param {String} id
 * @param {Object} options
 * @param {String} options.address
 * @param {Amount} options.value
 * @returns {Promise}
 */

HTTPClient.prototype.send = function send(id, options) {
  let body = Object.assign({}, options);

  if (!body.outputs)
    body.outputs = [];

  body.outputs = body.outputs.map((output) => {
    return {
      value: output.value,
      address: output.address,
      script: toHex(output.script)
    };
  });

  return this._post(`/wallet/${id}/send`, body);
};

/**
 * Generate a new token.
 * @param {(String|Buffer)?} passphrase
 * @returns {Promise}
 */

HTTPClient.prototype.retoken = async function retoken(id, passphrase) {
  let body = await this._post(`/wallet/${id}/retoken`, { passphrase });
  return body.token;
};

/**
 * Change or set master key's passphrase.
 * @param {(String|Buffer)?} old
 * @param {String|Buffer} new_
 * @returns {Promise}
 */

HTTPClient.prototype.setPassphrase = function setPassphrase(id, old, new_) {
  let body = { old: old, passphrase: new_ };
  return this._post(`/wallet/${id}/passphrase`, body);
};

/**
 * Create a transaction, fill.
 * @param {String} id
 * @param {Object} options
 * @returns {Promise}
 */

HTTPClient.prototype.createTX = function createTX(id, options) {
  let body = Object.assign({}, options);

  if (!body.outputs)
    body.outputs = [];

  body.outputs = body.outputs.map((output) => {
    return {
      value: output.value,
      address: output.address,
      script: toHex(output.script)
    };
  });

  return this._post(`/wallet/${id}/create`, body);
};

/**
 * Sign a transaction.
 * @param {String} id
 * @param {TX} tx
 * @param {Object} options
 * @returns {Promise}
 */

HTTPClient.prototype.sign = function sign(id, tx, options) {
  let body = Object.assign({}, options);
  body.tx = toHex(tx);
  return this._post(`/wallet/${id}/sign`, body);
};

/**
 * @param {String} id
 * @param {Number} now - Current time.
 * @param {Number} age - Age delta (delete transactions older than `now - age`).
 * @returns {Promise}
 */

HTTPClient.prototype.zapWallet = function zapWallet(id, account, age) {
  return this._post(`/wallet/${id}/zap`, { account, age });
};

/**
 * Get wallet key.
 * @param {String} id
 * @param {String} address
 * @returns {Promise}
 */

HTTPClient.prototype.getKey = function getKey(id, address) {
  return this._get(`/wallet/${id}/key/${address}`);
};

/**
 * Get wallet key WIF dump.
 * @param {String} id
 * @param {String} address
 * @param {String?} passphrase
 * @returns {Promise}
 */

HTTPClient.prototype.getWIF = function getWIF(id, address, passphrase) {
  return this._get(`/wallet/${id}/wif/${address}`, { passphrase });
};

/**
 * Add a public account/purpose key to the wallet for multisig.
 * @param {String} id
 * @param {(String|Number)?} account
 * @param {Base58String} key - Account (bip44) or
 * Purpose (bip45) key (can be in base58 form).
 * @returns {Promise}
 */

HTTPClient.prototype.addSharedKey = function addSharedKey(id, account, key) {
  let body = { account: account, accountKey: key };
  return this._put(`/wallet/${id}/shared-key`, body);
};

/**
 * Remove a public account/purpose key to the wallet for multisig.
 * @param {String} id
 * @param {(String|Number)?} account
 * @param {Base58String} key - Account (bip44) or Purpose
 * (bip45) key (can be in base58 form).
 * @returns {Promise}
 */

HTTPClient.prototype.removeSharedKey = function removeSharedKey(id, account, key) {
  let body = { account: account, accountKey: key };
  return this._del(`/wallet/${id}/shared-key`, body);
};

/**
 * Import private key.
 * @param {String} id
 * @param {Number|String} account
 * @param {String} key
 * @returns {Promise}
 */

HTTPClient.prototype.importPrivate = function importPrivate(id, account, key) {
  let body = { account: account, privateKey: key };
  return this._post(`/wallet/${id}/import`, body);
};

/**
 * Import public key.
 * @param {String} id
 * @param {Number|String} account
 * @param {String} key
 * @returns {Promise}
 */

HTTPClient.prototype.importPublic = function importPublic(id, account, key) {
  let body = { account: account, publicKey: key };
  return this._post(`/wallet/${id}/import`, body);
};

/**
 * Import address.
 * @param {String} id
 * @param {Number|String} account
 * @param {String} address
 * @returns {Promise}
 */

HTTPClient.prototype.importAddress = function importAddress(id, account, address) {
  return this._post(`/wallet/${id}/import`, { account, address });
};

/**
 * Lock a coin.
 * @param {String} id
 * @param {String} hash
 * @param {Number} index
 * @returns {Promise}
 */

HTTPClient.prototype.lockCoin = function lockCoin(id, hash, index) {
  return this._put(`/wallet/${id}/coin/locked`, { hash, index });
};

/**
 * Unlock a coin.
 * @param {String} id
 * @param {String} hash
 * @param {Number} index
 * @returns {Promise}
 */

HTTPClient.prototype.unlockCoin = function unlockCoin(id, hash, index) {
  return this._del(`/wallet/${id}/coin/locked`, { hash, index });
};

/**
 * Get locked coins.
 * @param {String} id
 * @returns {Promise}
 */

HTTPClient.prototype.getLocked = function getLocked(id) {
  return this._get(`/wallet/${id}/coin/locked`);
};

/**
 * Lock wallet.
 * @param {String} id
 * @returns {Promise}
 */

HTTPClient.prototype.lock = function lock(id) {
  return this._post(`/wallet/${id}/lock`, {});
};

/**
 * Unlock wallet.
 * @param {String} id
 * @param {String} passphrase
 * @param {Number} timeout
 * @returns {Promise}
 */

HTTPClient.prototype.unlock = function unlock(id, passphrase, timeout) {
  return this._post(`/wallet/${id}/unlock`, { passphrase, timeout });
};

/**
 * Resend pending wallet transactions.
 * @returns {Promise}
 */

HTTPClient.prototype.resendWallet = function resendWallet(id) {
  return this._post(`/wallet/${id}/resend`, {});
};

/**
 * Get wallet accounts.
 * @param {String} id
 * @returns {Promise} - Returns Array.
 */

HTTPClient.prototype.getAccounts = function getAccounts(id) {
  return this._get(`/wallet/${id}/account`);
};

/**
 * Get wallet master key.
 * @param {String} id
 * @returns {Promise}
 */

HTTPClient.prototype.getMaster = function getMaster(id) {
  return this._get(`/wallet/${id}/master`);
};

/**
 * Get wallet account.
 * @param {String} id
 * @param {String} account
 * @returns {Promise}
 */

HTTPClient.prototype.getAccount = function getAccount(id, account) {
  return this._get(`/wallet/${id}/account/${account}`);
};

/**
 * Create account.
 * @param {String} id
 * @param {String} name
 * @param {Object} options
 * @returns {Promise}
 */

HTTPClient.prototype.createAccount = function createAccount(id, name, options) {
  return this._put(`/wallet/${id}/account/${name}`, options || {});
};

/**
 * Create address.
 * @param {String} id
 * @param {Object} options
 * @returns {Promise}
 */

HTTPClient.prototype.createAddress = function createAddress(id, options) {
  if (!options)
    options = {};

  if (typeof options === 'string')
    options = { account: options };

  return this._post(`/wallet/${id}/address`, options);
};

/**
 * Create change address.
 * @param {String} id
 * @param {Object} options
 * @returns {Promise}
 */

HTTPClient.prototype.createChange = function createChange(id, options) {
  if (!options)
    options = {};

  if (typeof options === 'string')
    options = { account: options };

  return this._post(`/wallet/${id}/change`, options);
};

/**
 * Create nested address.
 * @param {String} id
 * @param {Object} options
 * @returns {Promise}
 */

HTTPClient.prototype.createNested = function createNested(id, options) {
  if (!options)
    options = {};

  if (typeof options === 'string')
    options = { account: options };

  return this._post(`/wallet/${id}/nested`, options);
};

/*
 * Helpers
 */

function toHex(obj) {
  if (!obj)
    return;

  if (obj.toRaw)
    obj = obj.toRaw();

  if (Buffer.isBuffer(obj))
    obj = obj.toString('hex');

  return obj;
}

/*
 * Expose
 */

module.exports = HTTPClient;
