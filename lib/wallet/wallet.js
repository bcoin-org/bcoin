/*!
 * wallet.js - wallet object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const EventEmitter = require('events');
const Network = require('../protocol/network');
const util = require('../utils/util');
const encoding = require('../utils/encoding');
const Lock = require('../utils/lock');
const digest = require('../crypto/digest');
const cleanse = require('../crypto/cleanse');
const BufferReader = require('../utils/reader');
const StaticWriter = require('../utils/staticwriter');
const base58 = require('../utils/base58');
const TXDB = require('./txdb');
const Path = require('./path');
const common = require('./common');
const Address = require('../primitives/address');
const MTX = require('../primitives/mtx');
const Script = require('../script/script');
const WalletKey = require('./walletkey');
const HD = require('../hd/hd');
const Output = require('../primitives/output');
const Account = require('./account');
const MasterKey = require('./masterkey');
const policy = require('../protocol/policy');
const consensus = require('../protocol/consensus');
const Mnemonic = HD.Mnemonic;

/**
 * BIP44 Wallet
 * @alias module:wallet.Wallet
 * @constructor
 * @param {Object} options
 * present, no coins will be available.
 * @param {(HDPrivateKey|HDPublicKey)?} options.master - Master HD key. If not
 * present, it will be generated.
 * @param {Boolean?} options.witness - Whether to use witness programs.
 * @param {Number?} options.accountIndex - The BIP44 account index (default=0).
 * @param {Number?} options.receiveDepth - The index of the _next_ receiving
 * address.
 * @param {Number?} options.changeDepth - The index of the _next_ change
 * address.
 * @param {String?} options.type - Type of wallet (pubkeyhash, multisig)
 * (default=pubkeyhash).
 * @param {Boolean?} options.compressed - Whether to use compressed
 * public keys (default=true).
 * @param {Number?} options.m - `m` value for multisig.
 * @param {Number?} options.n - `n` value for multisig.
 * @param {String?} options.id - Wallet ID (used for storage)
 * @param {String?} options.mnemonic - mnemonic phrase to use to instantiate an
 * hd private key for wallet
 * (default=account key "address").
 */

function Wallet(wdb, options) {
  if (!(this instanceof Wallet))
    return new Wallet(wdb, options);

  EventEmitter.call(this);

  assert(wdb, 'WDB required.');

  this.wdb = wdb;
  this.db = wdb.db;
  this.network = wdb.network;
  this.logger = wdb.logger;
  this.writeLock = new Lock();
  this.fundLock = new Lock();

  this.wid = 0;
  this.id = null;
  this.initialized = false;
  this.watchOnly = false;
  this.accountDepth = 0;
  this.token = encoding.ZERO_HASH;
  this.tokenDepth = 0;
  this.master = new MasterKey();

  this.txdb = new TXDB(this.wdb);

  if (options)
    this.fromOptions(options);
}

Object.setPrototypeOf(Wallet.prototype, EventEmitter.prototype);

/**
 * Inject properties from options object.
 * @private
 * @param {Object} options
 */

Wallet.prototype.fromOptions = function fromOptions(options) {
  let key = options.master;
  let id, token, mnemonic;

  if (key) {
    if (typeof key === 'string')
      key = HD.PrivateKey.fromBase58(key, this.network);

    assert(HD.isPrivate(key),
      'Must create wallet with hd private key.');
  } else {
    mnemonic = new Mnemonic(options.mnemonic);
    key = HD.fromMnemonic(mnemonic, this.network);
  }

  assert(key.network === this.network,
    'Network mismatch for master key.');

  this.master.fromKey(key, mnemonic);

  if (options.wid != null) {
    assert(util.isU32(options.wid));
    this.wid = options.wid;
  }

  if (options.id) {
    assert(common.isName(options.id), 'Bad wallet ID.');
    id = options.id;
  }

  if (options.initialized != null) {
    assert(typeof options.initialized === 'boolean');
    this.initialized = options.initialized;
  }

  if (options.watchOnly != null) {
    assert(typeof options.watchOnly === 'boolean');
    this.watchOnly = options.watchOnly;
  }

  if (options.accountDepth != null) {
    assert(util.isU32(options.accountDepth));
    this.accountDepth = options.accountDepth;
  }

  if (options.token) {
    assert(Buffer.isBuffer(options.token));
    assert(options.token.length === 32);
    token = options.token;
  }

  if (options.tokenDepth != null) {
    assert(util.isU32(options.tokenDepth));
    this.tokenDepth = options.tokenDepth;
  }

  if (!id)
    id = this.getID();

  if (!token)
    token = this.getToken(this.tokenDepth);

  this.id = id;
  this.token = token;

  return this;
};

/**
 * Instantiate wallet from options.
 * @param {WalletDB} wdb
 * @param {Object} options
 * @returns {Wallet}
 */

Wallet.fromOptions = function fromOptions(wdb, options) {
  return new Wallet(wdb).fromOptions(options);
};

/**
 * Attempt to intialize the wallet (generating
 * the first addresses along with the lookahead
 * addresses). Called automatically from the
 * walletdb.
 * @returns {Promise}
 */

Wallet.prototype.init = async function init(options) {
  const passphrase = options.passphrase;

  assert(!this.initialized);
  this.initialized = true;

  if (passphrase)
    await this.master.encrypt(passphrase);

  const account = await this._createAccount(options, passphrase);
  assert(account);

  this.logger.info('Wallet initialized (%s).', this.id);

  await this.txdb.open(this);
};

/**
 * Open wallet (done after retrieval).
 * @returns {Promise}
 */

Wallet.prototype.open = async function open() {
  assert(this.initialized);

  const account = await this.getAccount(0);

  if (!account)
    throw new Error('Default account not found.');

  this.logger.info('Wallet opened (%s).', this.id);

  await this.txdb.open(this);
};

/**
 * Close the wallet, unregister with the database.
 * @returns {Promise}
 */

Wallet.prototype.destroy = async function destroy() {
  const unlock1 = await this.writeLock.lock();
  const unlock2 = await this.fundLock.lock();
  try {
    await this.master.destroy();
    this.writeLock.destroy();
    this.fundLock.destroy();
  } finally {
    unlock2();
    unlock1();
  }
};

/**
 * Add a public account key to the wallet (multisig).
 * Saves the key in the wallet database.
 * @param {(Number|String)} acct
 * @param {HDPublicKey} key
 * @returns {Promise}
 */

Wallet.prototype.addSharedKey = async function addSharedKey(acct, key) {
  const unlock = await this.writeLock.lock();
  try {
    return await this._addSharedKey(acct, key);
  } finally {
    unlock();
  }
};

/**
 * Add a public account key to the wallet without a lock.
 * @private
 * @param {(Number|String)} acct
 * @param {HDPublicKey} key
 * @returns {Promise}
 */

Wallet.prototype._addSharedKey = async function _addSharedKey(acct, key) {
  const account = await this.getAccount(acct);

  if (!account)
    throw new Error('Account not found.');

  const b = this.db.batch();
  const result = await account.addSharedKey(b, key);
  await b.write();

  return result;
};

/**
 * Remove a public account key from the wallet (multisig).
 * @param {(Number|String)} acct
 * @param {HDPublicKey} key
 * @returns {Promise}
 */

Wallet.prototype.removeSharedKey = async function removeSharedKey(acct, key) {
  const unlock = await this.writeLock.lock();
  try {
    return await this._removeSharedKey(acct, key);
  } finally {
    unlock();
  }
};

/**
 * Remove a public account key from the wallet (multisig).
 * @private
 * @param {(Number|String)} acct
 * @param {HDPublicKey} key
 * @returns {Promise}
 */

Wallet.prototype._removeSharedKey = async function _removeSharedKey(acct, key) {
  const account = await this.getAccount(acct);

  if (!account)
    throw new Error('Account not found.');

  const b = this.db.batch();
  const result = await account.removeSharedKey(b, key);
  await b.write();

  return result;
};

/**
 * Change or set master key's passphrase.
 * @param {String|Buffer} passphrase
 * @param {String|Buffer} old
 * @returns {Promise}
 */

Wallet.prototype.setPassphrase = async function setPassphrase(passphrase, old) {
  if (old != null)
    await this.decrypt(old);

  await this.encrypt(passphrase);
};

/**
 * Encrypt the wallet permanently.
 * @param {String|Buffer} passphrase
 * @returns {Promise}
 */

Wallet.prototype.encrypt = async function encrypt(passphrase) {
  const unlock = await this.writeLock.lock();
  try {
    return await this._encrypt(passphrase);
  } finally {
    unlock();
  }
};

/**
 * Encrypt the wallet permanently, without a lock.
 * @private
 * @param {String|Buffer} passphrase
 * @returns {Promise}
 */

Wallet.prototype._encrypt = async function _encrypt(passphrase) {
  const key = await this.master.encrypt(passphrase, true);
  const b = this.db.batch();

  try {
    await this.wdb.encryptKeys(b, this.wid, key);
  } finally {
    cleanse(key);
  }

  this.save(b);

  await b.write();
};

/**
 * Decrypt the wallet permanently.
 * @param {String|Buffer} passphrase
 * @returns {Promise}
 */

Wallet.prototype.decrypt = async function decrypt(passphrase) {
  const unlock = await this.writeLock.lock();
  try {
    return await this._decrypt(passphrase);
  } finally {
    unlock();
  }
};

/**
 * Decrypt the wallet permanently, without a lock.
 * @private
 * @param {String|Buffer} passphrase
 * @returns {Promise}
 */

Wallet.prototype._decrypt = async function _decrypt(passphrase) {
  const key = await this.master.decrypt(passphrase, true);
  const b = this.db.batch();

  try {
    await this.wdb.decryptKeys(b, this.wid, key);
  } finally {
    cleanse(key);
  }

  this.save(b);

  await b.write();
};

/**
 * Generate a new token.
 * @param {(String|Buffer)?} passphrase
 * @returns {Promise}
 */

Wallet.prototype.retoken = async function retoken(passphrase) {
  const unlock = await this.writeLock.lock();
  try {
    return await this._retoken(passphrase);
  } finally {
    unlock();
  }
};

/**
 * Generate a new token without a lock.
 * @private
 * @param {(String|Buffer)?} passphrase
 * @returns {Promise}
 */

Wallet.prototype._retoken = async function _retoken(passphrase) {
  if (passphrase)
    await this.unlock(passphrase);

  this.tokenDepth += 1;
  this.token = this.getToken(this.tokenDepth);

  const b = this.db.batch();
  this.save(b);

  await b.write();

  return this.token;
};

/**
 * Rename the wallet.
 * @param {String} id
 * @returns {Promise}
 */

Wallet.prototype.rename = async function rename(id) {
  const unlock = await this.writeLock.lock();
  try {
    return await this.wdb.rename(this, id);
  } finally {
    unlock();
  }
};

/**
 * Rename account.
 * @param {(String|Number)?} acct
 * @param {String} name
 * @returns {Promise}
 */

Wallet.prototype.renameAccount = async function renameAccount(acct, name) {
  const unlock = await this.writeLock.lock();
  try {
    return await this._renameAccount(acct, name);
  } finally {
    unlock();
  }
};

/**
 * Rename account without a lock.
 * @private
 * @param {(String|Number)?} acct
 * @param {String} name
 * @returns {Promise}
 */

Wallet.prototype._renameAccount = async function _renameAccount(acct, name) {
  if (!common.isName(name))
    throw new Error('Bad account name.');

  const account = await this.getAccount(acct);

  if (!account)
    throw new Error('Account not found.');

  if (account.accountIndex === 0)
    throw new Error('Cannot rename default account.');

  if (await this.hasAccount(name))
    throw new Error('Account name not available.');

  const b = this.db.batch();

  this.wdb.renameAccount(b, account, name);

  await b.write();
};

/**
 * Lock the wallet, destroy decrypted key.
 */

Wallet.prototype.lock = async function lock() {
  const unlock1 = await this.writeLock.lock();
  const unlock2 = await this.fundLock.lock();
  try {
    await this.master.lock();
  } finally {
    unlock2();
    unlock1();
  }
};

/**
 * Unlock the key for `timeout` seconds.
 * @param {Buffer|String} passphrase
 * @param {Number?} [timeout=60]
 */

Wallet.prototype.unlock = function unlock(passphrase, timeout) {
  return this.master.unlock(passphrase, timeout);
};

/**
 * Generate the wallet ID if none was passed in.
 * It is represented as HASH160(m/44->public|magic)
 * converted to an "address" with a prefix
 * of `0x03be04` (`WLT` in base58).
 * @private
 * @returns {Base58String}
 */

Wallet.prototype.getID = function getID() {
  assert(this.master.key, 'Cannot derive id.');

  const key = this.master.key.derive(44);

  const bw = new StaticWriter(37);
  bw.writeBytes(key.publicKey);
  bw.writeU32(this.network.magic);

  const hash = digest.hash160(bw.render());

  const b58 = new StaticWriter(27);
  b58.writeU8(0x03);
  b58.writeU8(0xbe);
  b58.writeU8(0x04);
  b58.writeBytes(hash);
  b58.writeChecksum();

  return base58.encode(b58.render());
};

/**
 * Generate the wallet api key if none was passed in.
 * It is represented as HASH256(m/44'->private|nonce).
 * @private
 * @param {HDPrivateKey} master
 * @param {Number} nonce
 * @returns {Buffer}
 */

Wallet.prototype.getToken = function getToken(nonce) {
  if (!this.master.key)
    throw new Error('Cannot derive token.');

  const key = this.master.key.derive(44, true);

  const bw = new StaticWriter(36);
  bw.writeBytes(key.privateKey);
  bw.writeU32(nonce);

  return digest.hash256(bw.render());
};

/**
 * Create an account. Requires passphrase if master key is encrypted.
 * @param {Object} options - See {@link Account} options.
 * @returns {Promise} - Returns {@link Account}.
 */

Wallet.prototype.createAccount = async function createAccount(options, passphrase) {
  const unlock = await this.writeLock.lock();
  try {
    return await this._createAccount(options, passphrase);
  } finally {
    unlock();
  }
};

/**
 * Create an account without a lock.
 * @param {Object} options - See {@link Account} options.
 * @returns {Promise} - Returns {@link Account}.
 */

Wallet.prototype._createAccount = async function _createAccount(options, passphrase) {
  let name = options.name;

  if (!name)
    name = this.accountDepth.toString(10);

  if (await this.hasAccount(name))
    throw new Error('Account already exists.');

  await this.unlock(passphrase);

  let key;
  if (this.watchOnly && options.accountKey) {
    key = options.accountKey;

    if (typeof key === 'string')
      key = HD.PublicKey.fromBase58(key, this.network);

    if (!HD.isPublic(key))
      throw new Error('Must add HD public keys to watch only wallet.');

    assert(key.network === this.network,
      'Network mismatch for watch only key.');
  } else {
    assert(this.master.key);
    key = this.master.key.deriveAccount(44, this.accountDepth);
    key = key.toPublic();
  }

  const opt = {
    wid: this.wid,
    id: this.id,
    name: this.accountDepth === 0 ? 'default' : name,
    witness: options.witness,
    watchOnly: this.watchOnly,
    accountKey: key,
    accountIndex: this.accountDepth,
    type: options.type,
    m: options.m,
    n: options.n,
    keys: options.keys
  };

  const b = this.db.batch();

  const account = Account.fromOptions(this.wdb, opt);

  await account.init(b);

  this.logger.info('Created account %s/%s/%d.',
    account.id,
    account.name,
    account.accountIndex);

  this.accountDepth++;
  this.save(b);

  await b.write();

  return account;
};

/**
 * Ensure an account. Requires passphrase if master key is encrypted.
 * @param {Object} options - See {@link Account} options.
 * @returns {Promise} - Returns {@link Account}.
 */

Wallet.prototype.ensureAccount = async function ensureAccount(options, passphrase) {
  const name = options.name;
  const account = await this.getAccount(name);

  if (account)
    return account;

  return await this.createAccount(options, passphrase);
};

/**
 * List account names and indexes from the db.
 * @returns {Promise} - Returns Array.
 */

Wallet.prototype.getAccounts = function getAccounts() {
  return this.wdb.getAccounts(this.wid);
};

/**
 * Get all wallet address hashes.
 * @param {(String|Number)?} acct
 * @returns {Promise} - Returns Array.
 */

Wallet.prototype.getAddressHashes = function getAddressHashes(acct) {
  if (acct != null)
    return this.getAccountHashes(acct);
  return this.wdb.getWalletHashes(this.wid);
};

/**
 * Get all account address hashes.
 * @param {String|Number} acct
 * @returns {Promise} - Returns Array.
 */

Wallet.prototype.getAccountHashes = async function getAccountHashes(acct) {
  const index = await this.getAccountIndex(acct);

  if (index === -1)
    throw new Error('Account not found.');

  return await this.wdb.getAccountHashes(this.wid, index);
};

/**
 * Retrieve an account from the database.
 * @param {Number|String} acct
 * @returns {Promise} - Returns {@link Account}.
 */

Wallet.prototype.getAccount = async function getAccount(acct) {
  const index = await this.getAccountIndex(acct);

  if (index === -1)
    return null;

  const account = await this.wdb.getAccount(this.wid, index);

  if (!account)
    return null;

  account.wid = this.wid;
  account.id = this.id;
  account.watchOnly = this.watchOnly;

  return account;
};

/**
 * Lookup the corresponding account name's index.
 * @param {String|Number} acct - Account name/index.
 * @returns {Promise} - Returns Number.
 */

Wallet.prototype.getAccountIndex = function getAccountIndex(acct) {
  if (acct == null)
    return -1;

  if (typeof acct === 'number')
    return acct;

  return this.wdb.getAccountIndex(this.wid, acct);
};

/**
 * Lookup the corresponding account name's index.
 * @param {String|Number} acct - Account name/index.
 * @returns {Promise} - Returns Number.
 * @throws on non-existent account
 */

Wallet.prototype.ensureIndex = async function ensureIndex(acct) {
  if (acct == null || acct === -1)
    return -1;

  const index = await this.getAccountIndex(acct);

  if (index === -1)
    throw new Error('Account not found.');

  return index;
};

/**
 * Lookup the corresponding account index's name.
 * @param {WalletID} wid
 * @param {Number} index - Account index.
 * @returns {Promise} - Returns String.
 */

Wallet.prototype.getAccountName = async function getAccountName(index) {
  if (typeof index === 'string')
    return index;

  return await this.wdb.getAccountName(this.wid, index);
};

/**
 * Test whether an account exists.
 * @param {Number|String} acct
 * @returns {Promise} - Returns {@link Boolean}.
 */

Wallet.prototype.hasAccount = async function hasAccount(acct) {
  const index = await this.getAccountIndex(acct);

  if (index === -1)
    return false;

  return await this.db.hasAccount(this.wid, index);
};

/**
 * Create a new receiving address (increments receiveDepth).
 * @param {(Number|String)?} acct
 * @returns {Promise} - Returns {@link WalletKey}.
 */

Wallet.prototype.createReceive = function createReceive(acct = 0) {
  return this.createKey(acct, 0);
};

/**
 * Create a new change address (increments receiveDepth).
 * @param {(Number|String)?} acct
 * @returns {Promise} - Returns {@link WalletKey}.
 */

Wallet.prototype.createChange = function createChange(acct = 0) {
  return this.createKey(acct, 1);
};

/**
 * Create a new nested address (increments receiveDepth).
 * @param {(Number|String)?} acct
 * @returns {Promise} - Returns {@link WalletKey}.
 */

Wallet.prototype.createNested = function createNested(acct = 0) {
  return this.createKey(acct, 2);
};

/**
 * Create a new address (increments depth).
 * @param {(Number|String)?} acct
 * @param {Number} branch
 * @returns {Promise} - Returns {@link WalletKey}.
 */

Wallet.prototype.createKey = async function createKey(acct, branch) {
  const unlock = await this.writeLock.lock();
  try {
    return await this._createKey(acct, branch);
  } finally {
    unlock();
  }
};

/**
 * Create a new address (increments depth) without a lock.
 * @private
 * @param {(Number|String)?} acct
 * @param {Number} branche
 * @returns {Promise} - Returns {@link WalletKey}.
 */

Wallet.prototype._createKey = async function _createKey(acct, branch) {
  const account = await this.getAccount(acct);

  if (!account)
    throw new Error('Account not found.');

  const b = this.db.batch();
  const key = await account.createKey(b, branch);
  await b.write();

  return key;
};

/**
 * Save the wallet to the database. Necessary
 * when address depth and keys change.
 * @returns {Promise}
 */

Wallet.prototype.save = function save(b) {
  return this.wdb.save(b, this);
};

/**
 * Test whether the wallet possesses an address.
 * @param {Address|Hash} address
 * @returns {Promise} - Returns Boolean.
 */

Wallet.prototype.hasAddress = async function hasAddress(address) {
  const hash = Address.getHash(address, 'hex');
  const path = await this.getPath(hash);
  return path != null;
};

/**
 * Get path by address hash.
 * @param {Address|Hash} address
 * @returns {Promise} - Returns {@link Path}.
 */

Wallet.prototype.getPath = async function getPath(address) {
  const hash = Address.getHash(address, 'hex');
  return this.wdb.getPath(this.wid, hash);
};

/**
 * Get path by address hash (without account name).
 * @private
 * @param {Address|Hash} address
 * @returns {Promise} - Returns {@link Path}.
 */

Wallet.prototype.readPath = async function readPath(address) {
  const hash = Address.getHash(address, 'hex');
  return this.wdb.readPath(this.wid, hash);
};

/**
 * Test whether the wallet contains a path.
 * @param {Address|Hash} address
 * @returns {Promise} - Returns {Boolean}.
 */

Wallet.prototype.hasPath = async function hasPath(address) {
  const hash = Address.getHash(address, 'hex');
  return await this.wdb.hasPath(this.wid, hash);
};

/**
 * Get all wallet paths.
 * @param {(String|Number)?} acct
 * @returns {Promise} - Returns {@link Path}.
 */

Wallet.prototype.getPaths = async function getPaths(acct) {
  if (acct != null)
    return await this.getAccountPaths(acct);

  const paths = await this.wdb.getWalletPaths(this.wid);
  const result = [];

  for (const path of paths) {
    path.name = await this.getAccountName(path.account);

    assert(path.name);

    result.push(path);
  }

  return result;
};

/**
 * Get all account paths.
 * @param {String|Number} acct
 * @returns {Promise} - Returns {@link Path}.
 */

Wallet.prototype.getAccountPaths = async function getAccountPaths(acct) {
  const index = await this.getAccountIndex(acct);

  if (index === -1)
    throw new Error('Account not found.');

  const hashes = await this.getAccountHashes(index);
  const name = await this.getAccountName(acct);

  assert(name);

  const result = [];

  for (const hash of hashes) {
    const path = await this.readPath(hash);

    assert(path);
    assert(path.account === index);

    path.name = name;

    result.push(path);
  }

  return result;
};

/**
 * Import a keyring (will not exist on derivation chain).
 * Rescanning must be invoked manually.
 * @param {(String|Number)?} acct
 * @param {WalletKey} ring
 * @param {(String|Buffer)?} passphrase
 * @returns {Promise}
 */

Wallet.prototype.importKey = async function importKey(acct, ring, passphrase) {
  const unlock = await this.writeLock.lock();
  try {
    return await this._importKey(acct, ring, passphrase);
  } finally {
    unlock();
  }
};

/**
 * Import a keyring (will not exist on derivation chain) without a lock.
 * @private
 * @param {(String|Number)?} acct
 * @param {WalletKey} ring
 * @param {(String|Buffer)?} passphrase
 * @returns {Promise}
 */

Wallet.prototype._importKey = async function _importKey(acct, ring, passphrase) {
  assert(ring.network === this.network,
    'Network mismatch for key.');

  if (!this.watchOnly) {
    if (!ring.privateKey)
      throw new Error('Cannot import pubkey into non watch-only wallet.');
  } else {
    if (ring.privateKey)
      throw new Error('Cannot import privkey into watch-only wallet.');
  }

  const hash = ring.getHash('hex');

  if (await this.getPath(hash))
    throw new Error('Key already exists.');

  const account = await this.getAccount(acct);

  if (!account)
    throw new Error('Account not found.');

  if (account.type !== Account.types.PUBKEYHASH)
    throw new Error('Cannot import into non-pkh account.');

  await this.unlock(passphrase);

  const key = WalletKey.fromRing(account, ring);
  const path = key.toPath();

  if (this.master.encrypted) {
    path.data = this.master.encipher(path.data, path.hash);
    assert(path.data);
    path.encrypted = true;
  }

  const b = this.db.batch();
  await account.savePath(b, path);
  await b.write();
};

/**
 * Import a keyring (will not exist on derivation chain).
 * Rescanning must be invoked manually.
 * @param {(String|Number)?} acct
 * @param {WalletKey} ring
 * @param {(String|Buffer)?} passphrase
 * @returns {Promise}
 */

Wallet.prototype.importAddress = async function importAddress(acct, address) {
  const unlock = await this.writeLock.lock();
  try {
    return await this._importAddress(acct, address);
  } finally {
    unlock();
  }
};

/**
 * Import a keyring (will not exist on derivation chain) without a lock.
 * @private
 * @param {(String|Number)?} acct
 * @param {WalletKey} ring
 * @param {(String|Buffer)?} passphrase
 * @returns {Promise}
 */

Wallet.prototype._importAddress = async function _importAddress(acct, address) {
  assert(address.network === this.network,
    'Network mismatch for address.');

  if (!this.watchOnly)
    throw new Error('Cannot import address into non watch-only wallet.');

  if (await this.getPath(address))
    throw new Error('Address already exists.');

  const account = await this.getAccount(acct);

  if (!account)
    throw new Error('Account not found.');

  if (account.type !== Account.types.PUBKEYHASH)
    throw new Error('Cannot import into non-pkh account.');

  const path = Path.fromAddress(account, address);

  const b = this.db.batch();
  await account.savePath(b, path);
  await b.write();
};

/**
 * Fill a transaction with inputs, estimate
 * transaction size, calculate fee, and add a change output.
 * @see MTX#selectCoins
 * @see MTX#fill
 * @param {MTX} mtx - _Must_ be a mutable transaction.
 * @param {Object?} options
 * @param {(String|Number)?} options.account - If no account is
 * specified, coins from the entire wallet will be filled.
 * @param {String?} options.selection - Coin selection priority. Can
 * be `age`, `random`, or `all`. (default=age).
 * @param {Boolean} options.round - Whether to round to the nearest
 * kilobyte for fee calculation.
 * See {@link TX#getMinFee} vs. {@link TX#getRoundFee}.
 * @param {Rate} options.rate - Rate used for fee calculation.
 * @param {Boolean} options.confirmed - Select only confirmed coins.
 * @param {Boolean} options.free - Do not apply a fee if the
 * transaction priority is high enough to be considered free.
 * @param {Amount?} options.hardFee - Use a hard fee rather than
 * calculating one.
 * @param {Number|Boolean} options.subtractFee - Whether to subtract the
 * fee from existing outputs rather than adding more inputs.
 */

Wallet.prototype.fund = async function fund(mtx, options, force) {
  const unlock = await this.fundLock.lock(force);
  try {
    return await this._fund(mtx, options);
  } finally {
    unlock();
  }
};

/**
 * Fill a transaction with inputs without a lock.
 * @private
 * @see MTX#selectCoins
 * @see MTX#fill
 */

Wallet.prototype._fund = async function _fund(mtx, options) {
  if (!options)
    options = {};

  if (!this.initialized)
    throw new Error('Wallet is not initialized.');

  if (this.watchOnly)
    throw new Error('Cannot fund from watch-only wallet.');

  const acct = options.account || 0;
  const change = await this.changeAddress(acct);

  if (!change)
    throw new Error('Account not found.');

  let rate = options.rate;
  if (rate == null)
    rate = await this.wdb.estimateFee(options.blocks);

  let coins;
  if (options.smart) {
    coins = await this.getSmartCoins(options.account);
  } else {
    coins = await this.getCoins(options.account);
    coins = this.txdb.filterLocked(coins);
  }

  await mtx.fund(coins, {
    selection: options.selection,
    round: options.round,
    depth: options.depth,
    hardFee: options.hardFee,
    subtractFee: options.subtractFee,
    subtractIndex: options.subtractIndex,
    changeAddress: change,
    height: this.wdb.state.height,
    rate: rate,
    maxFee: options.maxFee,
    estimate: prev => this.estimateSize(prev)
  });

  assert(mtx.getFee() <= MTX.Selector.MAX_FEE, 'TX exceeds MAX_FEE.');
};

/**
 * Get account by address.
 * @param {Address} address
 * @returns {Account}
 */

Wallet.prototype.getAccountByAddress = async function getAccountByAddress(address) {
  const hash = Address.getHash(address, 'hex');
  const path = await this.getPath(hash);

  if (!path)
    return null;

  return await this.getAccount(path.account);
};

/**
 * Input size estimator for max possible tx size.
 * @param {Script} prev
 * @returns {Number}
 */

Wallet.prototype.estimateSize = async function estimateSize(prev) {
  const scale = consensus.WITNESS_SCALE_FACTOR;
  const address = prev.getAddress();

  if (!address)
    return -1;

  const account = await this.getAccountByAddress(address);

  if (!account)
    return -1;

  let size = 0;

  if (prev.isScripthash()) {
    // Nested bullshit.
    if (account.witness) {
      switch (account.type) {
        case Account.types.PUBKEYHASH:
          size += 23; // redeem script
          size *= 4; // vsize
          break;
        case Account.types.MULTISIG:
          size += 35; // redeem script
          size *= 4; // vsize
          break;
      }
    }
  }

  switch (account.type) {
    case Account.types.PUBKEYHASH:
      // P2PKH
      // OP_PUSHDATA0 [signature]
      size += 1 + 73;
      // OP_PUSHDATA0 [key]
      size += 1 + 33;
      break;
    case Account.types.MULTISIG:
      // P2SH Multisig
      // OP_0
      size += 1;
      // OP_PUSHDATA0 [signature] ...
      size += (1 + 73) * account.m;
      // OP_PUSHDATA2 [redeem]
      size += 3;
      // m value
      size += 1;
      // OP_PUSHDATA0 [key] ...
      size += (1 + 33) * account.n;
      // n value
      size += 1;
      // OP_CHECKMULTISIG
      size += 1;
      break;
  }

  if (account.witness) {
    // Varint witness items length.
    size += 1;
    // Calculate vsize if
    // we're a witness program.
    size = (size + scale - 1) / scale | 0;
  } else {
    // Byte for varint
    // size of input script.
    size += encoding.sizeVarint(size);
  }

  return size;
};

/**
 * Build a transaction, fill it with outputs and inputs,
 * sort the members according to BIP69 (set options.sort=false
 * to avoid sorting), set locktime, and template it.
 * @param {Object} options - See {@link Wallet#fund options}.
 * @param {Object[]} options.outputs - See {@link MTX#addOutput}.
 * @returns {Promise} - Returns {@link MTX}.
 */

Wallet.prototype.createTX = async function createTX(options, force) {
  const outputs = options.outputs;
  const mtx = new MTX();

  assert(Array.isArray(outputs), 'Outputs must be an array.');
  assert(outputs.length > 0, 'No outputs available.');

  // Add the outputs
  for (const obj of outputs) {
    const output = new Output(obj);
    const addr = output.getAddress();

    if (output.isDust())
      throw new Error('Output is dust.');

    if (output.value > 0) {
      if (!addr)
        throw new Error('Cannot send to unknown address.');

      if (addr.isNull())
        throw new Error('Cannot send to null address.');
    }

    mtx.outputs.push(output);
  }

  // Fill the inputs with unspents
  await this.fund(mtx, options, force);

  // Sort members a la BIP69
  if (options.sort !== false)
    mtx.sortMembers();

  // Set the locktime to target value.
  if (options.locktime != null)
    mtx.setLocktime(options.locktime);

  // Consensus sanity checks.
  assert(mtx.isSane(), 'TX failed sanity check.');
  assert(mtx.verifyInputs(this.wdb.state.height + 1),
    'TX failed context check.');

  const total = await this.template(mtx);

  if (total === 0)
    throw new Error('Templating failed.');

  return mtx;
};

/**
 * Build a transaction, fill it with outputs and inputs,
 * sort the members according to BIP69, set locktime,
 * sign and broadcast. Doing this all in one go prevents
 * coins from being double spent.
 * @param {Object} options - See {@link Wallet#fund options}.
 * @param {Object[]} options.outputs - See {@link MTX#addOutput}.
 * @returns {Promise} - Returns {@link TX}.
 */

Wallet.prototype.send = async function send(options, passphrase) {
  const unlock = await this.fundLock.lock();
  try {
    return await this._send(options, passphrase);
  } finally {
    unlock();
  }
};

/**
 * Build and send a transaction without a lock.
 * @private
 * @param {Object} options - See {@link Wallet#fund options}.
 * @param {Object[]} options.outputs - See {@link MTX#addOutput}.
 * @returns {Promise} - Returns {@link TX}.
 */

Wallet.prototype._send = async function _send(options, passphrase) {
  const mtx = await this.createTX(options, true);

  await this.sign(mtx, passphrase);

  if (!mtx.isSigned())
    throw new Error('TX could not be fully signed.');

  const tx = mtx.toTX();

  // Policy sanity checks.
  if (tx.getSigopsCost(mtx.view) > policy.MAX_TX_SIGOPS_COST)
    throw new Error('TX exceeds policy sigops.');

  if (tx.getWeight() > policy.MAX_TX_WEIGHT)
    throw new Error('TX exceeds policy weight.');

  await this.wdb.addTX(tx);

  this.logger.debug('Sending wallet tx (%s): %s', this.id, tx.txid());

  await this.wdb.send(tx);

  return tx;
};

/**
 * Intentionally double-spend outputs by
 * increasing fee for an existing transaction.
 * @param {Hash} hash
 * @param {Rate} rate
 * @param {(String|Buffer)?} passphrase
 * @returns {Promise} - Returns {@link TX}.
 */

Wallet.prototype.increaseFee = async function increaseFee(hash, rate, passphrase) {
  assert(util.isU32(rate), 'Rate must be a number.');

  const wtx = await this.getTX(hash);

  if (!wtx)
    throw new Error('Transaction not found.');

  if (wtx.height !== -1)
    throw new Error('Transaction is confirmed.');

  const tx = wtx.tx;

  if (tx.isCoinbase())
    throw new Error('Transaction is a coinbase.');

  const view = await this.getSpentView(tx);

  if (!tx.hasCoins(view))
    throw new Error('Not all coins available.');

  const oldFee = tx.getFee(view);

  let fee = tx.getMinFee(null, rate);

  if (fee > MTX.Selector.MAX_FEE)
    fee = MTX.Selector.MAX_FEE;

  if (oldFee >= fee)
    throw new Error('Fee is not increasing.');

  const mtx = MTX.fromTX(tx);
  mtx.view = view;

  for (const input of mtx.inputs) {
    input.script.clear();
    input.witness.clear();
  }

  let change;
  for (let i = 0; i < mtx.outputs.length; i++) {
    const output = mtx.outputs[i];
    const addr = output.getAddress();

    if (!addr)
      continue;

    const path = await this.getPath(addr);

    if (!path)
      continue;

    if (path.branch === 1) {
      change = output;
      mtx.changeIndex = i;
      break;
    }
  }

  if (!change)
    throw new Error('No change output.');

  change.value += oldFee;

  if (mtx.getFee() !== 0)
    throw new Error('Arithmetic error for change.');

  change.value -= fee;

  if (change.value < 0)
    throw new Error('Fee is too high.');

  if (change.isDust()) {
    mtx.outputs.splice(mtx.changeIndex, 1);
    mtx.changeIndex = -1;
  }

  await this.sign(mtx, passphrase);

  if (!mtx.isSigned())
    throw new Error('TX could not be fully signed.');

  const ntx = mtx.toTX();

  this.logger.debug(
    'Increasing fee for wallet tx (%s): %s',
    this.id, ntx.txid());

  await this.wdb.addTX(ntx);
  await this.wdb.send(ntx);

  return ntx;
};

/**
 * Resend pending wallet transactions.
 * @returns {Promise}
 */

Wallet.prototype.resend = async function resend() {
  const wtxs = await this.getPending();

  if (wtxs.length > 0)
    this.logger.info('Rebroadcasting %d transactions.', wtxs.length);

  const txs = [];

  for (const wtx of wtxs)
    txs.push(wtx.tx);

  const sorted = common.sortDeps(txs);

  for (const tx of sorted)
    await this.wdb.send(tx);

  return txs;
};

/**
 * Derive necessary addresses for signing a transaction.
 * @param {MTX} mtx
 * @param {Number?} index - Input index.
 * @returns {Promise} - Returns {@link WalletKey}[].
 */

Wallet.prototype.deriveInputs = async function deriveInputs(mtx) {
  assert(mtx.mutable);

  const paths = await this.getInputPaths(mtx);
  const rings = [];

  for (const path of paths) {
    const account = await this.getAccount(path.account);

    if (!account)
      continue;

    const ring = account.derivePath(path, this.master);

    if (ring)
      rings.push(ring);
  }

  return rings;
};

/**
 * Retrieve a single keyring by address.
 * @param {Address|Hash} hash
 * @returns {Promise}
 */

Wallet.prototype.getKey = async function getKey(address) {
  const hash = Address.getHash(address, 'hex');
  const path = await this.getPath(hash);

  if (!path)
    return null;

  const account = await this.getAccount(path.account);

  if (!account)
    return null;

  return account.derivePath(path, this.master);
};

/**
 * Retrieve a single keyring by address
 * (with the private key reference).
 * @param {Address|Hash} hash
 * @param {(Buffer|String)?} passphrase
 * @returns {Promise}
 */

Wallet.prototype.getPrivateKey = async function getPrivateKey(address, passphrase) {
  const hash = Address.getHash(address, 'hex');
  const path = await this.getPath(hash);

  if (!path)
    return null;

  const account = await this.getAccount(path.account);

  if (!account)
    return null;

  await this.unlock(passphrase);

  const key = account.derivePath(path, this.master);

  if (!key.privateKey)
    return null;

  return key;
};

/**
 * Map input addresses to paths.
 * @param {MTX} mtx
 * @returns {Promise} - Returns {@link Path}[].
 */

Wallet.prototype.getInputPaths = async function getInputPaths(mtx) {
  assert(mtx.mutable);

  if (!mtx.hasCoins())
    throw new Error('Not all coins available.');

  const hashes = mtx.getInputHashes('hex');
  const paths = [];

  for (const hash of hashes) {
    const path = await this.getPath(hash);
    if (path)
      paths.push(path);
  }

  return paths;
};

/**
 * Map output addresses to paths.
 * @param {TX} tx
 * @returns {Promise} - Returns {@link Path}[].
 */

Wallet.prototype.getOutputPaths = async function getOutputPaths(tx) {
  const paths = [];
  const hashes = tx.getOutputHashes('hex');

  for (const hash of hashes) {
    const path = await this.getPath(hash);
    if (path)
      paths.push(path);
  }

  return paths;
};

/**
 * Increase lookahead for account.
 * @param {(Number|String)?} account
 * @param {Number} lookahead
 * @returns {Promise}
 */

Wallet.prototype.setLookahead = async function setLookahead(acct, lookahead) {
  const unlock = await this.writeLock.lock();
  try {
    return this._setLookahead(acct, lookahead);
  } finally {
    unlock();
  }
};

/**
 * Increase lookahead for account (without a lock).
 * @private
 * @param {(Number|String)?} account
 * @param {Number} lookahead
 * @returns {Promise}
 */

Wallet.prototype._setLookahead = async function _setLookahead(acct, lookahead) {
  const account = await this.getAccount(acct);

  if (!account)
    throw new Error('Account not found.');

  const b = this.db.batch();
  await account.setLookahead(b, lookahead);
  await b.write();
};

/**
 * Sync address depths based on a transaction's outputs.
 * This is used for deriving new addresses when
 * a confirmed transaction is seen.
 * @param {TX} tx
 * @returns {Promise}
 */

Wallet.prototype.syncOutputDepth = async function syncOutputDepth(tx) {
  const map = new Map();

  for (const hash of tx.getOutputHashes('hex')) {
    const path = await this.readPath(hash);

    if (!path)
      continue;

    if (path.index === -1)
      continue;

    if (!map.has(path.account))
      map.set(path.account, []);

    map.get(path.account).push(path);
  }

  const derived = [];
  const b = this.db.batch();

  for (const [acct, paths] of map) {
    let receive = -1;
    let change = -1;
    let nested = -1;

    for (const path of paths) {
      switch (path.branch) {
        case 0:
          if (path.index > receive)
            receive = path.index;
          break;
        case 1:
          if (path.index > change)
            change = path.index;
          break;
        case 2:
          if (path.index > nested)
            nested = path.index;
          break;
      }
    }

    receive += 2;
    change += 2;
    nested += 2;

    const account = await this.getAccount(acct);
    assert(account);

    const ring = await account.syncDepth(b, receive, change, nested);

    if (ring)
      derived.push(ring);
  }

  await b.write();

  return derived;
};

/**
 * Build input scripts templates for a transaction (does not
 * sign, only creates signature slots). Only builds scripts
 * for inputs that are redeemable by this wallet.
 * @param {MTX} mtx
 * @returns {Promise} - Returns Number
 * (total number of scripts built).
 */

Wallet.prototype.template = async function template(mtx) {
  const rings = await this.deriveInputs(mtx);
  return mtx.template(rings);
};

/**
 * Build input scripts and sign inputs for a transaction. Only attempts
 * to build/sign inputs that are redeemable by this wallet.
 * @param {MTX} tx
 * @param {Object|String|Buffer} options - Options or passphrase.
 * @returns {Promise} - Returns Number (total number
 * of inputs scripts built and signed).
 */

Wallet.prototype.sign = async function sign(mtx, passphrase) {
  if (this.watchOnly)
    throw new Error('Cannot sign from a watch-only wallet.');

  await this.unlock(passphrase);

  const rings = await this.deriveInputs(mtx);

  return mtx.signAsync(rings, Script.hashType.ALL, this.wdb.workers);
};

/**
 * Get a coin viewpoint.
 * @param {TX} tx
 * @returns {Promise} - Returns {@link CoinView}.
 */

Wallet.prototype.getCoinView = function getCoinView(tx) {
  return this.txdb.getCoinView(tx);
};

/**
 * Get a historical coin viewpoint.
 * @param {TX} tx
 * @returns {Promise} - Returns {@link CoinView}.
 */

Wallet.prototype.getSpentView = function getSpentView(tx) {
  return this.txdb.getSpentView(tx);
};

/**
 * Convert transaction to transaction details.
 * @param {TXRecord} wtx
 * @returns {Promise} - Returns {@link Details}.
 */

Wallet.prototype.toDetails = function toDetails(wtx) {
  return this.txdb.toDetails(wtx);
};

/**
 * Get transaction details.
 * @param {Hash} hash
 * @returns {Promise} - Returns {@link Details}.
 */

Wallet.prototype.getDetails = function getDetails(hash) {
  return this.txdb.getDetails(hash);
};

/**
 * Get a coin from the wallet.
 * @param {Hash} hash
 * @param {Number} index
 * @returns {Promise} - Returns {@link Coin}.
 */

Wallet.prototype.getCoin = function getCoin(hash, index) {
  return this.txdb.getCoin(hash, index);
};

/**
 * Get a transaction from the wallet.
 * @param {Hash} hash
 * @returns {Promise} - Returns {@link TX}.
 */

Wallet.prototype.getTX = function getTX(hash) {
  return this.txdb.getTX(hash);
};

/**
 * List blocks for the wallet.
 * @returns {Promise} - Returns {@link BlockRecord}.
 */

Wallet.prototype.getBlocks = function getBlocks() {
  return this.txdb.getBlocks();
};

/**
 * Get a block from the wallet.
 * @param {Number} height
 * @returns {Promise} - Returns {@link BlockRecord}.
 */

Wallet.prototype.getBlock = function getBlock(height) {
  return this.txdb.getBlock(height);
};

/**
 * Add a transaction to the wallets TX history.
 * @param {TX} tx
 * @returns {Promise}
 */

Wallet.prototype.add = async function add(tx, block) {
  const unlock = await this.writeLock.lock();
  try {
    return await this._add(tx, block);
  } finally {
    unlock();
  }
};

/**
 * Add a transaction to the wallet without a lock.
 * Potentially resolves orphans.
 * @private
 * @param {TX} tx
 * @returns {Promise}
 */

Wallet.prototype._add = async function _add(tx, block) {
  const details = await this.txdb.add(tx, block);

  if (details) {
    const derived = await this.syncOutputDepth(tx);
    if (derived.length > 0) {
      this.wdb.emit('address', this.id, derived);
      this.emit('address', derived);
    }
  }

  return details;
};

/**
 * Revert a block.
 * @param {Number} height
 * @returns {Promise}
 */

Wallet.prototype.revert = async function revert(height) {
  const unlock = await this.writeLock.lock();
  try {
    return await this.txdb.revert(height);
  } finally {
    unlock();
  }
};

/**
 * Remove a wallet transaction.
 * @param {Hash} hash
 * @returns {Promise}
 */

Wallet.prototype.remove = async function remove(hash) {
  const unlock = await this.writeLock.lock();
  try {
    return await this.txdb.remove(hash);
  } finally {
    unlock();
  }
};

/**
 * Zap stale TXs from wallet.
 * @param {(Number|String)?} acct
 * @param {Number} age - Age threshold (unix time, default=72 hours).
 * @returns {Promise}
 */

Wallet.prototype.zap = async function zap(acct, age) {
  const unlock = await this.writeLock.lock();
  try {
    return await this._zap(acct, age);
  } finally {
    unlock();
  }
};

/**
 * Zap stale TXs from wallet without a lock.
 * @private
 * @param {(Number|String)?} acct
 * @param {Number} age
 * @returns {Promise}
 */

Wallet.prototype._zap = async function _zap(acct, age) {
  const account = await this.ensureIndex(acct);
  return await this.txdb.zap(account, age);
};

/**
 * Abandon transaction.
 * @param {Hash} hash
 * @returns {Promise}
 */

Wallet.prototype.abandon = async function abandon(hash) {
  const unlock = await this.writeLock.lock();
  try {
    return await this._abandon(hash);
  } finally {
    unlock();
  }
};

/**
 * Abandon transaction without a lock.
 * @private
 * @param {Hash} hash
 * @returns {Promise}
 */

Wallet.prototype._abandon = function _abandon(hash) {
  return this.txdb.abandon(hash);
};

/**
 * Lock a single coin.
 * @param {Coin|Outpoint} coin
 */

Wallet.prototype.lockCoin = function lockCoin(coin) {
  return this.txdb.lockCoin(coin);
};

/**
 * Unlock a single coin.
 * @param {Coin|Outpoint} coin
 */

Wallet.prototype.unlockCoin = function unlockCoin(coin) {
  return this.txdb.unlockCoin(coin);
};

/**
 * Test locked status of a single coin.
 * @param {Coin|Outpoint} coin
 */

Wallet.prototype.isLocked = function isLocked(coin) {
  return this.txdb.isLocked(coin);
};

/**
 * Return an array of all locked outpoints.
 * @returns {Outpoint[]}
 */

Wallet.prototype.getLocked = function getLocked() {
  return this.txdb.getLocked();
};

/**
 * Get all transactions in transaction history.
 * @param {(String|Number)?} acct
 * @returns {Promise} - Returns {@link TX}[].
 */

Wallet.prototype.getHistory = async function getHistory(acct) {
  const account = await this.ensureIndex(acct);
  return this.txdb.getHistory(account);
};

/**
 * Get all available coins.
 * @param {(String|Number)?} account
 * @returns {Promise} - Returns {@link Coin}[].
 */

Wallet.prototype.getCoins = async function getCoins(acct) {
  const account = await this.ensureIndex(acct);
  return await this.txdb.getCoins(account);
};

/**
 * Get all available credits.
 * @param {(String|Number)?} account
 * @returns {Promise} - Returns {@link Credit}[].
 */

Wallet.prototype.getCredits = async function getCredits(acct) {
  const account = await this.ensureIndex(acct);
  return await this.txdb.getCredits(account);
};

/**
 * Get "smart" coins.
 * @param {(String|Number)?} account
 * @returns {Promise} - Returns {@link Coin}[].
 */

Wallet.prototype.getSmartCoins = async function getSmartCoins(acct) {
  const credits = await this.getCredits(acct);
  const coins = [];

  for (const credit of credits) {
    const coin = credit.coin;

    if (credit.spent)
      continue;

    if (this.txdb.isLocked(coin))
      continue;

    // Always used confirmed coins.
    if (coin.height !== -1) {
      coins.push(coin);
      continue;
    }

    // Use unconfirmed only if they were
    // created as a result of one of our
    // _own_ transactions. i.e. they're
    // not low-fee and not in danger of
    // being double-spent by a bad actor.
    if (!credit.own)
      continue;

    coins.push(coin);
  }

  return coins;
};

/**
 * Get all pending/unconfirmed transactions.
 * @param {(String|Number)?} acct
 * @returns {Promise} - Returns {@link TX}[].
 */

Wallet.prototype.getPending = async function getPending(acct) {
  const account = await this.ensureIndex(acct);
  return await this.txdb.getPending(account);
};

/**
 * Get wallet balance.
 * @param {(String|Number)?} acct
 * @returns {Promise} - Returns {@link Balance}.
 */

Wallet.prototype.getBalance = async function getBalance(acct) {
  const account = await this.ensureIndex(acct);
  return await this.txdb.getBalance(account);
};

/**
 * Get a range of transactions between two timestamps.
 * @param {(String|Number)?} acct
 * @param {Object} options
 * @param {Number} options.start
 * @param {Number} options.end
 * @returns {Promise} - Returns {@link TX}[].
 */

Wallet.prototype.getRange = async function getRange(acct, options) {
  const account = await this.ensureIndex(acct);
  return await this.txdb.getRange(account, options);
};

/**
 * Get the last N transactions.
 * @param {(String|Number)?} acct
 * @param {Number} limit
 * @returns {Promise} - Returns {@link TX}[].
 */

Wallet.prototype.getLast = async function getLast(acct, limit) {
  const account = await this.ensureIndex(acct);
  return await this.txdb.getLast(account, limit);
};

/**
 * Get account key.
 * @param {Number} [acct=0]
 * @returns {HDPublicKey}
 */

Wallet.prototype.accountKey = async function accountKey(acct = 0) {
  const account = await this.getAccount(acct);
  if (!account)
    throw new Error('Account not found.');
  return account.accountKey;
};

/**
 * Get current receive depth.
 * @param {Number} [acct=0]
 * @returns {Number}
 */

Wallet.prototype.receiveDepth = async function receiveDepth(acct = 0) {
  const account = await this.getAccount(acct);
  if (!account)
    throw new Error('Account not found.');
  return account.receiveDepth;
};

/**
 * Get current change depth.
 * @param {Number} [acct=0]
 * @returns {Number}
 */

Wallet.prototype.changeDepth = async function changeDepth(acct = 0) {
  const account = await this.getAccount(acct);
  if (!account)
    throw new Error('Account not found.');
  return account.changeDepth;
};

/**
 * Get current nested depth.
 * @param {Number} [acct=0]
 * @returns {Number}
 */

Wallet.prototype.nestedDepth = async function nestedDepth(acct = 0) {
  const account = await this.getAccount(acct);
  if (!account)
    throw new Error('Account not found.');
  return account.nestedDepth;
};

/**
 * Get current receive address.
 * @param {Number} [acct=0]
 * @returns {Address}
 */

Wallet.prototype.receiveAddress = async function receiveAddress(acct = 0) {
  const account = await this.getAccount(acct);
  if (!account)
    throw new Error('Account not found.');
  return account.receiveAddress();
};

/**
 * Get current change address.
 * @param {Number} [acct=0]
 * @returns {Address}
 */

Wallet.prototype.changeAddress = async function changeAddress(acct = 0) {
  const account = await this.getAccount(acct);
  if (!account)
    throw new Error('Account not found.');
  return account.changeAddress();
};

/**
 * Get current nested address.
 * @param {Number} [acct=0]
 * @returns {Address}
 */

Wallet.prototype.nestedAddress = async function nestedAddress(acct = 0) {
  const account = await this.getAccount(acct);
  if (!account)
    throw new Error('Account not found.');
  return account.nestedAddress();
};

/**
 * Get current receive key.
 * @param {Number} [acct=0]
 * @returns {WalletKey}
 */

Wallet.prototype.receiveKey = async function receiveKey(acct = 0) {
  const account = await this.getAccount(acct);
  if (!account)
    throw new Error('Account not found.');
  return account.receiveKey();
};

/**
 * Get current change key.
 * @param {Number} [acct=0]
 * @returns {WalletKey}
 */

Wallet.prototype.changeKey = async function changeKey(acct = 0) {
  const account = await this.getAccount(acct);
  if (!account)
    throw new Error('Account not found.');
  return account.changeKey();
};

/**
 * Get current nested key.
 * @param {Number} [acct=0]
 * @returns {WalletKey}
 */

Wallet.prototype.nestedKey = async function nestedKey(acct = 0) {
  const account = await this.getAccount(acct);
  if (!account)
    throw new Error('Account not found.');
  return account.nestedKey();
};

/**
 * Convert the wallet to a more inspection-friendly object.
 * @returns {Object}
 */

Wallet.prototype.inspect = function inspect() {
  return {
    wid: this.wid,
    id: this.id,
    network: this.network.type,
    initialized: this.initialized,
    accountDepth: this.accountDepth,
    token: this.token.toString('hex'),
    tokenDepth: this.tokenDepth,
    master: this.master
  };
};

/**
 * Convert the wallet to an object suitable for
 * serialization.
 * @param {Boolean?} unsafe - Whether to include
 * the master key in the JSON.
 * @returns {Object}
 */

Wallet.prototype.toJSON = function toJSON(unsafe, balance) {
  return {
    network: this.network.type,
    wid: this.wid,
    id: this.id,
    initialized: this.initialized,
    watchOnly: this.watchOnly,
    accountDepth: this.accountDepth,
    token: this.token.toString('hex'),
    tokenDepth: this.tokenDepth,
    master: this.master.toJSON(unsafe),
    balance: balance ? balance.toJSON(true) : null
  };
};

/**
 * Calculate serialization size.
 * @returns {Number}
 */

Wallet.prototype.getSize = function getSize() {
  let size = 0;
  size += 50;
  size += encoding.sizeVarString(this.id, 'ascii');
  size += encoding.sizeVarlen(this.master.getSize());
  return size;
};

/**
 * Serialize the wallet.
 * @returns {Buffer}
 */

Wallet.prototype.toRaw = function toRaw() {
  const size = this.getSize();
  const bw = new StaticWriter(size);

  bw.writeU32(this.network.magic);
  bw.writeU32(this.wid);
  bw.writeVarString(this.id, 'ascii');
  bw.writeU8(this.initialized ? 1 : 0);
  bw.writeU8(this.watchOnly ? 1 : 0);
  bw.writeU32(this.accountDepth);
  bw.writeBytes(this.token);
  bw.writeU32(this.tokenDepth);
  bw.writeVarBytes(this.master.toRaw());

  return bw.render();
};

/**
 * Inject properties from serialized data.
 * @private
 * @param {Buffer} data
 */

Wallet.prototype.fromRaw = function fromRaw(data) {
  const br = new BufferReader(data);
  const network = Network.fromMagic(br.readU32());

  this.wid = br.readU32();
  this.id = br.readVarString('ascii');
  this.initialized = br.readU8() === 1;
  this.watchOnly = br.readU8() === 1;
  this.accountDepth = br.readU32();
  this.token = br.readBytes(32);
  this.tokenDepth = br.readU32();
  this.master.fromRaw(br.readVarBytes());

  assert(network === this.wdb.network, 'Wallet network mismatch.');

  return this;
};

/**
 * Instantiate a wallet from serialized data.
 * @param {Buffer} data
 * @returns {Wallet}
 */

Wallet.fromRaw = function fromRaw(wdb, data) {
  return new Wallet(wdb).fromRaw(data);
};

/**
 * Test an object to see if it is a Wallet.
 * @param {Object} obj
 * @returns {Boolean}
 */

Wallet.isWallet = function isWallet(obj) {
  return obj instanceof Wallet;
};

/*
 * Expose
 */

module.exports = Wallet;
