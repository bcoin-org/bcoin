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
const MappedLock = require('../utils/mappedlock');
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
const LRU = require('../utils/lru');
const policy = require('../protocol/policy');
const consensus = require('../protocol/consensus');
const Mnemonic = HD.Mnemonic;

/**
 * BIP44 Wallet
 * @alias module:wallet.Wallet
 * @constructor
 * @param {Object} options
 * @param {WalletDB} options.db
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
 * (default=account key "address").
 */

function Wallet(db, options) {
  if (!(this instanceof Wallet))
    return new Wallet(db, options);

  EventEmitter.call(this);

  assert(db, 'DB required.');

  this.db = db;
  this.network = db.network;
  this.logger = db.logger;
  this.readLock = new MappedLock();
  this.writeLock = new Lock();
  this.fundLock = new Lock();
  this.indexCache = new LRU(10000);
  this.accountCache = new LRU(10000);
  this.pathCache = new LRU(100000);
  this.current = null;

  this.wid = 0;
  this.id = null;
  this.initialized = false;
  this.watchOnly = false;
  this.accountDepth = 0;
  this.token = encoding.ZERO_HASH;
  this.tokenDepth = 0;
  this.master = new MasterKey();

  this.txdb = new TXDB(this);
  this.account = null;

  if (options)
    this.fromOptions(options);
}

util.inherits(Wallet, EventEmitter);

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
    assert(util.isNumber(options.wid));
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
    assert(util.isNumber(options.accountDepth));
    this.accountDepth = options.accountDepth;
  }

  if (options.token) {
    assert(Buffer.isBuffer(options.token));
    assert(options.token.length === 32);
    token = options.token;
  }

  if (options.tokenDepth != null) {
    assert(util.isNumber(options.tokenDepth));
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
 * @param {WalletDB} db
 * @param {Object} options
 * @returns {Wallet}
 */

Wallet.fromOptions = function fromOptions(db, options) {
  return new Wallet(db).fromOptions(options);
};

/**
 * Attempt to intialize the wallet (generating
 * the first addresses along with the lookahead
 * addresses). Called automatically from the
 * walletdb.
 * @returns {Promise}
 */

Wallet.prototype.init = async function init(options) {
  let passphrase = options.passphrase;
  let account;

  assert(!this.initialized);
  this.initialized = true;

  if (passphrase)
    await this.master.encrypt(passphrase);

  account = await this._createAccount(options, passphrase);
  assert(account);

  this.account = account;

  this.logger.info('Wallet initialized (%s).', this.id);

  await this.txdb.open();
};

/**
 * Open wallet (done after retrieval).
 * @returns {Promise}
 */

Wallet.prototype.open = async function open() {
  let account;

  assert(this.initialized);

  account = await this.getAccount(0);

  if (!account)
    throw new Error('Default account not found.');

  this.account = account;

  this.logger.info('Wallet opened (%s).', this.id);

  await this.txdb.open();
};

/**
 * Close the wallet, unregister with the database.
 * @returns {Promise}
 */

Wallet.prototype.destroy = async function destroy() {
  let unlock1 = await this.writeLock.lock();
  let unlock2 = await this.fundLock.lock();
  try {
    this.db.unregister(this);
    await this.master.destroy();
    this.readLock.destroy();
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
  let unlock = await this.writeLock.lock();
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

Wallet.prototype._addSharedKey = async function addSharedKey(acct, key) {
  let account, result;

  if (!key) {
    key = acct;
    acct = null;
  }

  if (acct == null)
    acct = 0;

  account = await this.getAccount(acct);

  if (!account)
    throw new Error('Account not found.');

  this.start();

  try {
    result = await account.addSharedKey(key);
  } catch (e) {
    this.drop();
    throw e;
  }

  await this.commit();

  return result;
};

/**
 * Remove a public account key from the wallet (multisig).
 * @param {(Number|String)} acct
 * @param {HDPublicKey} key
 * @returns {Promise}
 */

Wallet.prototype.removeSharedKey = async function removeSharedKey(acct, key) {
  let unlock = await this.writeLock.lock();
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

Wallet.prototype._removeSharedKey = async function removeSharedKey(acct, key) {
  let account, result;

  if (!key) {
    key = acct;
    acct = null;
  }

  if (acct == null)
    acct = 0;

  account = await this.getAccount(acct);

  if (!account)
    throw new Error('Account not found.');

  this.start();

  try {
    result = await account.removeSharedKey(key);
  } catch (e) {
    this.drop();
    throw e;
  }

  await this.commit();

  return result;
};

/**
 * Change or set master key's passphrase.
 * @param {(String|Buffer)?} old
 * @param {String|Buffer} new_
 * @returns {Promise}
 */

Wallet.prototype.setPassphrase = async function setPassphrase(old, new_) {
  if (new_ == null) {
    new_ = old;
    old = null;
  }

  if (old != null)
    await this.decrypt(old);

  if (new_ != null)
    await this.encrypt(new_);
};

/**
 * Encrypt the wallet permanently.
 * @param {String|Buffer} passphrase
 * @returns {Promise}
 */

Wallet.prototype.encrypt = async function encrypt(passphrase) {
  let unlock = await this.writeLock.lock();
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

Wallet.prototype._encrypt = async function encrypt(passphrase) {
  let key = await this.master.encrypt(passphrase, true);

  this.start();

  try {
    await this.db.encryptKeys(this, key);
  } catch (e) {
    cleanse(key);
    this.drop();
    throw e;
  }

  cleanse(key);

  this.save();

  await this.commit();
};

/**
 * Decrypt the wallet permanently.
 * @param {String|Buffer} passphrase
 * @returns {Promise}
 */

Wallet.prototype.decrypt = async function decrypt(passphrase) {
  let unlock = await this.writeLock.lock();
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

Wallet.prototype._decrypt = async function decrypt(passphrase) {
  let key = await this.master.decrypt(passphrase, true);

  this.start();

  try {
    await this.db.decryptKeys(this, key);
  } catch (e) {
    cleanse(key);
    this.drop();
    throw e;
  }

  cleanse(key);

  this.save();

  await this.commit();
};

/**
 * Generate a new token.
 * @param {(String|Buffer)?} passphrase
 * @returns {Promise}
 */

Wallet.prototype.retoken = async function retoken(passphrase) {
  let unlock = await this.writeLock.lock();
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

Wallet.prototype._retoken = async function retoken(passphrase) {
  await this.unlock(passphrase);

  this.tokenDepth++;
  this.token = this.getToken(this.tokenDepth);

  this.start();
  this.save();

  await this.commit();

  return this.token;
};

/**
 * Rename the wallet.
 * @param {String} id
 * @returns {Promise}
 */

Wallet.prototype.rename = async function rename(id) {
  let unlock = await this.writeLock.lock();
  try {
    return await this.db.rename(this, id);
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
  let unlock = await this.writeLock.lock();
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
  let account, old, paths;

  if (!common.isName(name))
    throw new Error('Bad account name.');

  account = await this.getAccount(acct);

  if (!account)
    throw new Error('Account not found.');

  if (account.accountIndex === 0)
    throw new Error('Cannot rename default account.');

  if (await this.hasAccount(name))
    throw new Error('Account name not available.');

  old = account.name;

  this.start();

  this.db.renameAccount(account, name);

  await this.commit();

  this.indexCache.remove(old);

  paths = this.pathCache.values();

  for (let path of paths) {
    if (path.account !== account.accountIndex)
      continue;

    path.name = name;
  }
};

/**
 * Lock the wallet, destroy decrypted key.
 */

Wallet.prototype.lock = async function lock() {
  let unlock1 = await this.writeLock.lock();
  let unlock2 = await this.fundLock.lock();
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
  let bw, key, hash;

  assert(this.master.key, 'Cannot derive id.');

  key = this.master.key.derive(44);

  bw = new StaticWriter(37);
  bw.writeBytes(key.publicKey);
  bw.writeU32(this.network.magic);

  hash = digest.hash160(bw.render());

  bw = new StaticWriter(27);
  bw.writeU8(0x03);
  bw.writeU8(0xbe);
  bw.writeU8(0x04);
  bw.writeBytes(hash);
  bw.writeChecksum();

  return base58.encode(bw.render());
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
  let bw, key;

  assert(this.master.key, 'Cannot derive token.');

  key = this.master.key.derive(44, true);

  bw = new StaticWriter(36);
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
  let unlock = await this.writeLock.lock();
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

Wallet.prototype._createAccount = async function createAccount(options, passphrase) {
  let name = options.name;
  let key, account, exists;

  if (!name)
    name = this.accountDepth + '';

  exists = await this.hasAccount(name);

  if (exists)
    throw new Error('Account already exists.');

  await this.unlock(passphrase);

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
    key = this.master.key.deriveAccount44(this.accountDepth);
    key = key.toPublic();
  }

  options = {
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

  this.start();

  try {
    account = Account.fromOptions(this.db, options);
    account.wallet = this;
    await account.init();
  } catch (e) {
    this.drop();
    throw e;
  }

  this.logger.info('Created account %s/%s/%d.',
    account.id,
    account.name,
    account.accountIndex);

  this.accountDepth++;
  this.save();

  await this.commit();

  return account;
};

/**
 * Ensure an account. Requires passphrase if master key is encrypted.
 * @param {Object} options - See {@link Account} options.
 * @returns {Promise} - Returns {@link Account}.
 */

Wallet.prototype.ensureAccount = async function ensureAccount(options, passphrase) {
  let name = options.name;
  let account = await this.getAccount(name);

  if (account)
    return account;

  return await this.createAccount(options, passphrase);
};

/**
 * List account names and indexes from the db.
 * @returns {Promise} - Returns Array.
 */

Wallet.prototype.getAccounts = function getAccounts() {
  return this.db.getAccounts(this.wid);
};

/**
 * Get all wallet address hashes.
 * @param {(String|Number)?} acct
 * @returns {Promise} - Returns Array.
 */

Wallet.prototype.getAddressHashes = function getAddressHashes(acct) {
  if (acct != null)
    return this.getAccountHashes(acct);
  return this.db.getWalletHashes(this.wid);
};

/**
 * Get all account address hashes.
 * @param {String|Number} acct
 * @returns {Promise} - Returns Array.
 */

Wallet.prototype.getAccountHashes = async function getAccountHashes(acct) {
  let index = await this.ensureIndex(acct, true);
  return await this.db.getAccountHashes(this.wid, index);
};

/**
 * Retrieve an account from the database.
 * @param {Number|String} acct
 * @returns {Promise} - Returns {@link Account}.
 */

Wallet.prototype.getAccount = async function getAccount(acct) {
  let index, unlock;

  if (this.account) {
    if (acct === 0 || acct === 'default')
      return this.account;
  }

  index = await this.getAccountIndex(acct);

  if (index === -1)
    return;

  unlock = await this.readLock.lock(index);

  try {
    return await this._getAccount(index);
  } finally {
    unlock();
  }
};

/**
 * Retrieve an account from the database without a lock.
 * @param {Number} index
 * @returns {Promise} - Returns {@link Account}.
 */

Wallet.prototype._getAccount = async function getAccount(index) {
  let account = this.accountCache.get(index);

  if (account)
    return account;

  account = await this.db.getAccount(this.wid, index);

  if (!account)
    return;

  account.wallet = this;
  account.wid = this.wid;
  account.id = this.id;
  account.watchOnly = this.watchOnly;

  await account.open();

  this.accountCache.set(index, account);

  return account;
};

/**
 * Lookup the corresponding account name's index.
 * @param {WalletID} wid
 * @param {String|Number} name - Account name/index.
 * @returns {Promise} - Returns Number.
 */

Wallet.prototype.getAccountIndex = async function getAccountIndex(name) {
  let index;

  if (name == null)
    return -1;

  if (typeof name === 'number')
    return name;

  index = this.indexCache.get(name);

  if (index != null)
    return index;

  index = await this.db.getAccountIndex(this.wid, name);

  if (index === -1)
    return -1;

  this.indexCache.set(name, index);

  return index;
};

/**
 * Lookup the corresponding account index's name.
 * @param {WalletID} wid
 * @param {Number} index - Account index.
 * @returns {Promise} - Returns String.
 */

Wallet.prototype.getAccountName = async function getAccountName(index) {
  let account;

  if (typeof index === 'string')
    return index;

  account = this.accountCache.get(index);

  if (account)
    return account.name;

  return await this.db.getAccountName(this.wid, index);
};

/**
 * Test whether an account exists.
 * @param {Number|String} acct
 * @returns {Promise} - Returns {@link Boolean}.
 */

Wallet.prototype.hasAccount = async function hasAccount(acct) {
  let index = await this.getAccountIndex(acct);

  if (index === -1)
    return false;

  if (this.accountCache.has(index))
    return true;

  return await this.db.hasAccount(this.wid, index);
};

/**
 * Create a new receiving address (increments receiveDepth).
 * @param {(Number|String)?} acct
 * @returns {Promise} - Returns {@link WalletKey}.
 */

Wallet.prototype.createReceive = function createReceive(acct) {
  return this.createKey(acct, 0);
};

/**
 * Create a new change address (increments receiveDepth).
 * @param {(Number|String)?} acct
 * @returns {Promise} - Returns {@link WalletKey}.
 */

Wallet.prototype.createChange = function createChange(acct) {
  return this.createKey(acct, 1);
};

/**
 * Create a new nested address (increments receiveDepth).
 * @param {(Number|String)?} acct
 * @returns {Promise} - Returns {@link WalletKey}.
 */

Wallet.prototype.createNested = function createNested(acct) {
  return this.createKey(acct, 2);
};

/**
 * Create a new address (increments depth).
 * @param {(Number|String)?} acct
 * @param {Number} branch
 * @returns {Promise} - Returns {@link WalletKey}.
 */

Wallet.prototype.createKey = async function createKey(acct, branch) {
  let unlock = await this.writeLock.lock();
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

Wallet.prototype._createKey = async function createKey(acct, branch) {
  let account, result;

  if (branch == null) {
    branch = acct;
    acct = null;
  }

  if (acct == null)
    acct = 0;

  account = await this.getAccount(acct);

  if (!account)
    throw new Error('Account not found.');

  this.start();

  try {
    result = await account.createKey(branch);
  } catch (e) {
    this.drop();
    throw e;
  }

  await this.commit();

  return result;
};

/**
 * Save the wallet to the database. Necessary
 * when address depth and keys change.
 * @returns {Promise}
 */

Wallet.prototype.save = function save() {
  return this.db.save(this);
};

/**
 * Start batch.
 * @private
 */

Wallet.prototype.start = function start() {
  return this.db.start(this);
};

/**
 * Drop batch.
 * @private
 */

Wallet.prototype.drop = function drop() {
  return this.db.drop(this);
};

/**
 * Clear batch.
 * @private
 */

Wallet.prototype.clear = function clear() {
  return this.db.clear(this);
};

/**
 * Save batch.
 * @returns {Promise}
 */

Wallet.prototype.commit = function commit() {
  return this.db.commit(this);
};

/**
 * Test whether the wallet possesses an address.
 * @param {Address|Hash} address
 * @returns {Promise} - Returns Boolean.
 */

Wallet.prototype.hasAddress = async function hasAddress(address) {
  let hash = Address.getHash(address, 'hex');
  let path = await this.getPath(hash);
  return path != null;
};

/**
 * Get path by address hash.
 * @param {Address|Hash} address
 * @returns {Promise} - Returns {@link Path}.
 */

Wallet.prototype.getPath = async function getPath(address) {
  let path = await this.readPath(address);

  if (!path)
    return;

  path.name = await this.getAccountName(path.account);

  assert(path.name);

  this.pathCache.set(path.hash, path);

  return path;
};

/**
 * Get path by address hash (without account name).
 * @private
 * @param {Address|Hash} address
 * @returns {Promise} - Returns {@link Path}.
 */

Wallet.prototype.readPath = async function readPath(address) {
  let hash = Address.getHash(address, 'hex');
  let path = this.pathCache.get(hash);

  if (path)
    return path;

  path = await this.db.getPath(this.wid, hash);

  if (!path)
    return;

  path.id = this.id;

  return path;
};

/**
 * Test whether the wallet contains a path.
 * @param {Address|Hash} address
 * @returns {Promise} - Returns {Boolean}.
 */

Wallet.prototype.hasPath = async function hasPath(address) {
  let hash = Address.getHash(address, 'hex');

  if (this.pathCache.has(hash))
    return true;

  return await this.db.hasPath(this.wid, hash);
};

/**
 * Get all wallet paths.
 * @param {(String|Number)?} acct
 * @returns {Promise} - Returns {@link Path}.
 */

Wallet.prototype.getPaths = async function getPaths(acct) {
  let paths, result;

  if (acct != null)
    return await this.getAccountPaths(acct);

  paths = await this.db.getWalletPaths(this.wid);
  result = [];

  for (let path of paths) {
    path.id = this.id;
    path.name = await this.getAccountName(path.account);

    assert(path.name);

    this.pathCache.set(path.hash, path);

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
  let index = await this.ensureIndex(acct, true);
  let hashes = await this.getAccountHashes(index);
  let name = await this.getAccountName(acct);
  let result = [];

  assert(name);

  for (let hash of hashes) {
    let path = await this.readPath(hash);

    assert(path);
    assert(path.account === index);

    path.name = name;

    this.pathCache.set(path.hash, path);

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
  let unlock = await this.writeLock.lock();
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

Wallet.prototype._importKey = async function importKey(acct, ring, passphrase) {
  let account, exists, path;

  if (acct && typeof acct === 'object') {
    passphrase = ring;
    ring = acct;
    acct = null;
  }

  if (acct == null)
    acct = 0;

  assert(ring.network === this.network,
    'Network mismatch for key.');

  if (!this.watchOnly) {
    if (!ring.privateKey)
      throw new Error('Cannot import pubkey into non watch-only wallet.');
  } else {
    if (ring.privateKey)
      throw new Error('Cannot import privkey into watch-only wallet.');
  }

  exists = await this.getPath(ring.getHash('hex'));

  if (exists)
    throw new Error('Key already exists.');

  account = await this.getAccount(acct);

  if (!account)
    throw new Error('Account not found.');

  if (account.type !== Account.types.PUBKEYHASH)
    throw new Error('Cannot import into non-pkh account.');

  await this.unlock(passphrase);

  ring = WalletKey.fromRing(account, ring);
  path = ring.toPath();

  if (this.master.encrypted) {
    path.data = this.master.encipher(path.data, path.hash);
    assert(path.data);
    path.encrypted = true;
  }

  this.start();

  try {
    await account.savePath(path);
  } catch (e) {
    this.drop();
    throw e;
  }

  await this.commit();
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
  let unlock = await this.writeLock.lock();
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

Wallet.prototype._importAddress = async function importAddress(acct, address) {
  let account, exists, path;

  if (!address) {
    address = acct;
    acct = null;
  }

  if (acct == null)
    acct = 0;

  assert(address.network === this.network,
    'Network mismatch for address.');

  if (!this.watchOnly)
    throw new Error('Cannot import address into non watch-only wallet.');

  exists = await this.getPath(address);

  if (exists)
    throw new Error('Address already exists.');

  account = await this.getAccount(acct);

  if (!account)
    throw new Error('Account not found.');

  if (account.type !== Account.types.PUBKEYHASH)
    throw new Error('Cannot import into non-pkh account.');

  path = Path.fromAddress(account, address);

  this.start();

  try {
    await account.savePath(path);
  } catch (e) {
    this.drop();
    throw e;
  }

  await this.commit();
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
  let unlock = await this.fundLock.lock(force);
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

Wallet.prototype._fund = async function fund(mtx, options) {
  let rate, account, coins;

  if (!options)
    options = {};

  if (!this.initialized)
    throw new Error('Wallet is not initialized.');

  if (this.watchOnly)
    throw new Error('Cannot fund from watch-only wallet.');

  if (options.account != null) {
    account = await this.getAccount(options.account);
    if (!account)
      throw new Error('Account not found.');
  } else {
    account = this.account;
  }

  if (!account.initialized)
    throw new Error('Account is not initialized.');

  rate = options.rate;

  if (rate == null)
    rate = await this.db.estimateFee(options.blocks);

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
    changeAddress: account.change.getAddress(),
    height: this.db.state.height,
    rate: rate,
    maxFee: options.maxFee,
    estimate: this.estimateSize.bind(this)
  });

  assert(mtx.getFee() <= MTX.Selector.MAX_FEE, 'TX exceeds MAX_FEE.');
};

/**
 * Get account by address.
 * @param {Address} address
 * @returns {Account}
 */

Wallet.prototype.getAccountByAddress = async function getAccountByAddress(address) {
  let hash = Address.getHash(address, 'hex');
  let path = await this.getPath(hash);

  if (!path)
    return;

  return await this.getAccount(path.account);
};

/**
 * Input size estimator for max possible tx size.
 * @param {Script} prev
 * @returns {Number}
 */

Wallet.prototype.estimateSize = async function estimateSize(prev) {
  let scale = consensus.WITNESS_SCALE_FACTOR;
  let address = prev.getAddress();
  let size = 0;
  let account;

  if (!address)
    return -1;

  account = await this.getAccountByAddress(address);

  if (!account)
    return -1;

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
  let outputs = options.outputs;
  let mtx = new MTX();
  let output, addr, total;

  assert(Array.isArray(outputs), 'Outputs must be an array.');
  assert(outputs.length > 0, 'No outputs available.');

  // Add the outputs
  for (output of outputs) {
    output = new Output(output);
    addr = output.getAddress();

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
  assert(mtx.verifyInputs(this.db.state.height + 1), 'TX failed context check.');

  total = await this.template(mtx);

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
  let unlock = await this.fundLock.lock();
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

Wallet.prototype._send = async function send(options, passphrase) {
  let mtx = await this.createTX(options, true);
  let tx;

  await this.sign(mtx, passphrase);

  if (!mtx.isSigned())
    throw new Error('TX could not be fully signed.');

  tx = mtx.toTX();

  // Policy sanity checks.
  if (tx.getSigopsCost(mtx.view) > policy.MAX_TX_SIGOPS_COST)
    throw new Error('TX exceeds policy sigops.');

  if (tx.getWeight() > policy.MAX_TX_WEIGHT)
    throw new Error('TX exceeds policy weight.');

  await this.db.addTX(tx);

  this.logger.debug('Sending wallet tx (%s): %s', this.id, tx.txid());

  await this.db.send(tx);

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
  let wtx = await this.getTX(hash);
  let tx, mtx, view, oldFee, fee, change;

  assert(util.isUInt32(rate), 'Rate must be a number.');

  if (!wtx)
    throw new Error('Transaction not found.');

  if (wtx.height !== -1)
    throw new Error('Transaction is confirmed.');

  tx = wtx.tx;

  if (tx.isCoinbase())
    throw new Error('Transaction is a coinbase.');

  view = await this.getSpentView(tx);

  if (!tx.hasCoins(view))
    throw new Error('Not all coins available.');

  oldFee = tx.getFee(view);
  fee = tx.getMinFee(null, rate);

  if (fee > MTX.Selector.MAX_FEE)
    fee = MTX.Selector.MAX_FEE;

  if (oldFee >= fee)
    throw new Error('Fee is not increasing.');

  mtx = MTX.fromTX(tx);
  mtx.view = view;

  for (let input of mtx.inputs) {
    input.script.length = 0;
    input.script.compile();
    input.witness.length = 0;
    input.witness.compile();
  }

  for (let i = 0; i < mtx.outputs.length; i++) {
    let output = mtx.outputs[i];
    let addr = output.getAddress();
    let path;

    if (!addr)
      continue;

    path = await this.getPath(addr);

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

  tx = mtx.toTX();

  this.logger.debug(
    'Increasing fee for wallet tx (%s): %s',
    this.id, tx.txid());

  await this.db.addTX(tx);
  await this.db.send(tx);

  return tx;
};

/**
 * Resend pending wallet transactions.
 * @returns {Promise}
 */

Wallet.prototype.resend = async function resend() {
  let wtxs = await this.getPending();
  let txs = [];

  if (wtxs.length > 0)
    this.logger.info('Rebroadcasting %d transactions.', wtxs.length);

  for (let wtx of wtxs)
    txs.push(wtx.tx);

  txs = common.sortDeps(txs);

  for (let tx of txs)
    await this.db.send(tx);

  return txs;
};

/**
 * Derive necessary addresses for signing a transaction.
 * @param {MTX} mtx
 * @param {Number?} index - Input index.
 * @returns {Promise} - Returns {@link WalletKey}[].
 */

Wallet.prototype.deriveInputs = async function deriveInputs(mtx) {
  let rings = [];
  let paths;

  assert(mtx.mutable);

  paths = await this.getInputPaths(mtx);

  for (let path of paths) {
    let account = await this.getAccount(path.account);
    let ring;

    if (!account)
      continue;

    ring = account.derivePath(path, this.master);

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
  let hash = Address.getHash(address, 'hex');
  let path = await this.getPath(hash);
  let account;

  if (!path)
    return;

  account = await this.getAccount(path.account);

  if (!account)
    return;

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
  let hash = Address.getHash(address, 'hex');
  let path = await this.getPath(hash);
  let account, key;

  if (!path)
    return;

  account = await this.getAccount(path.account);

  if (!account)
    return;

  await this.unlock(passphrase);

  key = account.derivePath(path, this.master);

  if (!key.privateKey)
    return;

  return key;
};

/**
 * Map input addresses to paths.
 * @param {MTX} mtx
 * @returns {Promise} - Returns {@link Path}[].
 */

Wallet.prototype.getInputPaths = async function getInputPaths(mtx) {
  let paths = [];
  let hashes;

  assert(mtx.mutable);

  if (!mtx.hasCoins())
    throw new Error('Not all coins available.');

  hashes = mtx.getInputHashes('hex');

  for (let hash of hashes) {
    let path = await this.getPath(hash);
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
  let paths = [];
  let hashes = tx.getOutputHashes('hex');

  for (let hash of hashes) {
    let path = await this.getPath(hash);
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
  let unlock = await this.writeLock.lock();
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

Wallet.prototype._setLookahead = async function setLookahead(acct, lookahead) {
  let account;

  if (lookahead == null) {
    lookahead = acct;
    acct = null;
  }

  if (acct == null)
    acct = 0;

  account = await this.getAccount(acct);

  if (!account)
    throw new Error('Account not found.');

  this.start();

  try {
    await account.setLookahead(lookahead);
  } catch (e) {
    this.drop();
    throw e;
  }

  await this.commit();
};

/**
 * Sync address depths based on a transaction's outputs.
 * This is used for deriving new addresses when
 * a confirmed transaction is seen.
 * @param {Details} details
 * @returns {Promise}
 */

Wallet.prototype.syncOutputDepth = async function syncOutputDepth(details) {
  let derived = [];
  let accounts = {};

  if (!details)
    return derived;

  for (let output of details.outputs) {
    let path = output.path;

    if (!path)
      continue;

    if (path.index === -1)
      continue;

    if (!accounts[path.account])
      accounts[path.account] = [];

    accounts[path.account].push(path);
  }

  accounts = util.values(accounts);

  for (let paths of accounts) {
    let acct = paths[0].account;
    let receive = -1;
    let change = -1;
    let nested = -1;
    let account, ring;

    for (let path of paths) {
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

    account = await this.getAccount(acct);
    assert(account);

    ring = await account.syncDepth(receive, change, nested);

    if (ring)
      derived.push(ring);
  }

  return derived;
};

/**
 * Get a redeem script or witness script by hash.
 * @param {Hash} hash - Can be a ripemd160 or a sha256.
 * @returns {Script}
 */

Wallet.prototype.getRedeem = async function getRedeem(hash) {
  let ring;

  if (typeof hash === 'string')
    hash = Buffer.from(hash, 'hex');

  ring = await this.getKey(hash.toString('hex'));

  if (!ring)
    return;

  return ring.getRedeem(hash);
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
  let rings = await this.deriveInputs(mtx);
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
  let rings;

  if (this.watchOnly)
    throw new Error('Cannot sign from a watch-only wallet.');

  await this.unlock(passphrase);

  rings = await this.deriveInputs(mtx);

  return await mtx.signAsync(rings, Script.hashType.ALL, this.db.workers);
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
  let unlock = await this.writeLock.lock();
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

Wallet.prototype._add = async function add(tx, block) {
  let details, derived;

  this.txdb.start();

  try {
    details = await this.txdb._add(tx, block);
    derived = await this.syncOutputDepth(details);
  } catch (e) {
    this.txdb.drop();
    throw e;
  }

  await this.txdb.commit();

  if (derived.length > 0) {
    this.db.emit('address', this.id, derived);
    this.emit('address', derived);
  }

  return details;
};

/**
 * Unconfirm a wallet transcation.
 * @param {Hash} hash
 * @returns {Promise}
 */

Wallet.prototype.unconfirm = async function unconfirm(hash) {
  let unlock = await this.writeLock.lock();
  try {
    return await this.txdb.unconfirm(hash);
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
  let unlock = await this.writeLock.lock();
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
  let unlock = await this.writeLock.lock();
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

Wallet.prototype._zap = async function zap(acct, age) {
  let account = await this.ensureIndex(acct);
  return await this.txdb.zap(account, age);
};

/**
 * Abandon transaction.
 * @param {Hash} hash
 * @returns {Promise}
 */

Wallet.prototype.abandon = async function abandon(hash) {
  let unlock = await this.writeLock.lock();
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

Wallet.prototype._abandon = function abandon(hash) {
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
  let account = await this.ensureIndex(acct);
  return this.txdb.getHistory(account);
};

/**
 * Get all available coins.
 * @param {(String|Number)?} account
 * @returns {Promise} - Returns {@link Coin}[].
 */

Wallet.prototype.getCoins = async function getCoins(acct) {
  let account = await this.ensureIndex(acct);
  return await this.txdb.getCoins(account);
};

/**
 * Get all available credits.
 * @param {(String|Number)?} account
 * @returns {Promise} - Returns {@link Credit}[].
 */

Wallet.prototype.getCredits = async function getCredits(acct) {
  let account = await this.ensureIndex(acct);
  return await this.txdb.getCredits(account);
};

/**
 * Get "smart" coins.
 * @param {(String|Number)?} account
 * @returns {Promise} - Returns {@link Coin}[].
 */

Wallet.prototype.getSmartCoins = async function getSmartCoins(acct) {
  let credits = await this.getCredits(acct);
  let coins = [];

  for (let credit of credits) {
    let coin = credit.coin;

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
  let account = await this.ensureIndex(acct);
  return await this.txdb.getPending(account);
};

/**
 * Get wallet balance.
 * @param {(String|Number)?} acct
 * @returns {Promise} - Returns {@link Balance}.
 */

Wallet.prototype.getBalance = async function getBalance(acct) {
  let account = await this.ensureIndex(acct);
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
  let account;
  if (acct && typeof acct === 'object') {
    options = acct;
    acct = null;
  }
  account = await this.ensureIndex(acct);
  return await this.txdb.getRange(account, options);
};

/**
 * Get the last N transactions.
 * @param {(String|Number)?} acct
 * @param {Number} limit
 * @returns {Promise} - Returns {@link TX}[].
 */

Wallet.prototype.getLast = async function getLast(acct, limit) {
  let account = await this.ensureIndex(acct);
  return await this.txdb.getLast(account, limit);
};

/**
 * Resolve account index.
 * @private
 * @param {(Number|String)?} acct
 * @param {Function} errback - Returns [Error].
 * @returns {Promise}
 */

Wallet.prototype.ensureIndex = async function ensureIndex(acct, enforce) {
  let index;

  if (acct == null) {
    if (enforce)
      throw new Error('No account provided.');
    return null;
  }

  index = await this.getAccountIndex(acct);

  if (index === -1)
    throw new Error('Account not found.');

  return index;
};

/**
 * Get current receive address.
 * @param {String?} enc - `"base58"` or `null`.
 * @returns {Address|Base58Address}
 */

Wallet.prototype.getAddress = function getAddress(enc) {
  return this.account.getAddress(enc);
};

/**
 * Get current receive address.
 * @param {String?} enc - `"base58"` or `null`.
 * @returns {Address|Base58Address}
 */

Wallet.prototype.getReceive = function getReceive(enc) {
  return this.account.getReceive(enc);
};

/**
 * Get current change address.
 * @param {String?} enc - `"base58"` or `null`.
 * @returns {Address|Base58Address}
 */

Wallet.prototype.getChange = function getChange(enc) {
  return this.account.getChange(enc);
};

/**
 * Get current nested address.
 * @param {String?} enc - `"base58"` or `null`.
 * @returns {Address|Base58Address}
 */

Wallet.prototype.getNested = function getNested(enc) {
  return this.account.getNested(enc);
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
    state: this.txdb.state ? this.txdb.state.toJSON(true) : null,
    master: this.master,
    account: this.account
  };
};

/**
 * Convert the wallet to an object suitable for
 * serialization.
 * @param {Boolean?} unsafe - Whether to include
 * the master key in the JSON.
 * @returns {Object}
 */

Wallet.prototype.toJSON = function toJSON(unsafe) {
  return {
    network: this.network.type,
    wid: this.wid,
    id: this.id,
    initialized: this.initialized,
    watchOnly: this.watchOnly,
    accountDepth: this.accountDepth,
    token: this.token.toString('hex'),
    tokenDepth: this.tokenDepth,
    state: this.txdb.state.toJSON(true),
    master: this.master.toJSON(unsafe),
    account: this.account.toJSON(true)
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
  let size = this.getSize();
  let bw = new StaticWriter(size);

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
  let br = new BufferReader(data);
  let network = Network.fromMagic(br.readU32());

  this.wid = br.readU32();
  this.id = br.readVarString('ascii');
  this.initialized = br.readU8() === 1;
  this.watchOnly = br.readU8() === 1;
  this.accountDepth = br.readU32();
  this.token = br.readBytes(32);
  this.tokenDepth = br.readU32();
  this.master.fromRaw(br.readVarBytes());

  assert(network === this.db.network, 'Wallet network mismatch.');

  return this;
};

/**
 * Instantiate a wallet from serialized data.
 * @param {Buffer} data
 * @returns {Wallet}
 */

Wallet.fromRaw = function fromRaw(db, data) {
  return new Wallet(db).fromRaw(data);
};

/**
 * Test an object to see if it is a Wallet.
 * @param {Object} obj
 * @returns {Boolean}
 */

Wallet.isWallet = function isWallet(obj) {
  return obj
    && typeof obj.accountDepth === 'number'
    && obj.template === 'function';
};

/*
 * Expose
 */

module.exports = Wallet;
