/*!
 * wallet.js - wallet object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var assert = require('assert');
var EventEmitter = require('events').EventEmitter;
var constants = require('../protocol/constants');
var Network = require('../protocol/network');
var util = require('../utils/util');
var Locker = require('../utils/locker');
var co = require('../utils/co');
var crypto = require('../crypto/crypto');
var btcutils = require('../btc/utils');
var BufferReader = require('../utils/reader');
var BufferWriter = require('../utils/writer');
var base58 = require('../utils/base58');
var TXDB = require('./txdb');
var Path = require('./path');
var common = require('./common');
var Address = require('../primitives/address');
var MTX = require('../primitives/mtx');
var WalletKey = require('./walletkey');
var HD = require('../hd/hd');
var Account = require('./account');
var MasterKey = require('./masterkey');
var LRU = require('../utils/lru');

/**
 * BIP44 Wallet
 * @exports Wallet
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
  this.readLock = new Locker.Mapped();
  this.writeLock = new Locker();
  this.fundLock = new Locker();
  this.indexCache = new LRU(10000);
  this.accountCache = new LRU(10000);
  this.pathCache = new LRU(100000);
  this.current = null;

  this.wid = 0;
  this.id = null;
  this.initialized = false;
  this.watchOnly = false;
  this.accountDepth = 0;
  this.token = constants.ZERO_HASH;
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
  var key = options.master;
  var id, token;

  if (MasterKey.isMasterKey(key)) {
    this.master.fromOptions(key);
  } else {
    if (!key)
      key = HD.fromMnemonic(null, this.network);

    if (HD.isBase58(key))
      key = HD.fromBase58(key);

    assert(HD.isPrivate(key),
      'Must create wallet with hd private key.');

    assert(key.network === this.network,
      'Network mismatch for master key.');

    this.master.fromKey(key);
  }

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

Wallet.prototype.init = co(function* init(options) {
  var passphrase = options.passphrase;
  var account;

  assert(!this.initialized);
  this.initialized = true;

  if (passphrase)
    yield this.master.encrypt(passphrase);

  account = yield this._createAccount(options, passphrase);
  assert(account);

  this.account = account;

  this.logger.info('Wallet initialized (%s).', this.id);

  yield this.txdb.open();
});

/**
 * Open wallet (done after retrieval).
 * @returns {Promise}
 */

Wallet.prototype.open = co(function* open() {
  var account;

  assert(this.initialized);

  account = yield this.getAccount(0);

  if (!account)
    throw new Error('Default account not found.');

  this.account = account;

  this.logger.info('Wallet opened (%s).', this.id);

  yield this.txdb.open();
});

/**
 * Close the wallet, unregister with the database.
 * @returns {Promise}
 */

Wallet.prototype.destroy = co(function* destroy() {
  var unlock1 = yield this.writeLock.lock();
  var unlock2 = yield this.fundLock.lock();
  try {
    this.db.unregister(this);
    yield this.master.destroy();
    this.readLock.destroy();
    this.writeLock.destroy();
    this.fundLock.destroy();
  } finally {
    unlock2();
    unlock1();
  }
});

/**
 * Add a public account key to the wallet (multisig).
 * Saves the key in the wallet database.
 * @param {(Number|String)} acct
 * @param {HDPublicKey} key
 * @returns {Promise}
 */

Wallet.prototype.addSharedKey = co(function* addSharedKey(acct, key) {
  var unlock = yield this.writeLock.lock();
  try {
    return yield this._addSharedKey(acct, key);
  } finally {
    unlock();
  }
});

/**
 * Add a public account key to the wallet without a lock.
 * @private
 * @param {(Number|String)} acct
 * @param {HDPublicKey} key
 * @returns {Promise}
 */

Wallet.prototype._addSharedKey = co(function* addSharedKey(acct, key) {
  var account, result;

  if (!key) {
    key = acct;
    acct = null;
  }

  if (acct == null)
    acct = 0;

  account = yield this.getAccount(acct);

  if (!account)
    throw new Error('Account not found.');

  this.start();

  try {
    result = yield account.addSharedKey(key);
  } catch (e) {
    this.drop();
    throw e;
  }

  yield this.commit();

  return result;
});

/**
 * Remove a public account key from the wallet (multisig).
 * @param {(Number|String)} acct
 * @param {HDPublicKey} key
 * @returns {Promise}
 */

Wallet.prototype.removeSharedKey = co(function* removeSharedKey(acct, key) {
  var unlock = yield this.writeLock.lock();
  try {
    return yield this._removeSharedKey(acct, key);
  } finally {
    unlock();
  }
});

/**
 * Remove a public account key from the wallet (multisig).
 * @private
 * @param {(Number|String)} acct
 * @param {HDPublicKey} key
 * @returns {Promise}
 */

Wallet.prototype._removeSharedKey = co(function* removeSharedKey(acct, key) {
  var account, result;

  if (!key) {
    key = acct;
    acct = null;
  }

  if (acct == null)
    acct = 0;

  account = yield this.getAccount(acct);

  if (!account)
    throw new Error('Account not found.');

  this.start();

  try {
    result = yield account.removeSharedKey(key);
  } catch (e) {
    this.drop();
    throw e;
  }

  yield this.commit();

  return result;
});

/**
 * Change or set master key's passphrase.
 * @param {(String|Buffer)?} old
 * @param {String|Buffer} new_
 * @returns {Promise}
 */

Wallet.prototype.setPassphrase = co(function* setPassphrase(old, new_) {
  if (new_ == null) {
    new_ = old;
    old = null;
  }

  if (old != null)
    yield this.decrypt(old);

  if (new_ != null)
    yield this.encrypt(new_);
});

/**
 * Encrypt the wallet permanently.
 * @param {String|Buffer} passphrase
 * @returns {Promise}
 */

Wallet.prototype.encrypt = co(function* encrypt(passphrase) {
  var unlock = yield this.writeLock.lock();
  try {
    return yield this._encrypt(passphrase);
  } finally {
    unlock();
  }
});

/**
 * Encrypt the wallet permanently, without a lock.
 * @private
 * @param {String|Buffer} passphrase
 * @returns {Promise}
 */

Wallet.prototype._encrypt = co(function* encrypt(passphrase) {
  var key = yield this.master.encrypt(passphrase, true);

  this.start();

  try {
    yield this.db.encryptKeys(this, key);
  } catch (e) {
    crypto.cleanse(key);
    this.drop();
    throw e;
  }

  crypto.cleanse(key);

  this.save();

  yield this.commit();
});

/**
 * Decrypt the wallet permanently.
 * @param {String|Buffer} passphrase
 * @returns {Promise}
 */

Wallet.prototype.decrypt = co(function* decrypt(passphrase) {
  var unlock = yield this.writeLock.lock();
  try {
    return yield this._decrypt(passphrase);
  } finally {
    unlock();
  }
});

/**
 * Decrypt the wallet permanently, without a lock.
 * @private
 * @param {String|Buffer} passphrase
 * @returns {Promise}
 */

Wallet.prototype._decrypt = co(function* decrypt(passphrase) {
  var key = yield this.master.decrypt(passphrase, true);

  this.start();

  try {
    yield this.db.decryptKeys(this, key);
  } catch (e) {
    crypto.cleanse(key);
    this.drop();
    throw e;
  }

  crypto.cleanse(key);

  this.save();

  yield this.commit();
});

/**
 * Generate a new token.
 * @param {(String|Buffer)?} passphrase
 * @returns {Promise}
 */

Wallet.prototype.retoken = co(function* retoken(passphrase) {
  var unlock = yield this.writeLock.lock();
  try {
    return yield this._retoken(passphrase);
  } finally {
    unlock();
  }
});

/**
 * Generate a new token without a lock.
 * @private
 * @param {(String|Buffer)?} passphrase
 * @returns {Promise}
 */

Wallet.prototype._retoken = co(function* retoken(passphrase) {
  yield this.unlock(passphrase);

  this.tokenDepth++;
  this.token = this.getToken(this.tokenDepth);

  this.start();
  this.save();

  yield this.commit();

  return this.token;
});

/**
 * Rename the wallet.
 * @param {String} id
 * @returns {Promise}
 */

Wallet.prototype.rename = co(function* rename(id) {
  var unlock = yield this.writeLock.lock();
  try {
    return yield this.db.rename(this, id);
  } finally {
    unlock();
  }
});

/**
 * Rename account.
 * @param {(String|Number)?} acct
 * @param {String} name
 * @returns {Promise}
 */

Wallet.prototype.renameAccount = co(function* renameAccount(acct, name) {
  var unlock = yield this.writeLock.lock();
  try {
    return yield this._renameAccount(acct, name);
  } finally {
    unlock();
  }
});

/**
 * Rename account without a lock.
 * @private
 * @param {(String|Number)?} acct
 * @param {String} name
 * @returns {Promise}
 */

Wallet.prototype._renameAccount = co(function* _renameAccount(acct, name) {
  var i, account, old, paths, path;

  if (!common.isName(name))
    throw new Error('Bad account name.');

  account = yield this.getAccount(acct);

  if (!account)
    throw new Error('Account not found.');

  if (account.accountIndex === 0)
    throw new Error('Cannot rename default account.');

  if (yield this.hasAccount(name))
    throw new Error('Account name not available.');

  old = account.name;

  this.start();

  this.db.renameAccount(account, name);

  yield this.commit();

  this.indexCache.remove(old);

  paths = this.pathCache.values();

  for (i = 0; i < paths.length; i++) {
    path = paths[i];

    if (path.account !== account.accountIndex)
      continue;

    path.name = name;
  }
});

/**
 * Lock the wallet, destroy decrypted key.
 */

Wallet.prototype.lock = co(function* lock() {
  var unlock1 = yield this.writeLock.lock();
  var unlock2 = yield this.fundLock.lock();
  try {
    yield this.master.lock();
  } finally {
    unlock2();
    unlock1();
  }
});

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
  var bw, key, hash;

  assert(this.master.key, 'Cannot derive id.');

  key = this.master.key.derive(44);

  bw = new BufferWriter();
  bw.writeBytes(key.publicKey);
  bw.writeU32(this.network.magic);

  hash = crypto.hash160(bw.render());

  bw = new BufferWriter();
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
  var bw, key;

  assert(this.master.key, 'Cannot derive token.');

  key = this.master.key.derive(44, true);

  bw = new BufferWriter();
  bw.writeBytes(key.privateKey);
  bw.writeU32(nonce);

  return crypto.hash256(bw.render());
};

/**
 * Create an account. Requires passphrase if master key is encrypted.
 * @param {Object} options - See {@link Account} options.
 * @returns {Promise} - Returns {@link Account}.
 */

Wallet.prototype.createAccount = co(function* createAccount(options, passphrase) {
  var unlock = yield this.writeLock.lock();
  try {
    return yield this._createAccount(options, passphrase);
  } finally {
    unlock();
  }
});

/**
 * Create an account without a lock.
 * @param {Object} options - See {@link Account} options.
 * @returns {Promise} - Returns {@link Account}.
 */

Wallet.prototype._createAccount = co(function* createAccount(options, passphrase) {
  var name = options.name;
  var key, account, exists;

  if (!name)
    name = this.accountDepth + '';

  exists = yield this.hasAccount(name);

  if (exists)
    throw new Error('Account already exists.');

  yield this.unlock(passphrase);

  if (this.watchOnly && options.accountKey) {
    key = options.accountKey;

    if (HD.isBase58(key))
      key = HD.fromBase58(key);

    if (!HD.isPublic(key))
      throw new Error('Must add HD public keys to watch only wallet.');

    assert(key.network === this.network,
      'Network mismatch for watch only key.');
  } else {
    assert(this.master.key);
    key = this.master.key.deriveAccount44(this.accountDepth);
    key = key.hdPublicKey;
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
    yield account.init();
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

  yield this.commit();

  return account;
});

/**
 * Ensure an account. Requires passphrase if master key is encrypted.
 * @param {Object} options - See {@link Account} options.
 * @returns {Promise} - Returns {@link Account}.
 */

Wallet.prototype.ensureAccount = co(function* ensureAccount(options, passphrase) {
  var name = options.name;
  var account = yield this.getAccount(name);

  if (account)
    return account;

  return yield this.createAccount(options, passphrase);
});

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

Wallet.prototype.getAccountHashes = co(function* getAccountHashes(acct) {
  var index = yield this.ensureIndex(acct, true);
  return yield this.db.getAccountHashes(this.wid, index);
});

/**
 * Retrieve an account from the database.
 * @param {Number|String} acct
 * @returns {Promise} - Returns {@link Account}.
 */

Wallet.prototype.getAccount = co(function* getAccount(acct) {
  var index, unlock;

  if (this.account) {
    if (acct === 0 || acct === 'default')
      return this.account;
  }

  index = yield this.getAccountIndex(acct);

  if (index === -1)
    return;

  unlock = yield this.readLock.lock(index);

  try {
    return yield this._getAccount(index);
  } finally {
    unlock();
  }
});

/**
 * Retrieve an account from the database without a lock.
 * @param {Number} index
 * @returns {Promise} - Returns {@link Account}.
 */

Wallet.prototype._getAccount = co(function* getAccount(index) {
  var account = this.accountCache.get(index);

  if (account)
    return account;

  account = yield this.db.getAccount(this.wid, index);

  if (!account)
    return;

  account.wallet = this;
  account.wid = this.wid;
  account.id = this.id;
  account.watchOnly = this.watchOnly;

  yield account.open();

  this.accountCache.set(index, account);

  return account;
});

/**
 * Lookup the corresponding account name's index.
 * @param {WalletID} wid
 * @param {String|Number} name - Account name/index.
 * @returns {Promise} - Returns Number.
 */

Wallet.prototype.getAccountIndex = co(function* getAccountIndex(name) {
  var index;

  if (name == null)
    return -1;

  if (typeof name === 'number')
    return name;

  index = this.indexCache.get(name);

  if (index != null)
    return index;

  index = yield this.db.getAccountIndex(this.wid, name);

  if (index === -1)
    return -1;

  this.indexCache.set(name, index);

  return index;
});

/**
 * Lookup the corresponding account index's name.
 * @param {WalletID} wid
 * @param {Number} index - Account index.
 * @returns {Promise} - Returns String.
 */

Wallet.prototype.getAccountName = co(function* getAccountName(index) {
  var account;

  if (typeof index === 'string')
    return index;

  account = this.accountCache.get(index);

  if (account)
    return account.name;

  return yield this.db.getAccountName(this.wid, index);
});

/**
 * Test whether an account exists.
 * @param {Number|String} acct
 * @returns {Promise} - Returns {@link Boolean}.
 */

Wallet.prototype.hasAccount = co(function* hasAccount(acct) {
  var index = yield this.getAccountIndex(acct);

  if (index === -1)
    return false;

  if (this.accountCache.has(index))
    return true;

  return yield this.db.hasAccount(this.wid, index);
});

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

Wallet.prototype.createKey = co(function* createKey(acct, branch) {
  var unlock = yield this.writeLock.lock();
  try {
    return yield this._createKey(acct, branch);
  } finally {
    unlock();
  }
});

/**
 * Create a new address (increments depth) without a lock.
 * @private
 * @param {(Number|String)?} acct
 * @param {Number} branche
 * @returns {Promise} - Returns {@link WalletKey}.
 */

Wallet.prototype._createKey = co(function* createKey(acct, branch) {
  var account, result;

  if (branch == null) {
    branch = acct;
    acct = null;
  }

  if (acct == null)
    acct = 0;

  account = yield this.getAccount(acct);

  if (!account)
    throw new Error('Account not found.');

  this.start();

  try {
    result = yield account.createKey(branch);
  } catch (e) {
    this.drop();
    throw e;
  }

  yield this.commit();

  return result;
});

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

Wallet.prototype.hasAddress = co(function* hasAddress(address) {
  var hash = Address.getHash(address, 'hex');
  var path;

  if (!hash)
    return false;

  path = yield this.getPath(hash);

  return path != null;
});

/**
 * Get path by address hash.
 * @param {Address|Hash} address
 * @returns {Promise} - Returns {@link Path}.
 */

Wallet.prototype.getPath = co(function* getPath(address) {
  var path = yield this.readPath(address);

  if (!path)
    return;

  path.name = yield this.getAccountName(path.account);

  assert(path.name);

  this.pathCache.set(path.hash, path);

  return path;
});

/**
 * Get path by address hash (without account name).
 * @private
 * @param {Address|Hash} address
 * @returns {Promise} - Returns {@link Path}.
 */

Wallet.prototype.readPath = co(function* readPath(address) {
  var hash = Address.getHash(address, 'hex');
  var path;

  if (!hash)
    return;

  path = this.pathCache.get(hash);

  if (path)
    return path;

  path = yield this.db.getPath(this.wid, hash);

  if (!path)
    return;

  path.id = this.id;

  return path;
});

/**
 * Test whether the wallet contains a path.
 * @param {Address|Hash} address
 * @returns {Promise} - Returns {Boolean}.
 */

Wallet.prototype.hasPath = co(function* hasPath(address) {
  var hash = Address.getHash(address, 'hex');

  if (!hash)
    return false;

  if (this.pathCache.has(hash))
    return true;

  return yield this.db.hasPath(this.wid, hash);
});

/**
 * Get all wallet paths.
 * @param {(String|Number)?} acct
 * @returns {Promise} - Returns {@link Path}.
 */

Wallet.prototype.getPaths = co(function* getPaths(acct) {
  var i, paths, path, result;

  if (acct != null)
    return yield this.getAccountPaths(acct);

  paths = yield this.db.getWalletPaths(this.wid);
  result = [];

  for (i = 0; i < paths.length; i++) {
    path = paths[i];
    path.id = this.id;
    path.name = yield this.getAccountName(path.account);

    assert(path.name);

    this.pathCache.set(path.hash, path);

    result.push(path);
  }

  return result;
});

/**
 * Get all account paths.
 * @param {String|Number} acct
 * @returns {Promise} - Returns {@link Path}.
 */

Wallet.prototype.getAccountPaths = co(function* getAccountPaths(acct) {
  var index = yield this.ensureIndex(acct, true);
  var hashes = yield this.getAccountHashes(index);
  var name = yield this.getAccountName(acct);
  var result = [];
  var i, hash, path;

  assert(name);

  for (i = 0; i < hashes.length; i++) {
    hash = hashes[i];
    path = yield this.readPath(hash);

    assert(path);
    assert(path.account === index);

    path.name = name;

    this.pathCache.set(path.hash, path);

    result.push(path);
  }

  return result;
});

/**
 * Import a keyring (will not exist on derivation chain).
 * Rescanning must be invoked manually.
 * @param {(String|Number)?} acct
 * @param {WalletKey} ring
 * @param {(String|Buffer)?} passphrase
 * @returns {Promise}
 */

Wallet.prototype.importKey = co(function* importKey(acct, ring, passphrase) {
  var unlock = yield this.writeLock.lock();
  try {
    return yield this._importKey(acct, ring, passphrase);
  } finally {
    unlock();
  }
});

/**
 * Import a keyring (will not exist on derivation chain) without a lock.
 * @private
 * @param {(String|Number)?} acct
 * @param {WalletKey} ring
 * @param {(String|Buffer)?} passphrase
 * @returns {Promise}
 */

Wallet.prototype._importKey = co(function* importKey(acct, ring, passphrase) {
  var account, exists, path;

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

  exists = yield this.getPath(ring.getHash('hex'));

  if (exists)
    throw new Error('Key already exists.');

  account = yield this.getAccount(acct);

  if (!account)
    throw new Error('Account not found.');

  if (account.type !== Account.types.PUBKEYHASH)
    throw new Error('Cannot import into non-pkh account.');

  yield this.unlock(passphrase);

  ring = WalletKey.fromRing(account, ring);
  path = ring.toPath();

  if (this.master.encrypted) {
    path.data = this.master.encipher(path.data, path.hash);
    assert(path.data);
    path.encrypted = true;
  }

  this.start();

  try {
    yield account.savePath(path);
  } catch (e) {
    this.drop();
    throw e;
  }

  yield this.commit();
});

/**
 * Import a keyring (will not exist on derivation chain).
 * Rescanning must be invoked manually.
 * @param {(String|Number)?} acct
 * @param {WalletKey} ring
 * @param {(String|Buffer)?} passphrase
 * @returns {Promise}
 */

Wallet.prototype.importAddress = co(function* importAddress(acct, address) {
  var unlock = yield this.writeLock.lock();
  try {
    return yield this._importAddress(acct, address);
  } finally {
    unlock();
  }
});

/**
 * Import a keyring (will not exist on derivation chain) without a lock.
 * @private
 * @param {(String|Number)?} acct
 * @param {WalletKey} ring
 * @param {(String|Buffer)?} passphrase
 * @returns {Promise}
 */

Wallet.prototype._importAddress = co(function* importAddress(acct, address) {
  var account, exists, path;

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

  exists = yield this.getPath(address);

  if (exists)
    throw new Error('Address already exists.');

  account = yield this.getAccount(acct);

  if (!account)
    throw new Error('Account not found.');

  if (account.type !== Account.types.PUBKEYHASH)
    throw new Error('Cannot import into non-pkh account.');

  path = Path.fromAddress(account, address);

  this.start();

  try {
    yield account.savePath(path);
  } catch (e) {
    this.drop();
    throw e;
  }

  yield this.commit();
});

/**
 * Fill a transaction with inputs, estimate
 * transaction size, calculate fee, and add a change output.
 * @see MTX#selectCoins
 * @see MTX#fill
 * @param {MTX} tx - _Must_ be a mutable transaction.
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

Wallet.prototype.fund = co(function* fund(tx, options, force) {
  var unlock = yield this.fundLock.lock(force);
  try {
    return yield this._fund(tx, options);
  } finally {
    unlock();
  }
});

/**
 * Fill a transaction with inputs without a lock.
 * @private
 * @see MTX#selectCoins
 * @see MTX#fill
 */

Wallet.prototype._fund = co(function* fund(tx, options) {
  var rate, account, coins;

  if (!options)
    options = {};

  if (!this.initialized)
    throw new Error('Wallet is not initialized.');

  if (this.watchOnly)
    throw new Error('Cannot fund from watch-only wallet.');

  if (options.account != null) {
    account = yield this.getAccount(options.account);
    if (!account)
      throw new Error('Account not found.');
  } else {
    account = this.account;
  }

  if (!account.initialized)
    throw new Error('Account is not initialized.');

  coins = yield this.getCoins(options.account);

  rate = options.rate;

  if (rate == null)
    rate = yield this.db.estimateFee();

  // Don't use any locked coins.
  coins = this.txdb.filterLocked(coins);

  tx.fund(coins, {
    selection: options.selection,
    round: options.round,
    confirmations: options.confirmations,
    free: options.free,
    hardFee: options.hardFee,
    subtractFee: options.subtractFee,
    changeAddress: account.change.getAddress(),
    height: this.db.state.height,
    rate: rate,
    maxFee: options.maxFee,
    m: account.m,
    n: account.n,
    witness: account.witness,
    script: account.receive.script
  });
});

/**
 * Build a transaction, fill it with outputs and inputs,
 * sort the members according to BIP69, set locktime,
 * and template it.
 * @param {Object} options - See {@link Wallet#fund options}.
 * @param {Object[]} options.outputs - See {@link MTX#addOutput}.
 * @returns {Promise} - Returns {@link MTX}.
 */

Wallet.prototype.createTX = co(function* createTX(options, force) {
  var outputs = options.outputs;
  var i, tx, total;

  if (!Array.isArray(outputs) || outputs.length === 0)
    throw new Error('No outputs.');

  // Create mutable tx
  tx = new MTX();

  // Add the outputs
  for (i = 0; i < outputs.length; i++) {
    tx.addOutput(outputs[i]);
    if (tx.outputs[i].isDust(constants.tx.MIN_RELAY))
      throw new Error('Output is dust.');
  }

  // Fill the inputs with unspents
  yield this.fund(tx, options, force);

  // Sort members a la BIP69
  tx.sortMembers();

  // Set the locktime to target value or
  // `height - whatever` to avoid fee sniping.
  // if (options.locktime != null)
  //   tx.setLocktime(options.locktime);
  // else
  //   tx.avoidFeeSniping(this.db.state.height);

  if (!tx.isSane())
    throw new Error('CheckTransaction failed.');

  if (!tx.checkInputs(this.db.state.height))
    throw new Error('CheckInputs failed.');

  total = yield this.template(tx);

  if (total === 0)
    throw new Error('Templating failed.');

  return tx;
});

/**
 * Build a transaction, fill it with outputs and inputs,
 * sort the members according to BIP69, set locktime,
 * sign and broadcast. Doing this all in one go prevents
 * coins from being double spent.
 * @param {Object} options - See {@link Wallet#fund options}.
 * @param {Object[]} options.outputs - See {@link MTX#addOutput}.
 * @returns {Promise} - Returns {@link TX}.
 */

Wallet.prototype.send = co(function* send(options, passphrase) {
  var unlock = yield this.fundLock.lock();
  try {
    return yield this._send(options, passphrase);
  } finally {
    unlock();
  }
});

/**
 * Build and send a transaction without a lock.
 * @private
 * @param {Object} options - See {@link Wallet#fund options}.
 * @param {Object[]} options.outputs - See {@link MTX#addOutput}.
 * @returns {Promise} - Returns {@link TX}.
 */

Wallet.prototype._send = co(function* send(options, passphrase) {
  var tx = yield this.createTX(options, true);

  yield this.sign(tx, passphrase);

  if (!tx.isSigned())
    throw new Error('TX could not be fully signed.');

  tx = tx.toTX();

  assert(tx.getFee() <= constants.tx.MAX_FEE, 'TX exceeds maxfee.');

  yield this.db.addTX(tx);

  this.logger.debug('Sending wallet tx (%s): %s', this.id, tx.rhash);

  yield this.db.send(tx);

  return tx;
});

/**
 * Intentionally double-spend outputs by
 * increasing fee for an existing transaction.
 * @param {Hash} hash
 * @param {Rate} rate
 * @param {(String|Buffer)?} passphrase
 * @returns {Promise} - Returns {@link TX}.
 */

Wallet.prototype.increaseFee = co(function* increaseFee(hash, rate, passphrase) {
  var tx = yield this.getTX(hash);
  var i, oldFee, fee, path, input, output, change;

  if (!tx)
    throw new Error('Transaction not found.');

  if (tx.isCoinbase())
    throw new Error('Transaction is a coinbase.');

  yield this.fillHistory(tx);

  if (!tx.hasCoins())
    throw new Error('Not all coins available.');

  if (!util.isUInt32(rate))
    throw new Error('Rate must be a number.');

  oldFee = tx.getFee();
  fee = tx.getMinFee(null, rate);

  if (fee > constants.tx.MAX_FEE)
    fee = constants.tx.MAX_FEE;

  if (oldFee >= fee)
    throw new Error('Fee is not increasing.');

  tx = MTX.fromRaw(tx.toRaw());

  for (i = 0; i < tx.inputs.length; i++) {
    input = tx.inputs[i];
    input.script.length = 0;
    input.script.compile();
    input.witness.length = 0;
    input.witness.compile();
  }

  for (i = 0; i < tx.outputs.length; i++) {
    output = tx.outputs[i];
    path = yield this.getPath(output.getAddress());

    if (!path)
      continue;

    if (path.branch === 1) {
      change = output;
      tx.changeIndex = i;
      break;
    }
  }

  if (!change)
    throw new Error('No change output.');

  change.value += oldFee;

  if (tx.getFee() !== 0)
    throw new Error('Arithmetic error for change.');

  change.value -= fee;

  if (change.value < 0)
    throw new Error('Fee is too high.');

  if (change.isDust(constants.tx.MIN_RELAY)) {
    tx.outputs.splice(tx.changeIndex, 1);
    tx.changeIndex = -1;
  }

  yield this.sign(tx, passphrase);

  if (!tx.isSigned())
    throw new Error('TX could not be fully signed.');

  tx = tx.toTX();

  this.logger.debug('Increasing fee for wallet tx (%s): %s', this.id, tx.rhash);

  yield this.db.addTX(tx);
  yield this.db.send(tx);

  return tx;
});

/**
 * Resend pending wallet transactions.
 * @returns {Promise}
 */

Wallet.prototype.resend = co(function* resend() {
  var txs = yield this.getPending();
  var i;

  if (txs.length > 0)
    this.logger.info('Rebroadcasting %d transactions.', txs.length);

  txs = btcutils.sortTX(txs);

  for (i = 0; i < txs.length; i++)
    yield this.db.send(txs[i]);

  return txs;
});

/**
 * Derive necessary addresses for signing a transaction.
 * @param {TX|Input} tx
 * @param {Number?} index - Input index.
 * @returns {Promise} - Returns {@link WalletKey}[].
 */

Wallet.prototype.deriveInputs = co(function* deriveInputs(tx) {
  var rings = [];
  var i, paths, path, account, ring;

  paths = yield this.getInputPaths(tx);

  for (i = 0; i < paths.length; i++) {
    path = paths[i];
    account = yield this.getAccount(path.account);

    if (!account)
      continue;

    ring = account.derivePath(path, this.master);

    if (ring)
      rings.push(ring);
  }

  return rings;
});

/**
 * Retrieve a single keyring by address.
 * @param {Address|Hash} hash
 * @returns {Promise}
 */

Wallet.prototype.getKey = co(function* getKey(address) {
  var hash = Address.getHash(address, 'hex');
  var path, account;

  if (!hash)
    return;

  path = yield this.getPath(hash);

  if (!path)
    return;

  account = yield this.getAccount(path.account);

  if (!account)
    return;

  return account.derivePath(path, this.master);
});

/**
 * Retrieve a single keyring by address
 * (with the private key reference).
 * @param {Address|Hash} hash
 * @param {(Buffer|String)?} passphrase
 * @returns {Promise}
 */

Wallet.prototype.getPrivateKey = co(function* getPrivateKey(address, passphrase) {
  var hash = Address.getHash(address, 'hex');
  var path, account, key;

  if (!hash)
    return;

  path = yield this.getPath(hash);

  if (!path)
    return;

  account = yield this.getAccount(path.account);

  if (!account)
    return;

  yield this.unlock(passphrase);

  key = account.derivePath(path, this.master);

  if (!key.privateKey)
    return;

  return key;
});

/**
 * Map input addresses to paths.
 * @param {TX} tx
 * @returns {Promise} - Returns {@link Path}[].
 */

Wallet.prototype.getInputPaths = co(function* getInputPaths(tx) {
  var paths = [];
  var i, hashes, hash, path;

  yield this.fillCoins(tx);

  if (!tx.hasCoins())
    throw new Error('Not all coins available.');

  hashes = tx.getInputHashes('hex');

  for (i = 0; i < hashes.length; i++) {
    hash = hashes[i];
    path = yield this.getPath(hash);
    if (path)
      paths.push(path);
  }

  return paths;
});

/**
 * Map output addresses to paths.
 * @param {TX} tx
 * @returns {Promise} - Returns {@link Path}[].
 */

Wallet.prototype.getOutputPaths = co(function* getOutputPaths(tx) {
  var paths = [];
  var hashes = tx.getOutputHashes('hex');
  var i, hash, path;

  for (i = 0; i < hashes.length; i++) {
    hash = hashes[i];
    path = yield this.getPath(hash);
    if (path)
      paths.push(path);
  }

  return paths;
});

/**
 * Increase lookahead for account.
 * @param {(Number|String)?} account
 * @param {Number} lookahead
 * @returns {Promise}
 */

Wallet.prototype.setLookahead = co(function* setLookahead(acct, lookahead) {
  var unlock = yield this.writeLock.lock();
  try {
    return this._setLookahead(acct, lookahead);
  } finally {
    unlock();
  }
});

/**
 * Increase lookahead for account (without a lock).
 * @private
 * @param {(Number|String)?} account
 * @param {Number} lookahead
 * @returns {Promise}
 */

Wallet.prototype._setLookahead = co(function* setLookahead(acct, lookahead) {
  var account;

  if (lookahead == null) {
    lookahead = acct;
    acct = null;
  }

  if (acct == null)
    acct = 0;

  account = yield this.getAccount(acct);

  if (!account)
    throw new Error('Account not found.');

  this.start();

  try {
    yield account.setLookahead(lookahead);
  } catch (e) {
    this.drop();
    throw e;
  }

  yield this.commit();
});

/**
 * Sync address depths based on a transaction's outputs.
 * This is used for deriving new addresses when
 * a confirmed transaction is seen.
 * @param {Details} details
 * @returns {Promise}
 */

Wallet.prototype.syncOutputDepth = co(function* syncOutputDepth(details) {
  var derived = [];
  var accounts = {};
  var i, j, path, paths, acct, account;
  var receive, change, nested, ring;

  if (!details)
    return derived;

  for (i = 0; i < details.outputs.length; i++) {
    path = details.outputs[i].path;

    if (!path)
      continue;

    if (path.index === -1)
      continue;

    if (!accounts[path.account])
      accounts[path.account] = [];

    accounts[path.account].push(path);
  }

  accounts = util.values(accounts);

  for (i = 0; i < accounts.length; i++) {
    paths = accounts[i];
    acct = paths[0].account;
    receive = -1;
    change = -1;
    nested = -1;

    for (j = 0; j < paths.length; j++) {
      path = paths[j];

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

    account = yield this.getAccount(acct);
    assert(account);

    ring = yield account.syncDepth(receive, change, nested);

    if (ring)
      derived.push(ring);
  }

  return derived;
});

/**
 * Get a redeem script or witness script by hash.
 * @param {Hash} hash - Can be a ripemd160 or a sha256.
 * @returns {Script}
 */

Wallet.prototype.getRedeem = co(function* getRedeem(hash) {
  var ring;

  if (typeof hash === 'string')
    hash = new Buffer(hash, 'hex');

  ring = yield this.getKey(hash.toString('hex'));

  if (!ring)
    return;

  return ring.getRedeem(hash);
});

/**
 * Build input scripts templates for a transaction (does not
 * sign, only creates signature slots). Only builds scripts
 * for inputs that are redeemable by this wallet.
 * @param {MTX} tx
 * @returns {Promise} - Returns Number
 * (total number of scripts built).
 */

Wallet.prototype.template = co(function* template(tx) {
  var rings = yield this.deriveInputs(tx);
  return tx.template(rings);
});

/**
 * Build input scripts and sign inputs for a transaction. Only attempts
 * to build/sign inputs that are redeemable by this wallet.
 * @param {MTX} tx
 * @param {Object|String|Buffer} options - Options or passphrase.
 * @returns {Promise} - Returns Number (total number
 * of inputs scripts built and signed).
 */

Wallet.prototype.sign = co(function* sign(tx, passphrase) {
  var rings;

  if (this.watchOnly)
    throw new Error('Cannot sign from a watch-only wallet.');

  yield this.unlock(passphrase);

  rings = yield this.deriveInputs(tx);

  return yield tx.signAsync(rings);
});

/**
 * Fill transaction with coins.
 * @param {TX} tx
 * @returns {Promise} - Returns {@link TX}.
 */

Wallet.prototype.fillCoins = function fillCoins(tx) {
  return this.txdb.fillCoins(tx);
};

/**
 * Fill transaction with historical coins.
 * @param {TX} tx
 * @returns {Promise} - Returns {@link TX}.
 */

Wallet.prototype.fillHistory = function fillHistory(tx) {
  return this.txdb.fillHistory(tx);
};

/**
 * Convert transaction to transaction details.
 * @param {TX} tx
 * @returns {Promise} - Returns {@link Details}.
 */

Wallet.prototype.toDetails = function toDetails(tx) {
  return this.txdb.toDetails(tx);
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

Wallet.prototype.add = co(function* add(tx, block) {
  var unlock = yield this.writeLock.lock();
  try {
    return yield this._add(tx, block);
  } finally {
    unlock();
  }
});

/**
 * Add a transaction to the wallet without a lock.
 * Potentially resolves orphans.
 * @private
 * @param {TX} tx
 * @returns {Promise}
 */

Wallet.prototype._add = co(function* add(tx, block) {
  var resolved = yield this.txdb.resolve(tx, block);
  var result = false;
  var i, orphan;

  for (i = 0; i < resolved.length; i++) {
    orphan = resolved[i];
    if (yield this._insert(orphan.tx, orphan.block))
      result = true;
  }

  return result;
});

/**
 * Insert a transaction into the wallet (no lock).
 * @private
 * @param {TX} tx
 * @returns {Promise}
 */

Wallet.prototype._insert = co(function* insert(tx, block) {
  var details, derived;

  this.txdb.start();

  try {
    details = yield this.txdb._add(tx, block);
    derived = yield this.syncOutputDepth(details);
  } catch (e) {
    this.txdb.drop();
    throw e;
  }

  yield this.txdb.commit();

  if (derived.length > 0) {
    this.db.emit('address', this.id, derived);
    this.emit('address', derived);
  }

  return details;
});

/**
 * Unconfirm a wallet transcation.
 * @param {Hash} hash
 * @returns {Promise}
 */

Wallet.prototype.unconfirm = co(function* unconfirm(hash) {
  var unlock = yield this.writeLock.lock();
  try {
    return yield this.txdb.unconfirm(hash);
  } finally {
    unlock();
  }
});

/**
 * Remove a wallet transaction.
 * @param {Hash} hash
 * @returns {Promise}
 */

Wallet.prototype.remove = co(function* remove(hash) {
  var unlock = yield this.writeLock.lock();
  try {
    return yield this.txdb.remove(hash);
  } finally {
    unlock();
  }
});

/**
 * Zap stale TXs from wallet.
 * @param {(Number|String)?} acct
 * @param {Number} age - Age threshold (unix time, default=72 hours).
 * @returns {Promise}
 */

Wallet.prototype.zap = co(function* zap(acct, age) {
  var unlock = yield this.writeLock.lock();
  try {
    return yield this._zap(acct, age);
  } finally {
    unlock();
  }
});

/**
 * Zap stale TXs from wallet without a lock.
 * @private
 * @param {(Number|String)?} acct
 * @param {Number} age
 * @returns {Promise}
 */

Wallet.prototype._zap = co(function* zap(acct, age) {
  var account = yield this.ensureIndex(acct);
  return yield this.txdb.zap(account, age);
});

/**
 * Abandon transaction.
 * @param {Hash} hash
 * @returns {Promise}
 */

Wallet.prototype.abandon = co(function* abandon(hash) {
  var unlock = yield this.writeLock.lock();
  try {
    return yield this._abandon(hash);
  } finally {
    unlock();
  }
});

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

Wallet.prototype.getHistory = co(function* getHistory(acct) {
  var account = yield this.ensureIndex(acct);
  return this.txdb.getHistory(account);
});

/**
 * Get all available coins.
 * @param {(String|Number)?} account
 * @returns {Promise} - Returns {@link Coin}[].
 */

Wallet.prototype.getCoins = co(function* getCoins(acct) {
  var account = yield this.ensureIndex(acct);
  return yield this.txdb.getCoins(account);
});

/**
 * Get all pending/unconfirmed transactions.
 * @param {(String|Number)?} acct
 * @returns {Promise} - Returns {@link TX}[].
 */

Wallet.prototype.getPending = co(function* getPending(acct) {
  var account = yield this.ensureIndex(acct);
  return yield this.txdb.getPending(account);
});

/**
 * Get wallet balance.
 * @param {(String|Number)?} acct
 * @returns {Promise} - Returns {@link Balance}.
 */

Wallet.prototype.getBalance = co(function* getBalance(acct) {
  var account = yield this.ensureIndex(acct);
  return yield this.txdb.getBalance(account);
});

/**
 * Get a range of transactions between two timestamps.
 * @param {(String|Number)?} acct
 * @param {Object} options
 * @param {Number} options.start
 * @param {Number} options.end
 * @returns {Promise} - Returns {@link TX}[].
 */

Wallet.prototype.getRange = co(function* getRange(acct, options) {
  var account;
  if (acct && typeof acct === 'object') {
    options = acct;
    acct = null;
  }
  account = yield this.ensureIndex(acct);
  return yield this.txdb.getRange(account, options);
});

/**
 * Get the last N transactions.
 * @param {(String|Number)?} acct
 * @param {Number} limit
 * @returns {Promise} - Returns {@link TX}[].
 */

Wallet.prototype.getLast = co(function* getLast(acct, limit) {
  var account = yield this.ensureIndex(acct);
  return yield this.txdb.getLast(account, limit);
});

/**
 * Resolve account index.
 * @private
 * @param {(Number|String)?} acct
 * @param {Function} errback - Returns [Error].
 * @returns {Promise}
 */

Wallet.prototype.ensureIndex = co(function* ensureIndex(acct, enforce) {
  var index;

  if (acct == null) {
    if (enforce)
      throw new Error('No account provided.');
    return null;
  }

  index = yield this.getAccountIndex(acct);

  if (index === -1)
    throw new Error('Account not found.');

  return index;
});

/**
 * Get public key for current receiving address.
 * @param {String?} enc - `"hex"` or `null`.
 * @returns {Buffer}
 */

Wallet.prototype.getPublicKey = function getPublicKey(enc) {
  if (!this.receive)
    return;
  return this.receive.getPublicKey(enc);
};

/**
 * Get redeem script for current receiving address.
 * @returns {Script}
 */

Wallet.prototype.getScript = function getScript() {
  if (!this.receive)
    return;
  return this.receive.getScript();
};

/**
 * Get scripthash for current receiving address.
 * @param {String?} enc - `"hex"` or `null`.
 * @returns {Buffer}
 */

Wallet.prototype.getScriptHash = function getScriptHash(enc) {
  if (!this.receive)
    return;
  return this.receive.getScriptHash(enc);
};

/**
 * Get ripemd160 scripthash for current receiving address.
 * @param {String?} enc - `"hex"` or `null`.
 * @returns {Buffer}
 */

Wallet.prototype.getScriptHash160 = function getScriptHash160(enc) {
  if (!this.receive)
    return;
  return this.receive.getScriptHash160(enc);
};

/**
 * Get sha256 scripthash for current receiving address.
 * @param {String?} enc - `"hex"` or `null`.
 * @returns {Buffer}
 */

Wallet.prototype.getScriptHash256 = function getScriptHash256(enc) {
  if (!this.receive)
    return;
  return this.receive.getScriptHash256(enc);
};

/**
 * Get scripthash address for current receiving address.
 * @param {String?} enc - `"base58"` or `null`.
 * @returns {Address|Base58Address}
 */

Wallet.prototype.getScriptAddress = function getScriptAddress(enc) {
  if (!this.receive)
    return;
  return this.receive.getScriptAddress(enc);
};

/**
 * Get witness program for current receiving address.
 * @returns {Buffer}
 */

Wallet.prototype.getProgram = function getProgram() {
  if (!this.receive)
    return;
  return this.receive.getProgram();
};

/**
 * Get current receiving address' ripemd160 program
 * scripthash (for witness programs behind a scripthash).
 * @param {String?} enc - `"hex"` or `null`.
 * @returns {Buffer}
 */

Wallet.prototype.getNestedHash = function getNestedHash(enc) {
  if (!this.nested)
    return;
  return this.nested.getHash(enc);
};

/**
 * Get current receiving address'
 * scripthash address for witness program.
 * @param {String?} enc - `"base58"` or `null`.
 * @returns {Address|Base58Address}
 */

Wallet.prototype.getNestedAddress = function getNestedAddress(enc) {
  if (!this.nested)
    return;
  return this.nested.getAddress(enc);
};

/**
 * Get public key hash for current receiving address.
 * @param {String?} enc - `"hex"` or `null`.
 * @returns {Buffer}
 */

Wallet.prototype.getKeyHash = function getKeyHash(enc) {
  if (!this.receive)
    return;
  return this.receive.getKeyHash(enc);
};

/**
 * Get pubkeyhash address for current receiving address.
 * @param {String?} enc - `"base58"` or `null`.
 * @returns {Address|Base58Address}
 */

Wallet.prototype.getKeyAddress = function getKeyAddress(enc) {
  if (!this.receive)
    return;
  return this.receive.getKeyAddress(enc);
};

/**
 * Get hash for current receiving address.
 * @param {String?} enc - `"hex"` or `null`.
 * @returns {Buffer}
 */

Wallet.prototype.getHash = function getHash(enc) {
  if (!this.receive)
    return;
  return this.receive.getHash(enc);
};

/**
 * Get base58 address for current receiving address.
 * @param {String?} enc - `"base58"` or `null`.
 * @returns {Address|Base58Address}
 */

Wallet.prototype.getAddress = function getAddress(enc) {
  if (!this.receive)
    return;
  return this.receive.getAddress(enc);
};

Wallet.prototype.__defineGetter__('publicKey', function() {
  return this.getPublicKey();
});

Wallet.prototype.__defineGetter__('script', function() {
  return this.getScript();
});

Wallet.prototype.__defineGetter__('scriptHash', function() {
  return this.getScriptHash();
});

Wallet.prototype.__defineGetter__('scriptHash160', function() {
  return this.getScriptHash160();
});

Wallet.prototype.__defineGetter__('scriptHash256', function() {
  return this.getScriptHash256();
});

Wallet.prototype.__defineGetter__('scriptAddress', function() {
  return this.getScriptAddress();
});

Wallet.prototype.__defineGetter__('program', function() {
  return this.getProgram();
});

Wallet.prototype.__defineGetter__('nestedHash', function() {
  return this.getNestedHash();
});

Wallet.prototype.__defineGetter__('nestedAddress', function() {
  return this.getNestedAddress();
});

Wallet.prototype.__defineGetter__('keyHash', function() {
  return this.getKeyHash();
});

Wallet.prototype.__defineGetter__('keyAddress', function() {
  return this.getKeyAddress();
});

Wallet.prototype.__defineGetter__('hash', function() {
  return this.getHash();
});

Wallet.prototype.__defineGetter__('address', function() {
  return this.getAddress();
});

Wallet.prototype.__defineGetter__('receiveDepth', function() {
  if (!this.account)
    return -1;
  return this.account.receiveDepth;
});

Wallet.prototype.__defineGetter__('changeDepth', function() {
  if (!this.account)
    return -1;
  return this.account.changeDepth;
});

Wallet.prototype.__defineGetter__('nestedDepth', function() {
  if (!this.account)
    return -1;
  return this.account.nestedDepth;
});

Wallet.prototype.__defineGetter__('accountKey', function() {
  if (!this.account)
    return;
  return this.account.accountKey;
});

Wallet.prototype.__defineGetter__('receive', function() {
  if (!this.account)
    return;
  return this.account.receive;
});

Wallet.prototype.__defineGetter__('change', function() {
  if (!this.account)
    return;
  return this.account.change;
});

Wallet.prototype.__defineGetter__('nested', function() {
  if (!this.account)
    return;
  return this.account.nested;
});

Wallet.prototype.__defineGetter__('state', function() {
  return this.txdb.state;
});

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
    state: this.state ? this.state.toJSON(true) : null,
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
    state: this.state.toJSON(true),
    master: this.master.toJSON(unsafe),
    account: this.account.toJSON(true)
  };
};

/**
 * Serialize the wallet.
 * @returns {Buffer}
 */

Wallet.prototype.toRaw = function toRaw(writer) {
  var bw = new BufferWriter(writer);

  bw.writeU32(this.network.magic);
  bw.writeU32(this.wid);
  bw.writeVarString(this.id, 'ascii');
  bw.writeU8(this.initialized ? 1 : 0);
  bw.writeU8(this.watchOnly ? 1 : 0);
  bw.writeU32(this.accountDepth);
  bw.writeBytes(this.token);
  bw.writeU32(this.tokenDepth);
  bw.writeVarBytes(this.master.toRaw());

  if (!writer)
    bw = bw.render();

  return bw;
};

/**
 * Inject properties from serialized data.
 * @private
 * @param {Buffer} data
 */

Wallet.prototype.fromRaw = function fromRaw(data) {
  var br = new BufferReader(data);
  var network;

  network = Network.fromMagic(br.readU32());

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
