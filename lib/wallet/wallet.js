/*!
 * wallet.js - wallet object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var EventEmitter = require('events').EventEmitter;
var constants = require('../protocol/constants');
var Network = require('../protocol/network');
var utils = require('../utils/utils');
var Locker = require('../utils/locker');
var co = require('../utils/co');
var crypto = require('../crypto/crypto');
var assert = require('assert');
var BufferReader = require('../utils/reader');
var BufferWriter = require('../utils/writer');
var TXDB = require('./txdb');
var Path = require('./path');
var Address = require('../primitives/address');
var MTX = require('../primitives/mtx');
var WalletKey = require('./walletkey');
var HD = require('../hd/hd');
var Account = require('./account');
var MasterKey = require('./masterkey');
var Input = require('../primitives/input');
var Output = require('../primitives/output');
var LRU = require('../utils/lru');
var PathInfo = require('./pathinfo');

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
  this.master = null;

  this.txdb = new TXDB(this);
  this.account = null;

  if (options)
    this.fromOptions(options);
}

utils.inherits(Wallet, EventEmitter);

/**
 * Inject properties from options object.
 * @private
 * @param {Object} options
 */

Wallet.prototype.fromOptions = function fromOptions(options) {
  var master = options.master;
  var id, token;

  if (!MasterKey.isMasterKey(master)) {
    if (!master)
      master = HD.fromMnemonic(null, this.network);

    if (HD.isExtended(master))
      master = HD.fromBase58(master);

    assert(HD.isPrivate(master),
      'Must create wallet with hd private key.');

    assert(master.network === this.network,
      'Network mismatch for master key.');

    master = MasterKey.fromKey(master);
  }

  this.master = master;

  if (options.wid != null) {
    assert(utils.isNumber(options.wid));
    this.wid = options.wid;
  }

  if (options.id) {
    assert(utils.isName(options.id), 'Bad wallet ID.');
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
    assert(utils.isNumber(options.accountDepth));
    this.accountDepth = options.accountDepth;
  }

  if (options.token) {
    assert(Buffer.isBuffer(options.token));
    assert(options.token.length === 32);
    token = options.token;
  }

  if (options.tokenDepth != null) {
    assert(utils.isNumber(options.tokenDepth));
    this.tokenDepth = options.tokenDepth;
  }

  if (!id)
    id = this.getID();

  if (!token)
    token = this.getToken(this.master.key, this.tokenDepth);

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
  var account;

  assert(!this.initialized);
  this.initialized = true;

  if (options.passphrase)
    yield this.master.encrypt(options.passphrase);

  account = yield this._createAccount(options);
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
    this.master.destroy();
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

Wallet.prototype.addKey = co(function* addKey(acct, key) {
  var unlock = yield this.writeLock.lock();
  try {
    return yield this._addKey(acct, key);
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

Wallet.prototype._addKey = co(function* addKey(acct, key) {
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
    result = yield account.addKey(key);
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

Wallet.prototype.removeKey = co(function* removeKey(acct, key) {
  var unlock = yield this.writeLock.lock();
  try {
    return yield this._removeKey(acct, key);
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

Wallet.prototype._removeKey = co(function* removeKey(acct, key) {
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
    result = yield account.removeKey(key);
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
  var key;

  if (this.master.encrypted)
    throw new Error('Wallet is already encrypted.');

  this.start();

  try {
    key = yield this.master.encrypt(passphrase);
    yield this.db.encryptKeys(this, key);
  } catch (e) {
    this.drop();
    throw e;
  }

  key.fill(0);

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
  var key;

  if (!this.master.encrypted)
    throw new Error('Wallet is not encrypted.');

  this.start();

  try {
    key = yield this.master.decrypt(passphrase);
    yield this.db.decryptKeys(this, key);
  } catch (e) {
    this.drop();
    throw e;
  }

  key.fill(0);

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
  var master = yield this.unlock(passphrase);

  this.tokenDepth++;
  this.token = this.getToken(master, this.tokenDepth);

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

  if (!utils.isName(name))
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
    this.master.destroy();
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
  var key, p, hash;

  assert(this.master.key, 'Cannot derive id.');

  key = this.master.key.derive(44);

  p = new BufferWriter();
  p.writeBytes(key.publicKey);
  p.writeU32(this.network.magic);

  hash = crypto.hash160(p.render());

  p = new BufferWriter();
  p.writeU8(0x03);
  p.writeU8(0xbe);
  p.writeU8(0x04);
  p.writeBytes(hash);
  p.writeChecksum();

  return utils.toBase58(p.render());
};

/**
 * Generate the wallet api key if none was passed in.
 * It is represented as HASH256(m/44'->private|nonce).
 * @private
 * @param {HDPrivateKey} master
 * @param {Number} nonce
 * @returns {Buffer}
 */

Wallet.prototype.getToken = function getToken(master, nonce) {
  var key, p;

  assert(master, 'Cannot derive token.');

  key = master.derive(44, true);

  p = new BufferWriter();
  p.writeBytes(key.privateKey);
  p.writeU32(nonce);

  return crypto.hash256(p.render());
};

/**
 * Create an account. Requires passphrase if master key is encrypted.
 * @param {Object} options - See {@link Account} options.
 * @returns {Promise} - Returns {@link Account}.
 */

Wallet.prototype.createAccount = co(function* createAccount(options) {
  var unlock = yield this.writeLock.lock();
  try {
    return yield this._createAccount(options);
  } finally {
    unlock();
  }
});

/**
 * Create an account without a lock.
 * @param {Object} options - See {@link Account} options.
 * @returns {Promise} - Returns {@link Account}.
 */

Wallet.prototype._createAccount = co(function* createAccount(options) {
  var passphrase = options.passphrase;
  var timeout = options.timeout;
  var name = options.name;
  var key, master, account, exists;

  if (!name)
    name = this.accountDepth + '';

  exists = yield this.hasAccount(name);

  if (exists)
    throw new Error('Account already exists.');

  master = yield this.unlock(passphrase, timeout);

  if (this.watchOnly && options.accountKey) {
    key = options.accountKey;

    if (HD.isExtended(key))
      key = HD.fromBase58(key);

    if (!HD.isPublic(key))
      throw new Error('Must add HD public keys to watch only wallet.');

    assert(key.network === this.network,
      'Network mismatch for watch only key.');
  } else {
    key = master.deriveAccount44(this.accountDepth);
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
  } catch (e) {
    this.drop();
    throw e;
  }

  account.wallet = this;

  yield account.init();

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

Wallet.prototype.ensureAccount = co(function* ensureAccount(options) {
  var name = options.name;
  var account = yield this.getAccount(name);

  if (!account)
    return yield this.createAccount(options);

  return account;
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
 * @returns {Promise} - Returns Array.
 */

Wallet.prototype.getAddressHashes = function getAddressHashes() {
  return this.db.getWalletHashes(this.wid);
};

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
  var account = yield this.getAccount(index);

  if (!account)
    return null;

  return account.name;
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
  path.name = yield this.getAccountName(path.account);

  assert(path.name);

  // account = yield this.getAccount(path.account);
  // assert(account);
  // path.name = account.name;
  // path.version = account.getWitnessVersion(path);
  // path.type = account.getAddressType(path);

  this.pathCache.set(hash, path);

  return path;
});

/**
 * Get all wallet paths.
 * @param {(String|Number)?} acct
 * @returns {Promise} - Returns {@link Path}.
 */

Wallet.prototype.getPaths = co(function* getPaths(acct) {
  var index = yield this.ensureIndex(acct);
  var paths = yield this.db.getWalletPaths(this.wid);
  var result = [];
  var i, path;

  for (i = 0; i < paths.length; i++) {
    path = paths[i];
    if (index == null || path.account === index) {
      path.id = this.id;
      path.name = yield this.getAccountName(path.account);

      assert(path.name);

      // account = yield this.getAccount(path.account);
      // assert(account);
      // path.name = account.name;
      // path.version = account.getWitnessVersion(path);
      // path.type = account.getAddressType(path);

      this.pathCache.set(path.hash, path);

      result.push(path);
    }
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

  rate = this.network.feeRate;

  if (options.rate != null) {
    rate = options.rate;
  } else {
    if (this.db.fees)
      rate = this.db.fees.estimateFee();
  }

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
    height: this.db.height,
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
  for (i = 0; i < outputs.length; i++)
    tx.addOutput(outputs[i]);

  // Fill the inputs with unspents
  yield this.fund(tx, options, force);

  // Sort members a la BIP69
  tx.sortMembers();

  // Set the locktime to target value or
  // `height - whatever` to avoid fee sniping.
  // if (options.locktime != null)
  //   tx.setLocktime(options.locktime);
  // else
  //   tx.avoidFeeSniping(this.db.height);

  if (!tx.isSane())
    throw new Error('CheckTransaction failed.');

  if (!tx.checkInputs(this.db.height))
    throw new Error('CheckInputs failed.');

  total = yield this.template(tx);

  if (total === 0)
    throw new Error('template failed.');

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

Wallet.prototype.send = co(function* send(options) {
  var unlock = yield this.fundLock.lock();
  try {
    return yield this._send(options);
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

Wallet.prototype._send = co(function* send(options) {
  var tx = yield this.createTX(options, true);

  yield this.sign(tx, options);

  if (!tx.isSigned())
    throw new Error('TX could not be fully signed.');

  tx = tx.toTX();

  yield this.db.addTX(tx);

  this.logger.debug('Sending wallet tx (%s): %s', this.id, tx.rhash);
  this.db.emit('send', tx);

  return tx;
});

/**
 * Resend pending wallet transactions.
 * @returns {Promise}
 */

Wallet.prototype.resend = co(function* resend() {
  var txs = yield this.getUnconfirmed();
  var i;

  if (txs.length > 0)
    this.logger.info('Rebroadcasting %d transactions.', txs.length);

  for (i = 0; i < txs.length; i++)
    this.db.emit('send', txs[i]);

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
 * Map input addresses to paths.
 * @param {TX|Input} tx
 * @returns {Promise} - Returns {@link Path}[].
 */

Wallet.prototype.getInputPaths = co(function* getInputPaths(tx) {
  var paths = [];
  var hashes = [];
  var i, hash, path;

  if (tx instanceof Input) {
    if (!tx.coin)
      throw new Error('Not all coins available.');

    hash = tx.coin.getHash('hex');

    if (hash)
      hashes.push(hash);
  } else {
    yield this.fillCoins(tx);

    if (!tx.hasCoins())
      throw new Error('Not all coins available.');

    hashes = tx.getInputHashes('hex');
  }

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
 * @param {TX|Output} tx
 * @returns {Promise} - Returns {@link Path}[].
 */

Wallet.prototype.getOutputPaths = co(function* getOutputPaths(tx) {
  var paths = [];
  var hashes = [];
  var i, hash, path;

  if (tx instanceof Output) {
    hash = tx.getHash('hex');
    if (hash)
      hashes.push(hash);
  } else {
    hashes = tx.getOutputHashes('hex');
  }

  for (i = 0; i < hashes.length; i++) {
    hash = hashes[i];
    path = yield this.getPath(hash);
    if (path)
      paths.push(path);
  }

  return paths;
});

/**
 * Sync address depths based on a transaction's outputs.
 * This is used for deriving new addresses when
 * a confirmed transaction is seen.
 * @param {PathInfo} info
 * @returns {Promise} - Returns Boolean
 * (true if new addresses were allocated).
 */

Wallet.prototype.syncOutputDepth = co(function* syncOutputDepth(info) {
  var derived = [];
  var accounts = {};
  var i, j, path, paths, account;
  var receive, change, nested, ring;

  for (i = 0; i < info.paths.length; i++) {
    path = info.paths[i];

    if (path.index === -1)
      continue;

    if (!accounts[path.account])
      accounts[path.account] = [];

    accounts[path.account].push(path);
  }

  accounts = utils.values(accounts);

  for (i = 0; i < accounts.length; i++) {
    paths = accounts[i];
    account = paths[0].account;
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

    account = yield this.getAccount(account);

    if (!account)
      continue;

    ring = yield account.setDepth(receive, change, nested);

    if (ring)
      derived.push(ring);
  }

  if (derived.length > 0) {
    this.db.emit('address', this.id, derived);
    this.emit('address', derived);
  }

  return derived;
});

/**
 * Emit balance events after a tx is saved.
 * @private
 * @param {TX} tx
 * @param {PathInfo} info
 * @returns {Promise}
 */

Wallet.prototype.updateBalances = co(function* updateBalances() {
  var balance;

  if (this.db.listeners('balance').length === 0
      && this.listeners('balance').length === 0) {
    return;
  }

  balance = yield this.getBalance();

  this.db.emit('balance', this.id, balance);
  this.emit('balance', balance);
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

Wallet.prototype.sign = co(function* sign(tx, options) {
  var rings;

  if (!options)
    options = {};

  if (typeof options === 'string' || Buffer.isBuffer(options))
    options = { passphrase: options };

  if (this.watchOnly)
    throw new Error('Cannot sign from a watch-only wallet.');

  yield this.unlock(options.passphrase, options.timeout);

  rings = yield this.deriveInputs(tx);

  return yield tx.signAsync(rings);
});

/**
 * Fill transaction with coins (accesses db).
 * @param {TX} tx
 * @returns {Promise} - Returns {@link TX}.
 */

Wallet.prototype.fillCoins = function fillCoins(tx) {
  return this.txdb.fillCoins(tx);
};

/**
 * Fill transaction with historical coins (accesses db).
 * @param {TX} tx
 * @returns {Promise} - Returns {@link TX}.
 */

Wallet.prototype.fillHistory = function fillHistory(tx) {
  return this.txdb.fillHistory(tx);
};

/**
 * Fill transaction with historical coins (accesses db).
 * @param {TX} tx
 * @returns {Promise} - Returns {@link TX}.
 */

Wallet.prototype.toDetails = function toDetails(tx) {
  return this.txdb.toDetails(tx);
};

/**
 * Fill transaction with historical coins (accesses db).
 * @param {TX} tx
 * @returns {Promise} - Returns {@link TX}.
 */

Wallet.prototype.getDetails = function getDetails(tx) {
  return this.txdb.getDetails(tx);
};

/**
 * Get a coin from the wallet (accesses db).
 * @param {Hash} hash
 * @param {Number} index
 * @returns {Promise} - Returns {@link Coin}.
 */

Wallet.prototype.getCoin = function getCoin(hash, index) {
  return this.txdb.getCoin(hash, index);
};

/**
 * Get a transaction from the wallet (accesses db).
 * @param {Hash} hash
 * @returns {Promise} - Returns {@link TX}.
 */

Wallet.prototype.getTX = function getTX(hash) {
  return this.txdb.getTX(hash);
};

/**
 * Add a transaction to the wallets TX history (accesses db).
 * @param {TX} tx
 * @returns {Promise}
 */

Wallet.prototype.add = co(function* add(tx) {
  var unlock = yield this.writeLock.lock();
  try {
    return yield this._add(tx);
  } finally {
    unlock();
  }
});

/**
 * Add a transaction to the wallet without a lock.
 * @param {TX} tx
 * @returns {Promise}
 */

Wallet.prototype._add = co(function* add(tx) {
  var info = yield this.getPathInfo(tx);
  var result;

  this.start();

  try {
    result = yield this.txdb._add(tx, info);
    yield this.syncOutputDepth(info);
    yield this.updateBalances();
  } catch (e) {
    this.drop();
    throw e;
  }

  yield this.commit();

  return result;
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
 * Zap stale TXs from wallet (accesses db).
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
 * Abandon transaction (accesses db).
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
 * Map a transactions' addresses to wallet IDs.
 * @param {TX} tx
 * @returns {Promise} - Returns {@link PathInfo}.
 */

Wallet.prototype.getPathInfo = co(function* getPathInfo(tx) {
  var hashes = tx.getHashes('hex');
  var paths = [];
  var i, hash, path;

  for (i = 0; i < hashes.length; i++) {
    hash = hashes[i];
    path = yield this.getPath(hash);
    if (path)
      paths.push(path);
  }

  return new PathInfo(this, tx, paths);
});

/**
 * Get all transactions in transaction history (accesses db).
 * @param {(String|Number)?} acct
 * @returns {Promise} - Returns {@link TX}[].
 */

Wallet.prototype.getHistory = co(function* getHistory(acct) {
  var account = yield this.ensureIndex(acct);
  return this.txdb.getHistory(account);
});

/**
 * Get all available coins (accesses db).
 * @param {(String|Number)?} account
 * @returns {Promise} - Returns {@link Coin}[].
 */

Wallet.prototype.getCoins = co(function* getCoins(acct) {
  var account = yield this.ensureIndex(acct);
  return yield this.txdb.getCoins(account);
});

/**
 * Get all pending/unconfirmed transactions (accesses db).
 * @param {(String|Number)?} acct
 * @returns {Promise} - Returns {@link TX}[].
 */

Wallet.prototype.getUnconfirmed = co(function* getUnconfirmed(acct) {
  var account = yield this.ensureIndex(acct);
  return yield this.txdb.getUnconfirmed(account);
});

/**
 * Get wallet balance (accesses db).
 * @param {(String|Number)?} acct
 * @returns {Promise} - Returns {@link Balance}.
 */

Wallet.prototype.getBalance = co(function* getBalance(acct) {
  var account = yield this.ensureIndex(acct);
  return yield this.txdb.getBalance(account);
});

/**
 * Get a range of transactions between two timestamps (accesses db).
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
 * Get the last N transactions (accesses db).
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

Wallet.prototype.ensureIndex = co(function* ensureIndex(acct) {
  var index;

  if (acct == null)
    return null;

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
    master: this.master,
    account: this.account
  };
};

/**
 * Convert the wallet to an object suitable for
 * serialization. Will automatically encrypt the
 * master key based on the `passphrase` option.
 * @returns {Object}
 */

Wallet.prototype.toJSON = function toJSON() {
  return {
    network: this.network.type,
    wid: this.wid,
    id: this.id,
    initialized: this.initialized,
    watchOnly: this.watchOnly,
    accountDepth: this.accountDepth,
    token: this.token.toString('hex'),
    tokenDepth: this.tokenDepth,
    master: this.master.toJSON(),
    account: this.account ? this.account.toJSON() : null
  };
};

/**
 * Inject properties from json object.
 * @private
 * @param {Object} json
 */

Wallet.prototype.fromJSON = function fromJSON(json) {
  var network;

  assert(utils.isNumber(json.wid));
  assert(typeof json.initialized === 'boolean');
  assert(typeof json.watchOnly === 'boolean');
  assert(utils.isName(json.id), 'Bad wallet ID.');
  assert(utils.isNumber(json.accountDepth));
  assert(typeof json.token === 'string');
  assert(json.token.length === 64);
  assert(utils.isNumber(json.tokenDepth));

  network = Network.get(json.network);

  this.wid = json.wid;
  this.id = json.id;
  this.initialized = json.initialized;
  this.watchOnly = json.watchOnly;
  this.accountDepth = json.accountDepth;
  this.token = new Buffer(json.token, 'hex');
  this.master = MasterKey.fromJSON(json.master);

  assert(network === this.db.network, 'Wallet network mismatch.');

  return this;
};

/**
 * Serialize the wallet.
 * @returns {Buffer}
 */

Wallet.prototype.toRaw = function toRaw(writer) {
  var p = new BufferWriter(writer);

  p.writeU32(this.network.magic);
  p.writeU32(this.wid);
  p.writeVarString(this.id, 'ascii');
  p.writeU8(this.initialized ? 1 : 0);
  p.writeU8(this.watchOnly ? 1 : 0);
  p.writeU32(this.accountDepth);
  p.writeBytes(this.token);
  p.writeU32(this.tokenDepth);
  p.writeVarBytes(this.master.toRaw());

  if (!writer)
    p = p.render();

  return p;
};

/**
 * Inject properties from serialized data.
 * @private
 * @param {Buffer} data
 */

Wallet.prototype.fromRaw = function fromRaw(data) {
  var p = new BufferReader(data);
  var network;

  network = Network.fromMagic(p.readU32());

  this.wid = p.readU32();
  this.id = p.readVarString('ascii');
  this.initialized = p.readU8() === 1;
  this.watchOnly = p.readU8() === 1;
  this.accountDepth = p.readU32();
  this.token = p.readBytes(32);
  this.tokenDepth = p.readU32();
  this.master = MasterKey.fromRaw(p.readVarBytes());

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
 * Instantiate a Wallet from a
 * jsonified wallet object.
 * @param {Object} json - The jsonified wallet object.
 * @returns {Wallet}
 */

Wallet.fromJSON = function fromJSON(db, json) {
  return new Wallet(db).fromJSON(json);
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
