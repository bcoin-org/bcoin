/*!
 * wallet.js - wallet object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var bcoin = require('../env');
var EventEmitter = require('events').EventEmitter;
var constants = bcoin.constants;
var utils = require('../utils/utils');
var spawn = require('../utils/spawn');
var co = spawn.co;
var crypto = require('../crypto/crypto');
var assert = utils.assert;
var BufferReader = require('../utils/reader');
var BufferWriter = require('../utils/writer');
var TXDB = require('./txdb');
var Path = require('./path');

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
  this.writeLock = new bcoin.locker();
  this.fundLock = new bcoin.locker();

  this.wid = 0;
  this.id = null;
  this.master = null;
  this.initialized = false;
  this.accountDepth = 0;
  this.token = constants.ZERO_HASH;
  this.tokenDepth = 0;
  this.tx = new TXDB(this);

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

  if (!master)
    master = bcoin.hd.fromMnemonic(null, this.network);

  if (!bcoin.hd.isHD(master) && !MasterKey.isMasterKey(master))
    master = bcoin.hd.from(master, this.network);

  if (bcoin.hd.isHD(master))
    master = MasterKey.fromKey(master);

  assert(MasterKey.isMasterKey(master));

  this.master = master;

  if (options.initialized != null) {
    assert(typeof options.initialized === 'boolean');
    this.initialized = options.initialized;
  }

  if (options.accountDepth != null) {
    assert(utils.isNumber(options.accountDepth));
    this.accountDepth = options.accountDepth;
  }

  if (options.wid != null) {
    assert(utils.isNumber(options.wid));
    this.wid = options.wid;
  }

  if (options.id) {
    assert(utils.isName(options.id), 'Bad wallet ID.');
    id = options.id;
  }

  if (!id)
    id = this.getID();

  if (options.token) {
    assert(Buffer.isBuffer(options.token));
    assert(options.token.length === 32);
    token = options.token;
  }

  if (options.tokenDepth != null) {
    assert(utils.isNumber(options.tokenDepth));
    this.tokenDepth = options.tokenDepth;
  }

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

  account = yield this.createAccount(options);
  assert(account);

  this.account = account;

  this.logger.info('Wallet initialized (%s).', this.id);

  yield this.tx.open();
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

  yield this.tx.open();
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
 * @param {HDPublicKey} key
 * @returns {Promise}
 */

Wallet.prototype.addKey = co(function* addKey(account, key) {
  var unlock = yield this.writeLock.lock();
  try {
    return yield this._addKey(account, key);
  } finally {
    unlock();
  }
});

/**
 * Add a public account key to the wallet without a lock.
 * @private
 * @param {HDPublicKey} key
 * @returns {Promise}
 */

Wallet.prototype._addKey = co(function* addKey(account, key) {
  var result;

  if (!key) {
    key = account;
    account = null;
  }

  if (account == null)
    account = 0;

  account = yield this.getAccount(account);

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
 * @param {HDPublicKey} key
 * @returns {Promise}
 */

Wallet.prototype.removeKey = co(function* removeKey(account, key) {
  var unlock = yield this.writeLock.lock();
  try {
    return yield this._removeKey(account, key);
  } finally {
    unlock();
  }
});

/**
 * Remove a public account key from the wallet (multisig).
 * @private
 * @param {HDPublicKey} key
 * @returns {Promise}
 */

Wallet.prototype._removeKey = co(function* removeKey(account, key) {
  var result;

  if (!key) {
    key = account;
    account = null;
  }

  if (account == null)
    account = 0;

  account = yield this.getAccount(account);

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
  var unlock = yield this.writeLock.lock();
  try {
    return yield this._setPassphrase(old, new_);
  } finally {
    unlock();
  }
});

/**
 * Change or set master key's passphrase without a lock.
 * @private
 * @param {(String|Buffer)?} old
 * @param {String|Buffer} new_
 * @returns {Promise}
 */

Wallet.prototype._setPassphrase = co(function* setPassphrase(old, new_) {
  if (new_ == null) {
    new_ = old;
    old = null;
  }

  if (old != null)
    yield this.master.decrypt(old);

  if (new_ != null)
    yield this.master.encrypt(new_);

  this.start();
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
 * Unlock the key for `timeout` milliseconds.
 * @param {Buffer|String} passphrase
 * @param {Number?} [timeout=60000] - ms.
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
  var key, master, account;

  if (typeof options.account === 'string')
    name = options.account;

  if (!name)
    name = this.accountDepth + '';

  master = yield this.unlock(passphrase, timeout);

  key = master.deriveAccount44(this.accountDepth);

  options = {
    network: this.network,
    wid: this.wid,
    id: this.id,
    name: this.accountDepth === 0 ? 'default' : name,
    witness: options.witness,
    accountKey: key.hdPublicKey,
    accountIndex: this.accountDepth,
    type: options.type,
    keys: options.keys,
    m: options.m,
    n: options.n
  };

  this.start();

  try {
    account = yield this.db.createAccount(options);
  } catch (e) {
    this.drop();
    throw e;
  }

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
  var account = options.account;
  var exists;

  if (typeof options.name === 'string')
    account = options.name;

  exists = yield this.hasAccount(account);

  if (exists)
    return yield this.getAccount(account);

  return this.createAccount(options);
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
  return this.db.getAddressHashes(this.wid);
};

/**
 * Retrieve an account from the database.
 * @param {Number|String} account
 * @returns {Promise} - Returns {@link Account}.
 */

Wallet.prototype.getAccount = co(function* getAccount(account) {
  if (this.account) {
    if (account === 0 || account === 'default')
      return this.account;
  }

  account = yield this.db.getAccount(this.wid, account);

  if (!account)
    return;

  account.wid = this.wid;
  account.id = this.id;

  return account;
});

/**
 * Test whether an account exists.
 * @param {Number|String} account
 * @returns {Promise} - Returns {@link Boolean}.
 */

Wallet.prototype.hasAccount = function hasAccount(account) {
  return this.db.hasAccount(this.wid, account);
};

/**
 * Create a new receiving address (increments receiveDepth).
 * @param {(Number|String)?} account
 * @returns {Promise} - Returns {@link KeyRing}.
 */

Wallet.prototype.createReceive = function createReceive(account) {
  return this.createAddress(account, false);
};

/**
 * Create a new change address (increments receiveDepth).
 * @param {(Number|String)?} account
 * @returns {Promise} - Returns {@link KeyRing}.
 */

Wallet.prototype.createChange = function createChange(account) {
  return this.createAddress(account, true);
};

/**
 * Create a new address (increments depth).
 * @param {(Number|String)?} account
 * @param {Boolean} change
 * @returns {Promise} - Returns {@link KeyRing}.
 */

Wallet.prototype.createAddress = co(function* createAddress(account, change) {
  var unlock = yield this.writeLock.lock();
  try {
    return yield this._createAddress(account, change);
  } finally {
    unlock();
  }
});

/**
 * Create a new address (increments depth) without a lock.
 * @param {(Number|String)?} account
 * @param {Boolean} change
 * @returns {Promise} - Returns {@link KeyRing}.
 */

Wallet.prototype._createAddress = co(function* createAddress(account, change) {
  var result;

  if (typeof account === 'boolean') {
    change = account;
    account = null;
  }

  if (account == null)
    account = 0;

  account = yield this.getAccount(account);

  if (!account)
    throw new Error('Account not found.');

  this.start();

  try {
    result = yield account.createAddress(change);
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
  return this.db.start(this.wid);
};

/**
 * Drop batch.
 * @private
 */

Wallet.prototype.drop = function drop() {
  return this.db.drop(this.wid);
};

/**
 * Save batch.
 * @returns {Promise}
 */

Wallet.prototype.commit = function commit() {
  return this.db.commit(this.wid);
};

/**
 * Test whether the wallet possesses an address.
 * @param {Address|Hash} address
 * @returns {Promise} - Returns Boolean.
 */

Wallet.prototype.hasAddress = function hasAddress(address) {
  var hash = bcoin.address.getHash(address, 'hex');
  if (!hash)
    return Promise.resolve(false);
  return this.db.hasAddress(this.wid, hash);
};

/**
 * Get path by address hash.
 * @param {Address|Hash} address
 * @returns {Promise} - Returns {@link Path}.
 */

Wallet.prototype.getPath = co(function* getPath(address) {
  var hash = bcoin.address.getHash(address, 'hex');
  var path;

  if (!hash)
    return;

  path = yield this.db.getAddressPath(this.wid, hash);

  if (!path)
    return;

  path.id = this.id;

  return path;
});

/**
 * Get all wallet paths.
 * @param {(String|Number)?} account
 * @returns {Promise} - Returns {@link Path}.
 */

Wallet.prototype.getPaths = co(function* getPaths(account) {
  var out = [];
  var i, paths, path;

  account = yield this._getIndex(account);
  paths = yield this.db.getWalletPaths(this.wid);

  for (i = 0; i < paths.length; i++) {
    path = paths[i];
    if (!account || path.account === account) {
      path.id = this.id;
      out.push(path);
    }
  }

  return out;
});

/**
 * Import a keyring (will not exist on derivation chain).
 * Rescanning must be invoked manually.
 * @param {(String|Number)?} account
 * @param {KeyRing} ring
 * @param {(String|Buffer)?} passphrase
 * @returns {Promise}
 */

Wallet.prototype.importKey = co(function* importKey(account, ring, passphrase) {
  var unlock = yield this.writeLock.lock();
  try {
    return yield this._importKey(account, ring, passphrase);
  } finally {
    unlock();
  }
});

/**
 * Import a keyring (will not exist on derivation chain) without a lock.
 * @private
 * @param {(String|Number)?} account
 * @param {KeyRing} ring
 * @param {(String|Buffer)?} passphrase
 * @returns {Promise}
 */

Wallet.prototype._importKey = co(function* importKey(account, ring, passphrase) {
  var exists, raw, path;

  if (account && typeof account === 'object') {
    passphrase = ring;
    ring = account;
    account = null;
  }

  if (account == null)
    account = 0;

  exists = yield this.getPath(ring.getHash('hex'));

  if (exists)
    throw new Error('Key already exists.');

  account = yield this.getAccount(account);

  if (!account)
    throw new Error('Account not found.');

  if (account.type !== bcoin.account.types.PUBKEYHASH)
    throw new Error('Cannot import into non-pkh account.');

  yield this.unlock(passphrase);

  raw = ring.toRaw();
  path = Path.fromAccount(account, ring);

  if (this.master.encrypted) {
    raw = this.master.encipher(raw, path.hash);
    assert(raw);
    path.encrypted = true;
  }

  path.imported = raw;
  ring.path = path;

  this.start();

  try {
    yield account.saveAddress([ring], true);
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

  if (rate == null) {
    if (this.db.fees)
      rate = this.db.fees.estimateFee();
    else
      rate = this.network.feeRate;
  }

  // Don't use any locked coins.
  coins = this.tx.filterLocked(coins);

  tx.fund(coins, {
    selection: options.selection,
    round: options.round,
    confirmations: options.confirmations,
    free: options.free,
    hardFee: options.hardFee,
    subtractFee: options.subtractFee,
    changeAddress: account.changeAddress.getAddress(),
    height: this.db.height,
    rate: rate,
    maxFee: options.maxFee,
    m: account.m,
    n: account.n,
    witness: account.witness,
    script: account.receiveAddress.script
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
  tx = bcoin.mtx();

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

  yield this.addTX(tx);

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
 * @returns {Promise} - Returns {@link KeyRing}[].
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

Wallet.prototype.getKeyRing = co(function* getKeyRing(address) {
  var hash = bcoin.address.getHash(address, 'hex');
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

  if (tx instanceof bcoin.input) {
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

  if (tx instanceof bcoin.output) {
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
  var unlock = yield this.writeLock.lock();
  try {
    return yield this._syncOutputDepth(info);
  } finally {
    unlock();
  }
});

/**
 * Sync address depths without a lock.
 * @private
 * @param {PathInfo} info
 * @returns {Promise} - Returns Boolean
 */

Wallet.prototype._syncOutputDepth = co(function* syncOutputDepth(info) {
  var receive = [];
  var accounts = {};
  var i, j, path, paths, account;
  var receiveDepth, changeDepth, ring;

  this.start();

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
    receiveDepth = -1;
    changeDepth = -1;

    for (j = 0; j < paths.length; j++) {
      path = paths[j];

      if (path.change) {
        if (path.index > changeDepth)
          changeDepth = path.index;
      } else {
        if (path.index > receiveDepth)
          receiveDepth = path.index;
      }
    }

    receiveDepth += 2;
    changeDepth += 2;

    account = yield this.getAccount(account);

    if (!account)
      continue;

    ring = yield account.setDepth(receiveDepth, changeDepth);

    if (ring)
      receive.push(ring);
  }

  yield this.commit();

  if (receive.length > 0) {
    this.db.emit('address', this.id, receive);
    this.emit('address', receive);
  }

  return receive;
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
 * Derive new addresses and emit balance.
 * @private
 * @param {TX} tx
 * @param {PathInfo} info
 * @returns {Promise}
 */

Wallet.prototype.handleTX = co(function* handleTX(info) {
  yield this.syncOutputDepth(info);
  yield this.updateBalances();
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

  ring = yield this.getKeyRing(hash.toString('hex'));

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
  return this.tx.fillCoins(tx);
};

/**
 * Fill transaction with historical coins (accesses db).
 * @param {TX} tx
 * @returns {Promise} - Returns {@link TX}.
 */

Wallet.prototype.fillHistory = function fillHistory(tx) {
  return this.tx.fillHistory(tx);
};

/**
 * Fill transaction with historical coins (accesses db).
 * @param {TX} tx
 * @returns {Promise} - Returns {@link TX}.
 */

Wallet.prototype.toDetails = function toDetails(tx) {
  return this.tx.toDetails(tx);
};

/**
 * Fill transaction with historical coins (accesses db).
 * @param {TX} tx
 * @returns {Promise} - Returns {@link TX}.
 */

Wallet.prototype.getDetails = function getDetails(tx) {
  return this.tx.getDetails(tx);
};

/**
 * Get a coin from the wallet (accesses db).
 * @param {Hash} hash
 * @param {Number} index
 * @returns {Promise} - Returns {@link Coin}.
 */

Wallet.prototype.getCoin = function getCoin(hash, index) {
  return this.tx.getCoin(hash, index);
};

/**
 * Get a transaction from the wallet (accesses db).
 * @param {Hash} hash
 * @returns {Promise} - Returns {@link TX}.
 */

Wallet.prototype.getTX = function getTX(hash) {
  return this.tx.getTX(hash);
};

/**
 * Add a transaction to the wallets TX history (accesses db).
 * @param {TX} tx
 * @returns {Promise}
 */

Wallet.prototype.addTX = function addTX(tx) {
  return this.db.addTX(tx);
};

/**
 * Get all transactions in transaction history (accesses db).
 * @param {(String|Number)?} account
 * @returns {Promise} - Returns {@link TX}[].
 */

Wallet.prototype.getHistory = co(function* getHistory(account) {
  account = yield this._getIndex(account);
  return this.tx.getHistory(account);
});

/**
 * Get all available coins (accesses db).
 * @param {(String|Number)?} account
 * @returns {Promise} - Returns {@link Coin}[].
 */

Wallet.prototype.getCoins = co(function* getCoins(account) {
  account = yield this._getIndex(account);
  return yield this.tx.getCoins(account);
});

/**
 * Get all pending/unconfirmed transactions (accesses db).
 * @param {(String|Number)?} account
 * @returns {Promise} - Returns {@link TX}[].
 */

Wallet.prototype.getUnconfirmed = co(function* getUnconfirmed(account) {
  account = yield this._getIndex(account);
  return yield this.tx.getUnconfirmed(account);
});

/**
 * Get wallet balance (accesses db).
 * @param {(String|Number)?} account
 * @returns {Promise} - Returns {@link Balance}.
 */

Wallet.prototype.getBalance = co(function* getBalance(account) {
  account = yield this._getIndex(account);
  return yield this.tx.getBalance(account);
});

/**
 * Get a range of transactions between two timestamps (accesses db).
 * @param {(String|Number)?} account
 * @param {Object} options
 * @param {Number} options.start
 * @param {Number} options.end
 * @returns {Promise} - Returns {@link TX}[].
 */

Wallet.prototype.getRange = co(function* getRange(account, options) {
  if (account && typeof account === 'object') {
    options = account;
    account = null;
  }
  account = yield this._getIndex(account);
  return yield this.tx.getRange(account, options);
});

/**
 * Get the last N transactions (accesses db).
 * @param {(String|Number)?} account
 * @param {Number} limit
 * @returns {Promise} - Returns {@link TX}[].
 */

Wallet.prototype.getLast = co(function* getLast(account, limit) {
  account = yield this._getIndex(account);
  return yield this.tx.getLast(account, limit);
});

/**
 * Zap stale TXs from wallet (accesses db).
 * @param {(Number|String)?} account
 * @param {Number} age - Age threshold (unix time, default=72 hours).
 * @returns {Promise}
 */

Wallet.prototype.zap = co(function* zap(account, age) {
  account = yield this._getIndex(account);
  return yield this.tx.zap(account, age);
});

/**
 * Abandon transaction (accesses db).
 * @param {Hash} hash
 * @returns {Promise}
 */

Wallet.prototype.abandon = function abandon(hash) {
  return this.tx.abandon(hash);
};

/**
 * Resolve account index.
 * @private
 * @param {(Number|String)?} account
 * @param {Function} errback - Returns [Error].
 * @returns {Promise}
 */

Wallet.prototype._getIndex = co(function* _getIndex(account) {
  var index;

  if (account == null)
    return null;

  index = yield this.db.getAccountIndex(this.wid, account);

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
  if (!this.receiveAddress)
    return;
  return this.receiveAddress.getPublicKey(enc);
};

/**
 * Get redeem script for current receiving address.
 * @returns {Script}
 */

Wallet.prototype.getScript = function getScript() {
  if (!this.receiveAddress)
    return;
  return this.receiveAddress.getScript();
};

/**
 * Get scripthash for current receiving address.
 * @param {String?} enc - `"hex"` or `null`.
 * @returns {Buffer}
 */

Wallet.prototype.getScriptHash = function getScriptHash(enc) {
  if (!this.receiveAddress)
    return;
  return this.receiveAddress.getScriptHash(enc);
};

/**
 * Get ripemd160 scripthash for current receiving address.
 * @param {String?} enc - `"hex"` or `null`.
 * @returns {Buffer}
 */

Wallet.prototype.getScriptHash160 = function getScriptHash160(enc) {
  if (!this.receiveAddress)
    return;
  return this.receiveAddress.getScriptHash160(enc);
};

/**
 * Get sha256 scripthash for current receiving address.
 * @param {String?} enc - `"hex"` or `null`.
 * @returns {Buffer}
 */

Wallet.prototype.getScriptHash256 = function getScriptHash256(enc) {
  if (!this.receiveAddress)
    return;
  return this.receiveAddress.getScriptHash256(enc);
};

/**
 * Get scripthash address for current receiving address.
 * @param {String?} enc - `"base58"` or `null`.
 * @returns {Address|Base58Address}
 */

Wallet.prototype.getScriptAddress = function getScriptAddress(enc) {
  if (!this.receiveAddress)
    return;
  return this.receiveAddress.getScriptAddress(enc);
};

/**
 * Get witness program for current receiving address.
 * @returns {Buffer}
 */

Wallet.prototype.getProgram = function getProgram() {
  if (!this.receiveAddress)
    return;
  return this.receiveAddress.getProgram();
};

/**
 * Get current receiving address' ripemd160 program
 * scripthash (for witness programs behind a scripthash).
 * @param {String?} enc - `"hex"` or `null`.
 * @returns {Buffer}
 */

Wallet.prototype.getProgramHash = function getProgramHash(enc) {
  if (!this.receiveAddress)
    return;
  return this.receiveAddress.getProgramHash(enc);
};

/**
 * Get current receiving address'
 * scripthash address for witness program.
 * @param {String?} enc - `"base58"` or `null`.
 * @returns {Address|Base58Address}
 */

Wallet.prototype.getProgramAddress = function getProgramAddress(enc) {
  if (!this.receiveAddress)
    return;
  return this.receiveAddress.getProgramAddress(enc);
};

/**
 * Get public key hash for current receiving address.
 * @param {String?} enc - `"hex"` or `null`.
 * @returns {Buffer}
 */

Wallet.prototype.getKeyHash = function getKeyHash(enc) {
  if (!this.receiveAddress)
    return;
  return this.receiveAddress.getKeyHash(enc);
};

/**
 * Get pubkeyhash address for current receiving address.
 * @param {String?} enc - `"base58"` or `null`.
 * @returns {Address|Base58Address}
 */

Wallet.prototype.getKeyAddress = function getKeyAddress(enc) {
  if (!this.receiveAddress)
    return;
  return this.receiveAddress.getKeyAddress(enc);
};

/**
 * Get hash for current receiving address.
 * @param {String?} enc - `"hex"` or `null`.
 * @returns {Buffer}
 */

Wallet.prototype.getHash = function getHash(enc) {
  if (!this.receiveAddress)
    return;
  return this.receiveAddress.getHash(enc);
};

/**
 * Get base58 address for current receiving address.
 * @param {String?} enc - `"base58"` or `null`.
 * @returns {Address|Base58Address}
 */

Wallet.prototype.getAddress = function getAddress(enc) {
  if (!this.receiveAddress)
    return;
  return this.receiveAddress.getAddress(enc);
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

Wallet.prototype.__defineGetter__('programHash', function() {
  return this.getProgramHash();
});

Wallet.prototype.__defineGetter__('programAddress', function() {
  return this.getProgramAddress();
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

Wallet.prototype.__defineGetter__('accountKey', function() {
  if (!this.account)
    return;
  return this.account.accountKey;
});

Wallet.prototype.__defineGetter__('receiveAddress', function() {
  if (!this.account)
    return;
  return this.account.receiveAddress;
});

Wallet.prototype.__defineGetter__('changeAddress', function() {
  if (!this.account)
    return;
  return this.account.changeAddress;
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
  assert(utils.isNumber(json.wid));
  assert(typeof json.initialized === 'boolean');
  assert(utils.isName(json.id), 'Bad wallet ID.');
  assert(utils.isNumber(json.accountDepth));
  assert(typeof json.token === 'string');
  assert(json.token.length === 64);
  assert(utils.isNumber(json.tokenDepth));

  this.network = bcoin.network.get(json.network);
  this.wid = json.wid;
  this.id = json.id;
  this.initialized = json.initialized;
  this.accountDepth = json.accountDepth;
  this.token = new Buffer(json.token, 'hex');
  this.master = MasterKey.fromJSON(json.master);

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
  p.writeVarString(this.id, 'utf8');
  p.writeU8(this.initialized ? 1 : 0);
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
  this.network = bcoin.network.fromMagic(p.readU32());
  this.wid = p.readU32();
  this.id = p.readVarString('utf8');
  this.initialized = p.readU8() === 1;
  this.accountDepth = p.readU32();
  this.token = p.readBytes(32);
  this.tokenDepth = p.readU32();
  this.master = MasterKey.fromRaw(p.readVarBytes());
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

/**
 * Master BIP32 key which can exist
 * in a timed out encrypted state.
 * @exports Master
 * @constructor
 * @param {Object} options
 */

function MasterKey(options) {
  if (!(this instanceof MasterKey))
    return new MasterKey(options);

  this.encrypted = false;
  this.iv = null;
  this.ciphertext = null;
  this.key = null;

  this.aesKey = null;
  this.timer = null;
  this.until = 0;
  this._destroy = this.destroy.bind(this);
  this.locker = new bcoin.locker(this);
}

/**
 * Inject properties from options object.
 * @private
 * @param {Object} options
 */

MasterKey.prototype.fromOptions = function fromOptions(options) {
  assert(options);

  if (options.encrypted != null) {
    assert(typeof options.encrypted === 'boolean');
    this.encrypted = options.encrypted;
  }

  if (options.iv) {
    assert(Buffer.isBuffer(options.iv));
    this.iv = options.iv;
  }

  if (options.ciphertext) {
    assert(Buffer.isBuffer(options.ciphertext));
    this.ciphertext = options.ciphertext;
  }

  if (options.key) {
    assert(bcoin.hd.isHD(options.key));
    this.key = options.key;
  }

  assert(this.encrypted ? !this.key : this.key);

  return this;
};

/**
 * Instantiate master key from options.
 * @returns {MasterKey}
 */

MasterKey.fromOptions = function fromOptions(options) {
  return new MasterKey().fromOptions(options);
};

/**
 * Decrypt the key and set a timeout to destroy decrypted data.
 * @param {Buffer|String} passphrase - Zero this yourself.
 * @param {Number} [timeout=60000] timeout in ms.
 * @returns {Promise} - Returns {@link HDPrivateKey}.
 */

MasterKey.prototype.unlock = co(function* _unlock(passphrase, timeout) {
  var unlock = yield this.locker.lock();
  try {
    return yield this._unlock(passphrase, timeout);
  } finally {
    unlock();
  }
});

/**
 * Decrypt the key without a lock.
 * @private
 * @param {Buffer|String} passphrase - Zero this yourself.
 * @param {Number} [timeout=60000] timeout in ms.
 * @returns {Promise} - Returns {@link HDPrivateKey}.
 */

MasterKey.prototype._unlock = co(function* _unlock(passphrase, timeout) {
  var data, key;

  if (this.key)
    return this.key;

  if (!passphrase)
    throw new Error('No passphrase.');

  assert(this.encrypted);

  key = yield crypto.derive(passphrase);
  data = crypto.decipher(this.ciphertext, key, this.iv);

  this.key = bcoin.hd.fromExtended(data);

  this.start(timeout);

  this.aesKey = key;

  return this.key;
});

/**
 * Start the destroy timer.
 * @private
 * @param {Number} [timeout=60000] timeout in ms.
 */

MasterKey.prototype.start = function start(timeout) {
  if (!timeout)
    timeout = 60000;

  this.stop();

  if (timeout === -1)
    return;

  this.until = utils.now() + (timeout / 1000 | 0);
  this.timer = setTimeout(this._destroy, timeout);
};

/**
 * Stop the destroy timer.
 * @private
 */

MasterKey.prototype.stop = function stop() {
  if (this.timer != null) {
    clearTimeout(this.timer);
    this.timer = null;
    this.until = 0;
  }
};

/**
 * Encrypt data with in-memory aes key.
 * @param {Buffer} data
 * @param {Buffer} iv
 * @returns {Buffer}
 */

MasterKey.prototype.encipher = function encipher(data, iv) {
  if (!this.aesKey)
    return;

  if (typeof iv === 'string')
    iv = new Buffer(iv, 'hex');

  return crypto.encipher(data, this.aesKey, iv.slice(0, 16));
};

/**
 * Decrypt data with in-memory aes key.
 * @param {Buffer} data
 * @param {Buffer} iv
 * @returns {Buffer}
 */

MasterKey.prototype.decipher = function decipher(data, iv) {
  if (!this.aesKey)
    return;

  if (typeof iv === 'string')
    iv = new Buffer(iv, 'hex');

  return crypto.decipher(data, this.aesKey, iv.slice(0, 16));
};

/**
 * Destroy the key by zeroing the
 * privateKey and chainCode. Stop
 * the timer if there is one.
 */

MasterKey.prototype.destroy = function destroy() {
  if (!this.encrypted) {
    assert(this.timer == null);
    assert(this.key);
    return;
  }

  this.stop();

  if (this.key) {
    this.key.destroy(true);
    this.key = null;
  }

  if (this.aesKey) {
    this.aesKey.fill(0);
    this.aesKey = null;
  }
};

/**
 * Decrypt the key permanently.
 * @param {Buffer|String} passphrase - Zero this yourself.
 * @returns {Promise}
 */

MasterKey.prototype.decrypt = co(function* decrypt(passphrase) {
  var unlock = yield this.locker.lock();
  try {
    return yield this._decrypt(passphrase);
  } finally {
    unlock();
  }
});

/**
 * Decrypt the key permanently without a lock.
 * @private
 * @param {Buffer|String} passphrase - Zero this yourself.
 * @returns {Promise}
 */

MasterKey.prototype._decrypt = co(function* decrypt(passphrase) {
  var data;

  if (!this.encrypted) {
    assert(this.key);
    return;
  }

  if (!passphrase)
    return;

  this.destroy();

  data = yield crypto.decrypt(this.ciphertext, passphrase, this.iv);

  this.key = bcoin.hd.fromExtended(data);
  this.encrypted = false;
  this.iv = null;
  this.ciphertext = null;
});

/**
 * Encrypt the key permanently.
 * @param {Buffer|String} passphrase - Zero this yourself.
 * @returns {Promise}
 */

MasterKey.prototype.encrypt = co(function* encrypt(passphrase) {
  var unlock = yield this.locker.lock();
  try {
    return yield this._encrypt(passphrase);
  } finally {
    unlock();
  }
});

/**
 * Encrypt the key permanently without a lock.
 * @private
 * @param {Buffer|String} passphrase - Zero this yourself.
 * @returns {Promise}
 */

MasterKey.prototype._encrypt = co(function* encrypt(passphrase) {
  var data, iv;

  if (this.encrypted)
    return;

  if (!passphrase)
    return;

  data = this.key.toExtended();
  iv = crypto.randomBytes(16);

  this.stop();

  data = yield crypto.encrypt(data, passphrase, iv);

  this.key = null;
  this.encrypted = true;
  this.iv = iv;
  this.ciphertext = data;
});

/**
 * Serialize the key in the form of:
 * `[enc-flag][iv?][ciphertext?][extended-key?]`
 * @returns {Buffer}
 */

MasterKey.prototype.toRaw = function toRaw(writer) {
  var p = new BufferWriter(writer);

  if (this.encrypted) {
    p.writeU8(1);
    p.writeVarBytes(this.iv);
    p.writeVarBytes(this.ciphertext);

    // Future-proofing:
    // algorithm (0=pbkdf2, 1=scrypt)
    p.writeU8(0);
    // iterations (pbkdf2) / N (scrypt)
    p.writeU32(50000);
    // r (scrypt)
    p.writeU32(0);
    // p (scrypt)
    p.writeU32(0);

    if (!writer)
      p = p.render();

    return p;
  }

  p.writeU8(0);
  p.writeVarBytes(this.key.toExtended());

  if (!writer)
    p = p.render();

  return p;
};

/**
 * Inject properties from serialized data.
 * @private
 * @param {Buffer} raw
 */

MasterKey.prototype.fromRaw = function fromRaw(raw) {
  var p = new BufferReader(raw);

  this.encrypted = p.readU8() === 1;

  if (this.encrypted) {
    this.iv = p.readVarBytes();
    this.ciphertext = p.readVarBytes();

    // Future-proofing:
    assert(p.readU8() === 0);
    assert(p.readU32() === 50000);
    assert(p.readU32() === 0);
    assert(p.readU32() === 0);

    return this;
  }

  this.key = bcoin.hd.fromExtended(p.readVarBytes());

  return this;
};

/**
 * Instantiate master key from serialized data.
 * @returns {MasterKey}
 */

MasterKey.fromRaw = function fromRaw(raw) {
  return new MasterKey().fromRaw(raw);
};

/**
 * Inject properties from an HDPrivateKey.
 * @private
 * @param {HDPrivateKey} key
 */

MasterKey.prototype.fromKey = function fromKey(key) {
  this.encrypted = false;
  this.iv = null;
  this.ciphertext = null;
  this.key = key;
  return this;
};

/**
 * Instantiate master key from an HDPrivateKey.
 * @param {HDPrivateKey} key
 * @returns {MasterKey}
 */

MasterKey.fromKey = function fromKey(key) {
  return new MasterKey().fromKey(key);
};

/**
 * Convert master key to a jsonifiable object.
 * @returns {Object}
 */

MasterKey.prototype.toJSON = function toJSON() {
  if (this.encrypted) {
    return {
      encrypted: true,
      iv: this.iv.toString('hex'),
      ciphertext: this.ciphertext.toString('hex'),
      // Future-proofing:
      algorithm: 'pbkdf2',
      N: 50000,
      r: 0,
      p: 0
    };
  }

  return {
    encrypted: false,
    key: this.key.toJSON()
  };
};

/**
 * Inject properties from JSON object.
 * @private
 * @param {Object} json
 */

MasterKey.prototype.fromJSON = function fromJSON(json) {
  assert(typeof json.encrypted === 'boolean');

  this.encrypted = json.encrypted;

  if (json.encrypted) {
    assert(typeof json.iv === 'string');
    assert(typeof json.ciphertext === 'string');
    // Future-proofing:
    assert(json.algorithm === 'pbkdf2');
    assert(json.N === 50000);
    assert(json.r === 0);
    assert(json.p === 0);
    this.iv = new Buffer(json.iv, 'hex');
    this.ciphertext = new Buffer(json.ciphertext, 'hex');
  } else {
    this.key = bcoin.hd.fromJSON(json.key);
  }

  return this;
};

/**
 * Instantiate master key from jsonified object.
 * @param {Object} json
 * @returns {MasterKey}
 */

MasterKey.fromJSON = function fromJSON(json) {
  return new MasterKey().fromJSON(json);
};

/**
 * Inspect the key.
 * @returns {Object}
 */

MasterKey.prototype.inspect = function inspect() {
  var json = this.toJSON();
  if (this.key)
    json.key = this.key.toJSON();
  return json;
};

/**
 * Test whether an object is a MasterKey.
 * @param {Object} obj
 * @returns {Boolean}
 */

MasterKey.isMasterKey = function isMasterKey(obj) {
  return obj
    && typeof obj.encrypted === 'boolean'
    && typeof obj.decrypt === 'function';
};

/*
 * Expose
 */

module.exports = Wallet;
