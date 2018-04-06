/*!
 * wallet.js - wallet object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const EventEmitter = require('events');
const {Lock} = require('bmutex');
const {base58} = require('bstring');
const bio = require('bufio');
const hash160 = require('bcrypto/lib/hash160');
const hash256 = require('bcrypto/lib/hash256');
const cleanse = require('bcrypto/lib/cleanse');
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
const {encoding} = bio;
const {Mnemonic} = HD;

/**
 * Wallet
 * @alias module:wallet.Wallet
 * @extends EventEmitter
 */

class Wallet extends EventEmitter {
  /**
   * Create a wallet.
   * @constructor
   * @param {Object} options
   */

  constructor(wdb, options) {
    super();

    assert(wdb, 'WDB required.');

    this.wdb = wdb;
    this.db = wdb.db;
    this.network = wdb.network;
    this.logger = wdb.logger;
    this.writeLock = new Lock();
    this.fundLock = new Lock();

    this.wid = 0;
    this.id = null;
    this.watchOnly = false;
    this.accountDepth = 0;
    this.token = consensus.ZERO_HASH;
    this.tokenDepth = 0;
    this.master = new MasterKey();

    this.txdb = new TXDB(this.wdb);

    if (options)
      this.fromOptions(options);
  }

  /**
   * Inject properties from options object.
   * @private
   * @param {Object} options
   */

  fromOptions(options) {
    if (!options)
      return this;

    let key = options.master;
    let id, token, mnemonic;

    if (key) {
      if (typeof key === 'string')
        key = HD.PrivateKey.fromBase58(key, this.network);

      assert(HD.isPrivate(key),
        'Must create wallet with hd private key.');
    } else {
      mnemonic = new Mnemonic(options.mnemonic);
      key = HD.fromMnemonic(mnemonic, options.password);
    }

    this.master.fromKey(key, mnemonic);

    if (options.wid != null) {
      assert((options.wid >>> 0) === options.wid);
      this.wid = options.wid;
    }

    if (options.id) {
      assert(common.isName(options.id), 'Bad wallet ID.');
      id = options.id;
    }

    if (options.watchOnly != null) {
      assert(typeof options.watchOnly === 'boolean');
      this.watchOnly = options.watchOnly;
    }

    if (options.accountDepth != null) {
      assert((options.accountDepth >>> 0) === options.accountDepth);
      this.accountDepth = options.accountDepth;
    }

    if (options.token) {
      assert(Buffer.isBuffer(options.token));
      assert(options.token.length === 32);
      token = options.token;
    }

    if (options.tokenDepth != null) {
      assert((options.tokenDepth >>> 0) === options.tokenDepth);
      this.tokenDepth = options.tokenDepth;
    }

    if (!id)
      id = this.getID();

    if (!token)
      token = this.getToken(this.tokenDepth);

    this.id = id;
    this.token = token;

    return this;
  }

  /**
   * Instantiate wallet from options.
   * @param {WalletDB} wdb
   * @param {Object} options
   * @returns {Wallet}
   */

  static fromOptions(wdb, options) {
    return new this(wdb).fromOptions(options);
  }

  /**
   * Attempt to intialize the wallet (generating
   * the first addresses along with the lookahead
   * addresses). Called automatically from the
   * walletdb.
   * @returns {Promise}
   */

  async init(options, passphrase) {
    if (passphrase)
      await this.master.encrypt(passphrase);

    const account = await this._createAccount(options, passphrase);
    assert(account);

    this.logger.info('Wallet initialized (%s).', this.id);

    return this.txdb.open(this);
  }

  /**
   * Open wallet (done after retrieval).
   * @returns {Promise}
   */

  async open() {
    const account = await this.getAccount(0);

    if (!account)
      throw new Error('Default account not found.');

    this.logger.info('Wallet opened (%s).', this.id);

    return this.txdb.open(this);
  }

  /**
   * Close the wallet, unregister with the database.
   * @returns {Promise}
   */

  async destroy() {
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
  }

  /**
   * Add a public account key to the wallet (multisig).
   * Saves the key in the wallet database.
   * @param {(Number|String)} acct
   * @param {HDPublicKey} key
   * @returns {Promise}
   */

  async addSharedKey(acct, key) {
    const unlock = await this.writeLock.lock();
    try {
      return await this._addSharedKey(acct, key);
    } finally {
      unlock();
    }
  }

  /**
   * Add a public account key to the wallet without a lock.
   * @private
   * @param {(Number|String)} acct
   * @param {HDPublicKey} key
   * @returns {Promise}
   */

  async _addSharedKey(acct, key) {
    const account = await this.getAccount(acct);

    if (!account)
      throw new Error('Account not found.');

    const b = this.db.batch();
    const result = await account.addSharedKey(b, key);
    await b.write();

    return result;
  }

  /**
   * Remove a public account key from the wallet (multisig).
   * @param {(Number|String)} acct
   * @param {HDPublicKey} key
   * @returns {Promise}
   */

  async removeSharedKey(acct, key) {
    const unlock = await this.writeLock.lock();
    try {
      return await this._removeSharedKey(acct, key);
    } finally {
      unlock();
    }
  }

  /**
   * Remove a public account key from the wallet (multisig).
   * @private
   * @param {(Number|String)} acct
   * @param {HDPublicKey} key
   * @returns {Promise}
   */

  async _removeSharedKey(acct, key) {
    const account = await this.getAccount(acct);

    if (!account)
      throw new Error('Account not found.');

    const b = this.db.batch();
    const result = await account.removeSharedKey(b, key);
    await b.write();

    return result;
  }

  /**
   * Change or set master key's passphrase.
   * @param {String|Buffer} passphrase
   * @param {String|Buffer} old
   * @returns {Promise}
   */

  async setPassphrase(passphrase, old) {
    if (old != null)
      await this.decrypt(old);

    await this.encrypt(passphrase);
  }

  /**
   * Encrypt the wallet permanently.
   * @param {String|Buffer} passphrase
   * @returns {Promise}
   */

  async encrypt(passphrase) {
    const unlock = await this.writeLock.lock();
    try {
      return await this._encrypt(passphrase);
    } finally {
      unlock();
    }
  }

  /**
   * Encrypt the wallet permanently, without a lock.
   * @private
   * @param {String|Buffer} passphrase
   * @returns {Promise}
   */

  async _encrypt(passphrase) {
    const key = await this.master.encrypt(passphrase, true);
    const b = this.db.batch();

    try {
      await this.wdb.encryptKeys(b, this.wid, key);
    } finally {
      cleanse(key);
    }

    this.save(b);

    await b.write();
  }

  /**
   * Decrypt the wallet permanently.
   * @param {String|Buffer} passphrase
   * @returns {Promise}
   */

  async decrypt(passphrase) {
    const unlock = await this.writeLock.lock();
    try {
      return await this._decrypt(passphrase);
    } finally {
      unlock();
    }
  }

  /**
   * Decrypt the wallet permanently, without a lock.
   * @private
   * @param {String|Buffer} passphrase
   * @returns {Promise}
   */

  async _decrypt(passphrase) {
    const key = await this.master.decrypt(passphrase, true);
    const b = this.db.batch();

    try {
      await this.wdb.decryptKeys(b, this.wid, key);
    } finally {
      cleanse(key);
    }

    this.save(b);

    await b.write();
  }

  /**
   * Generate a new token.
   * @param {(String|Buffer)?} passphrase
   * @returns {Promise}
   */

  async retoken(passphrase) {
    const unlock = await this.writeLock.lock();
    try {
      return await this._retoken(passphrase);
    } finally {
      unlock();
    }
  }

  /**
   * Generate a new token without a lock.
   * @private
   * @param {(String|Buffer)?} passphrase
   * @returns {Promise}
   */

  async _retoken(passphrase) {
    if (passphrase)
      await this.unlock(passphrase);

    this.tokenDepth += 1;
    this.token = this.getToken(this.tokenDepth);

    const b = this.db.batch();
    this.save(b);

    await b.write();

    return this.token;
  }

  /**
   * Rename the wallet.
   * @param {String} id
   * @returns {Promise}
   */

  async rename(id) {
    const unlock = await this.writeLock.lock();
    try {
      return await this.wdb.rename(this, id);
    } finally {
      unlock();
    }
  }

  /**
   * Rename account.
   * @param {(String|Number)?} acct
   * @param {String} name
   * @returns {Promise}
   */

  async renameAccount(acct, name) {
    const unlock = await this.writeLock.lock();
    try {
      return await this._renameAccount(acct, name);
    } finally {
      unlock();
    }
  }

  /**
   * Rename account without a lock.
   * @private
   * @param {(String|Number)?} acct
   * @param {String} name
   * @returns {Promise}
   */

  async _renameAccount(acct, name) {
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
  }

  /**
   * Lock the wallet, destroy decrypted key.
   */

  async lock() {
    const unlock1 = await this.writeLock.lock();
    const unlock2 = await this.fundLock.lock();
    try {
      await this.master.lock();
    } finally {
      unlock2();
      unlock1();
    }
  }

  /**
   * Unlock the key for `timeout` seconds.
   * @param {Buffer|String} passphrase
   * @param {Number?} [timeout=60]
   */

  unlock(passphrase, timeout) {
    return this.master.unlock(passphrase, timeout);
  }

  /**
   * Generate the wallet ID if none was passed in.
   * It is represented as HASH160(m/44->public|magic)
   * converted to an "address" with a prefix
   * of `0x03be04` (`WLT` in base58).
   * @private
   * @returns {Base58String}
   */

  getID() {
    assert(this.master.key, 'Cannot derive id.');

    const key = this.master.key.derive(44);

    const bw = bio.write(37);
    bw.writeBytes(key.publicKey);
    bw.writeU32(this.network.magic);

    const hash = hash160.digest(bw.render());

    const b58 = bio.write(27);
    b58.writeU8(0x03);
    b58.writeU8(0xbe);
    b58.writeU8(0x04);
    b58.writeBytes(hash);
    b58.writeChecksum(hash256.digest);

    return base58.encode(b58.render());
  }

  /**
   * Generate the wallet api key if none was passed in.
   * It is represented as HASH256(m/44'->private|nonce).
   * @private
   * @param {HDPrivateKey} master
   * @param {Number} nonce
   * @returns {Buffer}
   */

  getToken(nonce) {
    if (!this.master.key)
      throw new Error('Cannot derive token.');

    const key = this.master.key.derive(44, true);

    const bw = bio.write(36);
    bw.writeBytes(key.privateKey);
    bw.writeU32(nonce);

    return hash256.digest(bw.render());
  }

  /**
   * Create an account. Requires passphrase if master key is encrypted.
   * @param {Object} options - See {@link Account} options.
   * @returns {Promise} - Returns {@link Account}.
   */

  async createAccount(options, passphrase) {
    const unlock = await this.writeLock.lock();
    try {
      return await this._createAccount(options, passphrase);
    } finally {
      unlock();
    }
  }

  /**
   * Create an account without a lock.
   * @param {Object} options - See {@link Account} options.
   * @returns {Promise} - Returns {@link Account}.
   */

  async _createAccount(options, passphrase) {
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
    } else {
      assert(this.master.key);
      const type = this.network.keyPrefix.coinType;
      key = this.master.key.deriveAccount(44, type, this.accountDepth);
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

    this.accountDepth += 1;
    this.save(b);

    if (this.accountDepth === 1)
      this.increment(b);

    await b.write();

    return account;
  }

  /**
   * Ensure an account. Requires passphrase if master key is encrypted.
   * @param {Object} options - See {@link Account} options.
   * @returns {Promise} - Returns {@link Account}.
   */

  async ensureAccount(options, passphrase) {
    const name = options.name;
    const account = await this.getAccount(name);

    if (account)
      return account;

    return this.createAccount(options, passphrase);
  }

  /**
   * List account names and indexes from the db.
   * @returns {Promise} - Returns Array.
   */

  getAccounts() {
    return this.wdb.getAccounts(this.wid);
  }

  /**
   * Get all wallet address hashes.
   * @param {(String|Number)?} acct
   * @returns {Promise} - Returns Array.
   */

  getAddressHashes(acct) {
    if (acct != null)
      return this.getAccountHashes(acct);
    return this.wdb.getWalletHashes(this.wid);
  }

  /**
   * Get all account address hashes.
   * @param {String|Number} acct
   * @returns {Promise} - Returns Array.
   */

  async getAccountHashes(acct) {
    const index = await this.getAccountIndex(acct);

    if (index === -1)
      throw new Error('Account not found.');

    return this.wdb.getAccountHashes(this.wid, index);
  }

  /**
   * Retrieve an account from the database.
   * @param {Number|String} acct
   * @returns {Promise} - Returns {@link Account}.
   */

  async getAccount(acct) {
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
  }

  /**
   * Lookup the corresponding account name's index.
   * @param {String|Number} acct - Account name/index.
   * @returns {Promise} - Returns Number.
   */

  getAccountIndex(acct) {
    if (acct == null)
      return -1;

    if (typeof acct === 'number')
      return acct;

    return this.wdb.getAccountIndex(this.wid, acct);
  }

  /**
   * Lookup the corresponding account name's index.
   * @param {String|Number} acct - Account name/index.
   * @returns {Promise} - Returns Number.
   * @throws on non-existent account
   */

  async ensureIndex(acct) {
    if (acct == null || acct === -1)
      return -1;

    const index = await this.getAccountIndex(acct);

    if (index === -1)
      throw new Error('Account not found.');

    return index;
  }

  /**
   * Lookup the corresponding account index's name.
   * @param {Number} index - Account index.
   * @returns {Promise} - Returns String.
   */

  async getAccountName(index) {
    if (typeof index === 'string')
      return index;

    return this.wdb.getAccountName(this.wid, index);
  }

  /**
   * Test whether an account exists.
   * @param {Number|String} acct
   * @returns {Promise} - Returns {@link Boolean}.
   */

  async hasAccount(acct) {
    const index = await this.getAccountIndex(acct);

    if (index === -1)
      return false;

    return this.wdb.hasAccount(this.wid, index);
  }

  /**
   * Create a new receiving address (increments receiveDepth).
   * @param {(Number|String)?} acct
   * @returns {Promise} - Returns {@link WalletKey}.
   */

  createReceive(acct = 0) {
    return this.createKey(acct, 0);
  }

  /**
   * Create a new change address (increments receiveDepth).
   * @param {(Number|String)?} acct
   * @returns {Promise} - Returns {@link WalletKey}.
   */

  createChange(acct = 0) {
    return this.createKey(acct, 1);
  }

  /**
   * Create a new nested address (increments receiveDepth).
   * @param {(Number|String)?} acct
   * @returns {Promise} - Returns {@link WalletKey}.
   */

  createNested(acct = 0) {
    return this.createKey(acct, 2);
  }

  /**
   * Create a new address (increments depth).
   * @param {(Number|String)?} acct
   * @param {Number} branch
   * @returns {Promise} - Returns {@link WalletKey}.
   */

  async createKey(acct, branch) {
    const unlock = await this.writeLock.lock();
    try {
      return await this._createKey(acct, branch);
    } finally {
      unlock();
    }
  }

  /**
   * Create a new address (increments depth) without a lock.
   * @private
   * @param {(Number|String)?} acct
   * @param {Number} branche
   * @returns {Promise} - Returns {@link WalletKey}.
   */

  async _createKey(acct, branch) {
    const account = await this.getAccount(acct);

    if (!account)
      throw new Error('Account not found.');

    const b = this.db.batch();
    const key = await account.createKey(b, branch);
    await b.write();

    return key;
  }

  /**
   * Save the wallet to the database. Necessary
   * when address depth and keys change.
   * @returns {Promise}
   */

  save(b) {
    return this.wdb.save(b, this);
  }

  /**
   * Increment the wid depth.
   * @returns {Promise}
   */

  increment(b) {
    return this.wdb.increment(b, this.wid);
  }

  /**
   * Test whether the wallet possesses an address.
   * @param {Address|Hash} address
   * @returns {Promise} - Returns Boolean.
   */

  async hasAddress(address) {
    const hash = Address.getHash(address, 'hex');
    const path = await this.getPath(hash);
    return path != null;
  }

  /**
   * Get path by address hash.
   * @param {Address|Hash} address
   * @returns {Promise} - Returns {@link Path}.
   */

  async getPath(address) {
    const hash = Address.getHash(address, 'hex');
    return this.wdb.getPath(this.wid, hash);
  }

  /**
   * Get path by address hash (without account name).
   * @private
   * @param {Address|Hash} address
   * @returns {Promise} - Returns {@link Path}.
   */

  async readPath(address) {
    const hash = Address.getHash(address, 'hex');
    return this.wdb.readPath(this.wid, hash);
  }

  /**
   * Test whether the wallet contains a path.
   * @param {Address|Hash} address
   * @returns {Promise} - Returns {Boolean}.
   */

  async hasPath(address) {
    const hash = Address.getHash(address, 'hex');
    return this.wdb.hasPath(this.wid, hash);
  }

  /**
   * Get all wallet paths.
   * @param {(String|Number)?} acct
   * @returns {Promise} - Returns {@link Path}.
   */

  async getPaths(acct) {
    if (acct != null)
      return this.getAccountPaths(acct);

    return this.wdb.getWalletPaths(this.wid);
  }

  /**
   * Get all account paths.
   * @param {String|Number} acct
   * @returns {Promise} - Returns {@link Path}.
   */

  async getAccountPaths(acct) {
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
  }

  /**
   * Import a keyring (will not exist on derivation chain).
   * Rescanning must be invoked manually.
   * @param {(String|Number)?} acct
   * @param {WalletKey} ring
   * @param {(String|Buffer)?} passphrase
   * @returns {Promise}
   */

  async importKey(acct, ring, passphrase) {
    const unlock = await this.writeLock.lock();
    try {
      return await this._importKey(acct, ring, passphrase);
    } finally {
      unlock();
    }
  }

  /**
   * Import a keyring (will not exist on derivation chain) without a lock.
   * @private
   * @param {(String|Number)?} acct
   * @param {WalletKey} ring
   * @param {(String|Buffer)?} passphrase
   * @returns {Promise}
   */

  async _importKey(acct, ring, passphrase) {
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
  }

  /**
   * Import a keyring (will not exist on derivation chain).
   * Rescanning must be invoked manually.
   * @param {(String|Number)?} acct
   * @param {WalletKey} ring
   * @param {(String|Buffer)?} passphrase
   * @returns {Promise}
   */

  async importAddress(acct, address) {
    const unlock = await this.writeLock.lock();
    try {
      return await this._importAddress(acct, address);
    } finally {
      unlock();
    }
  }

  /**
   * Import a keyring (will not exist on derivation chain) without a lock.
   * @private
   * @param {(String|Number)?} acct
   * @param {WalletKey} ring
   * @param {(String|Buffer)?} passphrase
   * @returns {Promise}
   */

  async _importAddress(acct, address) {
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
  }

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

  async fund(mtx, options, force) {
    const unlock = await this.fundLock.lock(force);
    try {
      return await this._fund(mtx, options);
    } finally {
      unlock();
    }
  }

  /**
   * Fill a transaction with inputs without a lock.
   * @private
   * @see MTX#selectCoins
   * @see MTX#fill
   */

  async _fund(mtx, options) {
    if (!options)
      options = {};

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
  }

  /**
   * Get account by address.
   * @param {Address} address
   * @returns {Account}
   */

  async getAccountByAddress(address) {
    const hash = Address.getHash(address, 'hex');
    const path = await this.getPath(hash);

    if (!path)
      return null;

    return this.getAccount(path.account);
  }

  /**
   * Input size estimator for max possible tx size.
   * @param {Script} prev
   * @returns {Number}
   */

  async estimateSize(prev) {
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
  }

  /**
   * Build a transaction, fill it with outputs and inputs,
   * sort the members according to BIP69 (set options.sort=false
   * to avoid sorting), set locktime, and template it.
   * @param {Object} options - See {@link Wallet#fund options}.
   * @param {Object[]} options.outputs - See {@link MTX#addOutput}.
   * @returns {Promise} - Returns {@link MTX}.
   */

  async createTX(options, force) {
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
  }

  /**
   * Build a transaction, fill it with outputs and inputs,
   * sort the members according to BIP69, set locktime,
   * sign and broadcast. Doing this all in one go prevents
   * coins from being double spent.
   * @param {Object} options - See {@link Wallet#fund options}.
   * @param {Object[]} options.outputs - See {@link MTX#addOutput}.
   * @returns {Promise} - Returns {@link TX}.
   */

  async send(options, passphrase) {
    const unlock = await this.fundLock.lock();
    try {
      return await this._send(options, passphrase);
    } finally {
      unlock();
    }
  }

  /**
   * Build and send a transaction without a lock.
   * @private
   * @param {Object} options - See {@link Wallet#fund options}.
   * @param {Object[]} options.outputs - See {@link MTX#addOutput}.
   * @returns {Promise} - Returns {@link TX}.
   */

  async _send(options, passphrase) {
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
  }

  /**
   * Intentionally double-spend outputs by
   * increasing fee for an existing transaction.
   * @param {Hash} hash
   * @param {Rate} rate
   * @param {(String|Buffer)?} passphrase
   * @returns {Promise} - Returns {@link TX}.
   */

  async increaseFee(hash, rate, passphrase) {
    assert((rate >>> 0) === rate, 'Rate must be a number.');

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
  }

  /**
   * Resend pending wallet transactions.
   * @returns {Promise}
   */

  async resend() {
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
  }

  /**
   * Derive necessary addresses for signing a transaction.
   * @param {MTX} mtx
   * @param {Number?} index - Input index.
   * @returns {Promise} - Returns {@link WalletKey}[].
   */

  async deriveInputs(mtx) {
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
  }

  /**
   * Retrieve a single keyring by address.
   * @param {Address|Hash} hash
   * @returns {Promise}
   */

  async getKey(address) {
    const hash = Address.getHash(address, 'hex');
    const path = await this.getPath(hash);

    if (!path)
      return null;

    const account = await this.getAccount(path.account);

    if (!account)
      return null;

    return account.derivePath(path, this.master);
  }

  /**
   * Retrieve a single keyring by address
   * (with the private key reference).
   * @param {Address|Hash} hash
   * @param {(Buffer|String)?} passphrase
   * @returns {Promise}
   */

  async getPrivateKey(address, passphrase) {
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
  }

  /**
   * Map input addresses to paths.
   * @param {MTX} mtx
   * @returns {Promise} - Returns {@link Path}[].
   */

  async getInputPaths(mtx) {
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
  }

  /**
   * Map output addresses to paths.
   * @param {TX} tx
   * @returns {Promise} - Returns {@link Path}[].
   */

  async getOutputPaths(tx) {
    const paths = [];
    const hashes = tx.getOutputHashes('hex');

    for (const hash of hashes) {
      const path = await this.getPath(hash);
      if (path)
        paths.push(path);
    }

    return paths;
  }

  /**
   * Increase lookahead for account.
   * @param {(Number|String)?} account
   * @param {Number} lookahead
   * @returns {Promise}
   */

  async setLookahead(acct, lookahead) {
    const unlock = await this.writeLock.lock();
    try {
      return this._setLookahead(acct, lookahead);
    } finally {
      unlock();
    }
  }

  /**
   * Increase lookahead for account (without a lock).
   * @private
   * @param {(Number|String)?} account
   * @param {Number} lookahead
   * @returns {Promise}
   */

  async _setLookahead(acct, lookahead) {
    const account = await this.getAccount(acct);

    if (!account)
      throw new Error('Account not found.');

    const b = this.db.batch();
    await account.setLookahead(b, lookahead);
    await b.write();
  }

  /**
   * Sync address depths based on a transaction's outputs.
   * This is used for deriving new addresses when
   * a confirmed transaction is seen.
   * @param {TX} tx
   * @returns {Promise}
   */

  async syncOutputDepth(tx) {
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
  }

  /**
   * Build input scripts templates for a transaction (does not
   * sign, only creates signature slots). Only builds scripts
   * for inputs that are redeemable by this wallet.
   * @param {MTX} mtx
   * @returns {Promise} - Returns Number
   * (total number of scripts built).
   */

  async template(mtx) {
    const rings = await this.deriveInputs(mtx);
    return mtx.template(rings);
  }

  /**
   * Build input scripts and sign inputs for a transaction. Only attempts
   * to build/sign inputs that are redeemable by this wallet.
   * @param {MTX} tx
   * @param {Object|String|Buffer} options - Options or passphrase.
   * @returns {Promise} - Returns Number (total number
   * of inputs scripts built and signed).
   */

  async sign(mtx, passphrase) {
    if (this.watchOnly)
      throw new Error('Cannot sign from a watch-only wallet.');

    await this.unlock(passphrase);

    const rings = await this.deriveInputs(mtx);

    return mtx.signAsync(rings, Script.hashType.ALL, this.wdb.workers);
  }

  /**
   * Get a coin viewpoint.
   * @param {TX} tx
   * @returns {Promise} - Returns {@link CoinView}.
   */

  getCoinView(tx) {
    return this.txdb.getCoinView(tx);
  }

  /**
   * Get a historical coin viewpoint.
   * @param {TX} tx
   * @returns {Promise} - Returns {@link CoinView}.
   */

  getSpentView(tx) {
    return this.txdb.getSpentView(tx);
  }

  /**
   * Convert transaction to transaction details.
   * @param {TXRecord} wtx
   * @returns {Promise} - Returns {@link Details}.
   */

  toDetails(wtx) {
    return this.txdb.toDetails(wtx);
  }

  /**
   * Get transaction details.
   * @param {Hash} hash
   * @returns {Promise} - Returns {@link Details}.
   */

  getDetails(hash) {
    return this.txdb.getDetails(hash);
  }

  /**
   * Get a coin from the wallet.
   * @param {Hash} hash
   * @param {Number} index
   * @returns {Promise} - Returns {@link Coin}.
   */

  getCoin(hash, index) {
    return this.txdb.getCoin(hash, index);
  }

  /**
   * Get a transaction from the wallet.
   * @param {Hash} hash
   * @returns {Promise} - Returns {@link TX}.
   */

  getTX(hash) {
    return this.txdb.getTX(hash);
  }

  /**
   * List blocks for the wallet.
   * @returns {Promise} - Returns {@link BlockRecord}.
   */

  getBlocks() {
    return this.txdb.getBlocks();
  }

  /**
   * Get a block from the wallet.
   * @param {Number} height
   * @returns {Promise} - Returns {@link BlockRecord}.
   */

  getBlock(height) {
    return this.txdb.getBlock(height);
  }

  /**
   * Add a transaction to the wallets TX history.
   * @param {TX} tx
   * @returns {Promise}
   */

  async add(tx, block) {
    const unlock = await this.writeLock.lock();
    try {
      return await this._add(tx, block);
    } finally {
      unlock();
    }
  }

  /**
   * Add a transaction to the wallet without a lock.
   * Potentially resolves orphans.
   * @private
   * @param {TX} tx
   * @returns {Promise}
   */

  async _add(tx, block) {
    const details = await this.txdb.add(tx, block);

    if (details) {
      const derived = await this.syncOutputDepth(tx);
      if (derived.length > 0) {
        this.wdb.emit('address', this, derived);
        this.emit('address', derived);
      }
    }

    return details;
  }

  /**
   * Revert a block.
   * @param {Number} height
   * @returns {Promise}
   */

  async revert(height) {
    const unlock = await this.writeLock.lock();
    try {
      return await this.txdb.revert(height);
    } finally {
      unlock();
    }
  }

  /**
   * Remove a wallet transaction.
   * @param {Hash} hash
   * @returns {Promise}
   */

  async remove(hash) {
    const unlock = await this.writeLock.lock();
    try {
      return await this.txdb.remove(hash);
    } finally {
      unlock();
    }
  }

  /**
   * Zap stale TXs from wallet.
   * @param {(Number|String)?} acct
   * @param {Number} age - Age threshold (unix time, default=72 hours).
   * @returns {Promise}
   */

  async zap(acct, age) {
    const unlock = await this.writeLock.lock();
    try {
      return await this._zap(acct, age);
    } finally {
      unlock();
    }
  }

  /**
   * Zap stale TXs from wallet without a lock.
   * @private
   * @param {(Number|String)?} acct
   * @param {Number} age
   * @returns {Promise}
   */

  async _zap(acct, age) {
    const account = await this.ensureIndex(acct);
    return this.txdb.zap(account, age);
  }

  /**
   * Abandon transaction.
   * @param {Hash} hash
   * @returns {Promise}
   */

  async abandon(hash) {
    const unlock = await this.writeLock.lock();
    try {
      return await this._abandon(hash);
    } finally {
      unlock();
    }
  }

  /**
   * Abandon transaction without a lock.
   * @private
   * @param {Hash} hash
   * @returns {Promise}
   */

  _abandon(hash) {
    return this.txdb.abandon(hash);
  }

  /**
   * Lock a single coin.
   * @param {Coin|Outpoint} coin
   */

  lockCoin(coin) {
    return this.txdb.lockCoin(coin);
  }

  /**
   * Unlock a single coin.
   * @param {Coin|Outpoint} coin
   */

  unlockCoin(coin) {
    return this.txdb.unlockCoin(coin);
  }

  /**
   * Test locked status of a single coin.
   * @param {Coin|Outpoint} coin
   */

  isLocked(coin) {
    return this.txdb.isLocked(coin);
  }

  /**
   * Return an array of all locked outpoints.
   * @returns {Outpoint[]}
   */

  getLocked() {
    return this.txdb.getLocked();
  }

  /**
   * Get all transactions in transaction history.
   * @param {(String|Number)?} acct
   * @returns {Promise} - Returns {@link TX}[].
   */

  async getHistory(acct) {
    const account = await this.ensureIndex(acct);
    return this.txdb.getHistory(account);
  }

  /**
   * Get all available coins.
   * @param {(String|Number)?} account
   * @returns {Promise} - Returns {@link Coin}[].
   */

  async getCoins(acct) {
    const account = await this.ensureIndex(acct);
    return this.txdb.getCoins(account);
  }

  /**
   * Get all available credits.
   * @param {(String|Number)?} account
   * @returns {Promise} - Returns {@link Credit}[].
   */

  async getCredits(acct) {
    const account = await this.ensureIndex(acct);
    return this.txdb.getCredits(account);
  }

  /**
   * Get "smart" coins.
   * @param {(String|Number)?} account
   * @returns {Promise} - Returns {@link Coin}[].
   */

  async getSmartCoins(acct) {
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
  }

  /**
   * Get all pending/unconfirmed transactions.
   * @param {(String|Number)?} acct
   * @returns {Promise} - Returns {@link TX}[].
   */

  async getPending(acct) {
    const account = await this.ensureIndex(acct);
    return this.txdb.getPending(account);
  }

  /**
   * Get wallet balance.
   * @param {(String|Number)?} acct
   * @returns {Promise} - Returns {@link Balance}.
   */

  async getBalance(acct) {
    const account = await this.ensureIndex(acct);
    return this.txdb.getBalance(account);
  }

  /**
   * Get a range of transactions between two timestamps.
   * @param {(String|Number)?} acct
   * @param {Object} options
   * @param {Number} options.start
   * @param {Number} options.end
   * @returns {Promise} - Returns {@link TX}[].
   */

  async getRange(acct, options) {
    const account = await this.ensureIndex(acct);
    return this.txdb.getRange(account, options);
  }

  /**
   * Get the last N transactions.
   * @param {(String|Number)?} acct
   * @param {Number} limit
   * @returns {Promise} - Returns {@link TX}[].
   */

  async getLast(acct, limit) {
    const account = await this.ensureIndex(acct);
    return this.txdb.getLast(account, limit);
  }

  /**
   * Get account key.
   * @param {Number} [acct=0]
   * @returns {HDPublicKey}
   */

  async accountKey(acct = 0) {
    const account = await this.getAccount(acct);
    if (!account)
      throw new Error('Account not found.');
    return account.accountKey;
  }

  /**
   * Get current receive depth.
   * @param {Number} [acct=0]
   * @returns {Number}
   */

  async receiveDepth(acct = 0) {
    const account = await this.getAccount(acct);
    if (!account)
      throw new Error('Account not found.');
    return account.receiveDepth;
  }

  /**
   * Get current change depth.
   * @param {Number} [acct=0]
   * @returns {Number}
   */

  async changeDepth(acct = 0) {
    const account = await this.getAccount(acct);
    if (!account)
      throw new Error('Account not found.');
    return account.changeDepth;
  }

  /**
   * Get current nested depth.
   * @param {Number} [acct=0]
   * @returns {Number}
   */

  async nestedDepth(acct = 0) {
    const account = await this.getAccount(acct);
    if (!account)
      throw new Error('Account not found.');
    return account.nestedDepth;
  }

  /**
   * Get current receive address.
   * @param {Number} [acct=0]
   * @returns {Address}
   */

  async receiveAddress(acct = 0) {
    const account = await this.getAccount(acct);
    if (!account)
      throw new Error('Account not found.');
    return account.receiveAddress();
  }

  /**
   * Get current change address.
   * @param {Number} [acct=0]
   * @returns {Address}
   */

  async changeAddress(acct = 0) {
    const account = await this.getAccount(acct);
    if (!account)
      throw new Error('Account not found.');
    return account.changeAddress();
  }

  /**
   * Get current nested address.
   * @param {Number} [acct=0]
   * @returns {Address}
   */

  async nestedAddress(acct = 0) {
    const account = await this.getAccount(acct);
    if (!account)
      throw new Error('Account not found.');
    return account.nestedAddress();
  }

  /**
   * Get current receive key.
   * @param {Number} [acct=0]
   * @returns {WalletKey}
   */

  async receiveKey(acct = 0) {
    const account = await this.getAccount(acct);
    if (!account)
      throw new Error('Account not found.');
    return account.receiveKey();
  }

  /**
   * Get current change key.
   * @param {Number} [acct=0]
   * @returns {WalletKey}
   */

  async changeKey(acct = 0) {
    const account = await this.getAccount(acct);
    if (!account)
      throw new Error('Account not found.');
    return account.changeKey();
  }

  /**
   * Get current nested key.
   * @param {Number} [acct=0]
   * @returns {WalletKey}
   */

  async nestedKey(acct = 0) {
    const account = await this.getAccount(acct);
    if (!account)
      throw new Error('Account not found.');
    return account.nestedKey();
  }

  /**
   * Convert the wallet to a more inspection-friendly object.
   * @returns {Object}
   */

  inspect() {
    return {
      wid: this.wid,
      id: this.id,
      network: this.network.type,
      accountDepth: this.accountDepth,
      token: this.token.toString('hex'),
      tokenDepth: this.tokenDepth,
      master: this.master
    };
  }

  /**
   * Convert the wallet to an object suitable for
   * serialization.
   * @param {Boolean?} unsafe - Whether to include
   * the master key in the JSON.
   * @returns {Object}
   */

  toJSON(unsafe, balance) {
    return {
      network: this.network.type,
      wid: this.wid,
      id: this.id,
      watchOnly: this.watchOnly,
      accountDepth: this.accountDepth,
      token: this.token.toString('hex'),
      tokenDepth: this.tokenDepth,
      master: this.master.toJSON(this.network, unsafe),
      balance: balance ? balance.toJSON(true) : null
    };
  }

  /**
   * Calculate serialization size.
   * @returns {Number}
   */

  getSize() {
    let size = 0;
    size += 41;
    size += this.master.getSize();
    return size;
  }

  /**
   * Serialize the wallet.
   * @returns {Buffer}
   */

  toRaw() {
    const size = this.getSize();
    const bw = bio.write(size);

    let flags = 0;

    if (this.watchOnly)
      flags |= 1;

    bw.writeU8(flags);
    bw.writeU32(this.accountDepth);
    bw.writeBytes(this.token);
    bw.writeU32(this.tokenDepth);
    this.master.toWriter(bw);

    return bw.render();
  }

  /**
   * Inject properties from serialized data.
   * @private
   * @param {Buffer} data
   */

  fromRaw(data) {
    const br = bio.read(data);

    const flags = br.readU8();

    this.watchOnly = (flags & 1) !== 0;
    this.accountDepth = br.readU32();
    this.token = br.readBytes(32);
    this.tokenDepth = br.readU32();
    this.master.fromReader(br);

    return this;
  }

  /**
   * Instantiate a wallet from serialized data.
   * @param {Buffer} data
   * @returns {Wallet}
   */

  static fromRaw(wdb, data) {
    return new this(wdb).fromRaw(data);
  }

  /**
   * Test an object to see if it is a Wallet.
   * @param {Object} obj
   * @returns {Boolean}
   */

  static isWallet(obj) {
    return obj instanceof Wallet;
  }
}

/*
 * Expose
 */

module.exports = Wallet;
