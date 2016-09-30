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
  this.workerPool = db.workerPool;
  this.writeLock = new bcoin.locker(this);
  this.fundLock = new bcoin.locker(this);

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
 * Invoke write mutex lock.
 * @private
 */

Wallet.prototype._lockWrite = function _lockWrite(func, args, force) {
  return this.writeLock.lock(func, args, force);
};

/**
 * Invoke funding mutex lock.
 * @private
 */

Wallet.prototype._lockFund = function _lockFund(func, args, force) {
  return this.fundLock.lock(func, args, force);
};

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
 * @param {Function} callback
 */

Wallet.prototype.init = function init(options, callback) {
  var self = this;

  assert(!this.initialized);
  this.initialized = true;

  this.master.encrypt(options.passphrase, function(err) {
    if (err)
      return callback(err);

    self.createAccount(options, function(err, account) {
      if (err)
        return callback(err);

      assert(account);

      self.account = account;

      self.logger.info('Wallet initialized (%s).', self.id);

      self.tx.open(callback);
    });
  });
};

/**
 * Open wallet (done after retrieval).
 * @param {Function} callback
 */

Wallet.prototype.open = function open(callback) {
  var self = this;

  assert(this.initialized);

  this.getAccount(0, function(err, account) {
    if (err)
      return callback(err);

    if (!account)
      return callback(new Error('Default account not found.'));

    self.account = account;

    self.logger.info('Wallet opened (%s).', self.id);

    self.tx.open(callback);
  });
};

/**
 * Close the wallet, unregister with the database.
 * @param {Function} callback
 */

Wallet.prototype.destroy = function destroy(callback) {
  callback = utils.ensure(callback);

  try {
    this.db.unregister(this);
    this.master.destroy();
  } catch (e) {
    this.emit('error', e);
    return callback(e);
  }

  return utils.nextTick(callback);
};

/**
 * Add a public account key to the wallet (multisig).
 * Saves the key in the wallet database.
 * @param {HDPublicKey} key
 * @param {Function} callback
 */

Wallet.prototype.addKey = function addKey(account, key, callback) {
  var self = this;

  if (typeof key === 'function') {
    callback = key;
    key = account;
    account = null;
  }

  if (account == null)
    account = 0;

  callback = this._lockWrite(addKey, [account, key, callback]);

  if (!callback)
    return;

  this.getAccount(account, function(err, account) {
    if (err)
      return callback(err);

    if (!account)
      return callback(new Error('Account not found.'));

    self.start();

    account.addKey(key, function(err, result) {
      if (err) {
        self.drop();
        return callback(err);
      }
      self.commit(function(err) {
        if (err)
          return callback(err);
        callback(null, result);
      });
    });
  }, true);
};

/**
 * Remove a public account key from the wallet (multisig).
 * Remove the key from the wallet database.
 * @param {HDPublicKey} key
 * @param {Function} callback
 */

Wallet.prototype.removeKey = function removeKey(account, key, callback) {
  var self = this;

  if (typeof key === 'function') {
    callback = key;
    key = account;
    account = null;
  }

  if (account == null)
    account = 0;

  callback = this._lockWrite(removeKey, [account, key, callback]);

  if (!callback)
    return;

  this.getAccount(account, function(err, account) {
    if (err)
      return callback(err);

    if (!account)
      return callback(new Error('Account not found.'));

    self.start();

    account.removeKey(key, function(err, result) {
      if (err) {
        self.drop();
        return callback(err);
      }
      self.commit(function(err) {
        if (err)
          return callback(err);
        callback(null, result);
      });
    });
  }, true);
};

/**
 * Change or set master key's passphrase.
 * @param {(String|Buffer)?} old
 * @param {String|Buffer} new_
 * @param {Function} callback
 */

Wallet.prototype.setPassphrase = function setPassphrase(old, new_, callback) {
  var self = this;

  if (typeof new_ === 'function') {
    callback = new_;
    new_ = old;
    old = null;
  }

  callback = this._lockWrite(setPassphrase, [old, new_, callback]);

  if (!callback)
    return;

  this.master.decrypt(old, function(err) {
    if (err)
      return callback(err);

    self.master.encrypt(new_, function(err) {
      if (err)
        return callback(err);

      self.start();
      self.save();
      self.commit(callback);
    });
  });
};

/**
 * Generate a new token.
 * @param {(String|Buffer)?} passphrase
 * @param {Function} callback
 */

Wallet.prototype.retoken = function retoken(passphrase, callback) {
  var self = this;

  if (typeof passphrase === 'function') {
    callback = passphrase;
    passphrase = null;
  }

  callback = this._lockWrite(retoken, [passphrase, callback]);

  if (!callback)
    return;

  this.unlock(passphrase, null, function(err, master) {
    if (err)
      return callback(err);

    self.tokenDepth++;
    self.token = self.getToken(master, self.tokenDepth);

    self.start();
    self.save();
    self.commit(function(err) {
      if (err)
        return callback(err);
      callback(null, self.token);
    });
  });
};

/**
 * Lock the wallet, destroy decrypted key.
 */

Wallet.prototype.lock = function lock() {
  this.master.destroy();
};

/**
 * Unlock the key for `timeout` milliseconds.
 * @param {Buffer|String} passphrase
 * @param {Number?} [timeout=60000] - ms.
 */

Wallet.prototype.unlock = function unlock(passphrase, timeout, callback) {
  this.master.unlock(passphrase, timeout, callback);
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
 * @param {Function} callback - Returns [Error, {@link Account}].
 */

Wallet.prototype.createAccount = function createAccount(options, callback) {
  var self = this;
  var passphrase = options.passphrase;
  var timeout = options.timeout;
  var name = options.name;
  var key;

  callback = this._lockWrite(createAccount, [options, callback]);

  if (!callback)
    return;

  if (typeof options.account === 'string')
    name = options.account;

  if (!name)
    name = self.accountDepth + '';

  this.unlock(passphrase, timeout, function(err, master) {
    if (err)
      return callback(err);

    key = master.deriveAccount44(self.accountDepth);

    options = {
      network: self.network,
      wid: self.wid,
      id: self.id,
      name: self.accountDepth === 0 ? 'default' : name,
      witness: options.witness,
      accountKey: key.hdPublicKey,
      accountIndex: self.accountDepth,
      type: options.type,
      keys: options.keys,
      m: options.m,
      n: options.n
    };

    self.start();

    self.db.createAccount(options, function(err, account) {
      if (err) {
        self.drop();
        return callback(err);
      }

      self.accountDepth++;
      self.save();
      self.commit(function(err) {
        if (err)
          return callback(err);
        callback(null, account);
      });
    });
  });
};

/**
 * Ensure an account. Requires passphrase if master key is encrypted.
 * @param {Object} options - See {@link Account} options.
 * @param {Function} callback - Returns [Error, {@link Account}].
 */

Wallet.prototype.ensureAccount = function ensureAccount(options, callback) {
  var self = this;
  var account = options.account;

  if (typeof options.name === 'string')
    account = options.name;

  this.hasAccount(account, function(err, exists) {
    if (err)
      return callback(err);

    if (exists)
      return self.getAccount(account, callback);

    self.createAccount(options, callback);
  });
};

/**
 * List account names and indexes from the db.
 * @param {Function} callback - Returns [Error, Array].
 */

Wallet.prototype.getAccounts = function getAccounts(callback) {
  this.db.getAccounts(this.wid, callback);
};

/**
 * Get all wallet address hashes.
 * @param {Function} callback - Returns [Error, Array].
 */

Wallet.prototype.getAddressHashes = function getAddressHashes(callback) {
  this.db.getAddressHashes(this.wid, callback);
};

/**
 * Retrieve an account from the database.
 * @param {Number|String} account
 * @param {Function} callback - Returns [Error, {@link Account}].
 */

Wallet.prototype.getAccount = function getAccount(account, callback) {
  var self = this;

  if (this.account) {
    if (account === 0 || account === 'default')
      return callback(null, this.account);
  }

  this.db.getAccount(this.wid, account, function(err, account) {
    if (err)
      return callback(err);

    if (!account)
      return callback();

    account.wid = self.wid;
    account.id = self.id;

    callback(null, account);
  });
};

/**
 * Test whether an account exists.
 * @param {Number|String} account
 * @param {Function} callback - Returns [Error, {@link Boolean}].
 */

Wallet.prototype.hasAccount = function hasAccount(account, callback) {
  this.db.hasAccount(this.wid, account, callback);
};

/**
 * Create a new receiving address (increments receiveDepth).
 * @param {(Number|String)?} account
 * @param {Function} callback - Returns [Error, {@link KeyRing}].
 */

Wallet.prototype.createReceive = function createReceive(account, callback) {
  if (typeof account === 'function') {
    callback = account;
    account = null;
  }
  return this.createAddress(account, false, callback);
};

/**
 * Create a new change address (increments receiveDepth).
 * @param {(Number|String)?} account
 * @param {Function} callback - Returns [Error, {@link KeyRing}].
 */

Wallet.prototype.createChange = function createChange(account, callback) {
  if (typeof account === 'function') {
    callback = account;
    account = null;
  }
  return this.createAddress(account, true, callback);
};

/**
 * Create a new address (increments depth).
 * @param {(Number|String)?} account
 * @param {Boolean} change
 * @param {Function} callback - Returns [Error, {@link KeyRing}].
 */

Wallet.prototype.createAddress = function createAddress(account, change, callback) {
  var self = this;

  if (typeof change === 'function') {
    callback = change;
    change = account;
    account = null;
  }

  if (account == null)
    account = 0;

  callback = this._lockWrite(createAddress, [account, change, callback]);

  if (!callback)
    return;

  this.getAccount(account, function(err, account) {
    if (err)
      return callback(err);

    if (!account)
      return callback(new Error('Account not found.'));

    self.start();

    account.createAddress(change, function(err, result) {
      if (err) {
        self.drop();
        return callback(err);
      }
      self.commit(function(err) {
        if (err)
          return callback(err);
        callback(null, result);
      });
    });
  }, true);
};

/**
 * Save the wallet to the database. Necessary
 * when address depth and keys change.
 * @param {Function} callback
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
 * @param {Function} callback
 */

Wallet.prototype.commit = function commit(callback) {
  return this.db.commit(this.wid, callback);
};

/**
 * Test whether the wallet possesses an address.
 * @param {Address|Hash} address
 * @param {Function} callback - Returns [Error, Boolean].
 */

Wallet.prototype.hasAddress = function hasAddress(address, callback) {
  var hash = bcoin.address.getHash(address, 'hex');
  if (!hash)
    return callback(null, false);
  return this.db.hasAddress(this.wid, hash, callback);
};

/**
 * Get path by address hash.
 * @param {Address|Hash} address
 * @param {Function} callback - Returns [Error, {@link Path}].
 */

Wallet.prototype.getPath = function getPath(address, callback) {
  var self = this;
  var hash = bcoin.address.getHash(address, 'hex');

  if (!hash)
    return callback();

  this.db.getAddressPath(this.wid, hash, function(err, path) {
    if (err)
      return callback(err);

    if (!path)
      return callback();

    path.id = self.id;

    callback(null, path);
  });
};

/**
 * Get all wallet paths.
 * @param {(String|Number)?} account
 * @param {Function} callback - Returns [Error, {@link Path}].
 */

Wallet.prototype.getPaths = function getPaths(account, callback) {
  var self = this;
  var out = [];
  var i, path;

  this._getIndex(account, callback, function(account, callback) {
    this.db.getWalletPaths(this.wid, function(err, paths) {
      if (err)
        return callback(err);

      for (i = 0; i < paths.length; i++) {
        path = paths[i];
        if (!account || path.account === account) {
          path.id = self.id;
          out.push(path);
        }
      }

      callback(null, out);
    });
  });
};

/**
 * Import a keyring (will not exist on derivation chain).
 * Rescanning must be invoked manually.
 * @param {(String|Number)?} account
 * @param {KeyRing} ring
 * @param {(String|Buffer)?} passphrase
 * @param {Function} callback
 */

Wallet.prototype.importKey = function importKey(account, ring, passphrase, callback) {
  var self = this;
  var raw, path;

  if (typeof passphrase === 'function') {
    callback = passphrase;
    passphrase = null;
  }

  if (typeof ring === 'function') {
    callback = ring;
    ring = account;
    account = null;
  }

  if (account == null)
    account = 0;

  callback = this._lockWrite(importKey, [account, ring, passphrase, callback]);

  if (!callback)
    return;

  this.getPath(ring.getHash('hex'), function(err, exists) {
    if (err)
      return callback(err);

    if (exists)
      return callback(new Error('Key already exists.'));

    self.getAccount(account, function(err, account) {
      if (err)
        return callback(err);

      if (!account)
        return callback(new Error('Account not found.'));

      if (account.type !== bcoin.account.types.PUBKEYHASH)
        return callback(new Error('Cannot import into non-pkh account.'));

      self.unlock(passphrase, null, function(err) {
        if (err)
          return callback(err);

        raw = ring.toRaw();
        path = Path.fromAccount(account, ring);

        if (self.master.encrypted) {
          raw = self.master.encipher(raw, path.hash);
          assert(raw);
          path.encrypted = true;
        }

        path.imported = raw;
        ring.path = path;

        self.start();

        account.saveAddress([ring], function(err) {
          if (err) {
            self.drop();
            return callback(err);
          }
          self.commit(callback);
        });
      }, true);
    });
  });
};

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

Wallet.prototype.fund = function fund(tx, options, callback, force) {
  var self = this;
  var rate;

  if (typeof options === 'function') {
    callback = options;
    options = null;
  }

  if (!options)
    options = {};

  // We use a lock here to ensure we
  // don't end up double spending coins.
  callback = this._lockFund(fund, [tx, options, callback], force);

  if (!callback)
    return;

  if (!this.initialized)
    return callback(new Error('Wallet is not initialized.'));

  this.getAccount(options.account, function(err, account) {
    if (err)
      return callback(err);

    if (!account) {
      if (options.account != null)
        return callback(new Error('Account not found.'));
      account = self.account;
    }

    if (!account.initialized)
      return callback(new Error('Account is not initialized.'));

    self.getCoins(options.account, function(err, coins) {
      if (err)
        return callback(err);

      rate = options.rate;

      if (rate == null) {
        if (self.db.fees)
          rate = self.db.fees.estimateFee();
        else
          rate = self.network.getRate();
      }

      // Don't use any locked coins.
      coins = self.tx.filterLocked(coins);

      try {
        tx.fund(coins, {
          selection: options.selection,
          round: options.round,
          confirmations: options.confirmations,
          free: options.free,
          hardFee: options.hardFee,
          subtractFee: options.subtractFee,
          changeAddress: account.changeAddress.getAddress(),
          height: self.db.height,
          rate: rate,
          maxFee: options.maxFee,
          m: account.m,
          n: account.n,
          witness: account.witness,
          script: account.receiveAddress.script
        });
      } catch (e) {
        return callback(e);
      }

      callback();
    });
  });
};

/**
 * Build a transaction, fill it with outputs and inputs,
 * sort the members according to BIP69, set locktime,
 * and template it.
 * @param {Object} options - See {@link Wallet#fund options}.
 * @param {Object[]} options.outputs - See {@link MTX#addOutput}.
 * @param {Function} callback - Returns [Error, {@link MTX}].
 */

Wallet.prototype.createTX = function createTX(options, callback, force) {
  var self = this;
  var outputs = options.outputs;
  var i, tx;

  if (!Array.isArray(outputs) || outputs.length === 0)
    return callback(new Error('No outputs.'));

  // Create mutable tx
  tx = bcoin.mtx();

  // Add the outputs
  for (i = 0; i < outputs.length; i++) {
    try {
      tx.addOutput(outputs[i]);
    } catch (e) {
      callback = utils.asyncify(callback);
      return callback(e);
    }
  }

  // Fill the inputs with unspents
  this.fund(tx, options, function(err) {
    if (err)
      return callback(err);

    // Sort members a la BIP69
    tx.sortMembers();

    // Set the locktime to target value or
    // `height - whatever` to avoid fee sniping.
    // if (options.locktime != null)
    //   tx.setLocktime(options.locktime);
    // else
    //   tx.avoidFeeSniping(self.db.height);

    if (!tx.isSane())
      return callback(new Error('CheckTransaction failed.'));

    if (!tx.checkInputs(self.db.height))
      return callback(new Error('CheckInputs failed.'));

    self.template(tx, function(err, total) {
      if (err)
        return callback(err);

      if (total === 0)
        return callback(new Error('template failed.'));

      callback(null, tx);
    });
  }, force);
};

/**
 * Build a transaction, fill it with outputs and inputs,
 * sort the members according to BIP69, set locktime,
 * sign and broadcast. Doing this all in one go prevents
 * coins from being double spent.
 * @param {Object} options - See {@link Wallet#fund options}.
 * @param {Object[]} options.outputs - See {@link MTX#addOutput}.
 * @param {Function} callback - Returns [Error, {@link TX}].
 */

Wallet.prototype.send = function send(options, callback) {
  var self = this;

  callback = this._lockFund(send, [options, callback]);

  if (!callback)
    return;

  this.createTX(options, function(err, tx) {
    if (err)
      return callback(err);

    self.sign(tx, options, function(err) {
      if (err)
        return callback(err);

      if (!tx.isSigned())
        return callback(new Error('TX could not be fully signed.'));

      tx = tx.toTX();

      self.addTX(tx, function(err) {
        if (err)
          return callback(err);

        self.logger.debug('Sending wallet tx (%s): %s', self.id, tx.rhash);
        self.db.emit('send', tx);

        callback(null, tx);
      });
    });
  }, true);
};

/**
 * Resend pending wallet transactions.
 * @param {Function} callback
 */

Wallet.prototype.resend = function resend(callback) {
  var self = this;
  var i;

  this.getUnconfirmed(function(err, txs) {
    if (err)
      return callback(err);

    if (txs.length > 0)
      self.logger.info('Rebroadcasting %d transactions.', txs.length);

    for (i = 0; i < txs.length; i++)
      self.db.emit('send', txs[i]);

    callback();
  });
};

/**
 * Derive necessary addresses for signing a transaction.
 * @param {TX|Input} tx
 * @param {Number?} index - Input index.
 * @param {Function} callback - Returns [Error, {@link KeyRing}[]].
 */

Wallet.prototype.deriveInputs = function deriveInputs(tx, callback) {
  var self = this;
  var rings = [];
  var ring;

  this.getInputPaths(tx, function(err, paths) {
    if (err)
      return callback(err);

    utils.forEachSerial(paths, function(path, next) {
      self.getAccount(path.account, function(err, account) {
        if (err)
          return next(err);

        if (!account)
          return next();

        ring = account.derivePath(path, self.master);

        if (ring)
          rings.push(ring);

        next();
      });
    }, function(err) {
      if (err)
        return callback(err);

      callback(null, rings);
    });
  });
};

/**
 * Retrieve a single keyring by address.
 * @param {Address|Hash} hash
 * @param {Function} callback
 */

Wallet.prototype.getKeyRing = function getKeyRing(address, callback) {
  var self = this;
  var hash = bcoin.address.getHash(address, 'hex');
  var ring;

  if (!hash)
    return callback();

  this.getPath(hash, function(err, path) {
    if (err)
      return callback(err);

    if (!path)
      return callback();

    self.getAccount(path.account, function(err, account) {
      if (err)
        return callback(err);

      if (!account)
        return callback();

      ring = account.derivePath(path, self.master);

      callback(null, ring);
    });
  });
};

/**
 * Map input addresses to paths.
 * @param {TX|Input} tx
 * @param {Function} callback - Returns [Error, {@link Path}[]].
 */

Wallet.prototype.getInputPaths = function getInputPaths(tx, callback) {
  var self = this;
  var paths = [];
  var hashes = [];
  var hash;

  function done() {
    utils.forEachSerial(hashes, function(hash, next, i) {
      self.getPath(hash, function(err, path) {
        if (err)
          return next(err);

        if (path)
          paths.push(path);

        next();
      });
    }, function(err) {
      if (err)
        return callback(err);
      return callback(null, paths);
    });
  }

  if (tx instanceof bcoin.input) {
    if (!tx.coin)
      return callback(new Error('Not all coins available.'));
    hash = tx.coin.getHash('hex');
    if (hash)
      hashes.push(hash);
    return done();
  }

  this.fillCoins(tx, function(err) {
    if (err)
      return callback(err);

    if (!tx.hasCoins())
      return callback(new Error('Not all coins available.'));

    hashes = tx.getInputHashes('hex');
    done();
  });
};

/**
 * Map output addresses to paths.
 * @param {TX|Output} tx
 * @param {Function} callback - Returns [Error, {@link Path}[]].
 */

Wallet.prototype.getOutputPaths = function getOutputPaths(tx, callback) {
  var self = this;
  var paths = [];
  var hashes = [];
  var hash;

  if (tx instanceof bcoin.output) {
    hash = tx.getHash('hex');
    if (hash)
      hashes.push(hash);
  } else {
    hashes = tx.getOutputHashes('hex');
  }

  utils.forEachSerial(hashes, function(hash, next, i) {
    self.getPath(hash, function(err, path) {
      if (err)
        return next(err);

      if (path)
        paths.push(path);

      next();
    });
  }, function(err) {
    if (err)
      return callback(err);
    callback(null, paths);
  });
};

/**
 * Sync address depths based on a transaction's outputs.
 * This is used for deriving new addresses when
 * a confirmed transaction is seen.
 * @param {PathInfo} info
 * @param {Function} callback - Returns [Error, Boolean]
 * (true if new addresses were allocated).
 */

Wallet.prototype.syncOutputDepth = function syncOutputDepth(info, callback) {
  var self = this;
  var receive = [];
  var accounts = {};
  var i, path;

  callback = this._lockWrite(syncOutputDepth, [info, callback]);

  if (!callback)
    return;

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

  utils.forEachSerial(accounts, function(paths, next) {
    var account = paths[0].account;
    var receiveDepth = -1;
    var changeDepth = -1;

    for (i = 0; i < paths.length; i++) {
      path = paths[i];

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

    self.getAccount(account, function(err, account) {
      if (err)
        return next(err);

      if (!account)
        return next();

      account.setDepth(receiveDepth, changeDepth, function(err, rcv, chng) {
        if (err)
          return next(err);

        if (rcv)
          receive.push(rcv);

        next();
      });
    });
  }, function(err) {
    if (err) {
      self.drop();
      return callback(err);
    }

    if (receive.length > 0) {
      self.db.emit('address', self.id, receive);
      self.emit('address', receive);
    }

    self.commit(function(err) {
      if (err)
        return callback(err);
      callback(null, receive);
    });
  });
};

/**
 * Emit balance events after a tx is saved.
 * @private
 * @param {TX} tx
 * @param {PathInfo} info
 * @param {Function} callback
 */

Wallet.prototype.updateBalances = function updateBalances(callback) {
  var self = this;

  if (this.db.listeners('balance').length === 0
      && this.listeners('balance').length === 0) {
    return callback();
  }

  this.getBalance(function(err, balance) {
    if (err)
      return callback(err);

    self.db.emit('balance', self.id, balance);
    self.emit('balance', balance);

    callback();
  });
};

/**
 * Derive new addresses and emit balance.
 * @private
 * @param {TX} tx
 * @param {PathInfo} info
 * @param {Function} callback
 */

Wallet.prototype.handleTX = function handleTX(info, callback) {
  var self = this;
  this.syncOutputDepth(info, function(err) {
    if (err)
      return callback(err);

    self.updateBalances(callback);
  });
};

/**
 * Get a redeem script or witness script by hash.
 * @param {Hash} hash - Can be a ripemd160 or a sha256.
 * @returns {Script}
 */

Wallet.prototype.getRedeem = function getRedeem(hash, callback) {
  if (typeof hash === 'string')
    hash = new Buffer(hash, 'hex');

  this.getKeyRing(hash.toString('hex'), function(err, ring) {
    if (err)
      return callback(err);

    if (!ring)
      return callback();

    callback(null, ring.getRedeem(hash));
  });
};

/**
 * Build input scripts templates for a transaction (does not
 * sign, only creates signature slots). Only builds scripts
 * for inputs that are redeemable by this wallet.
 * @param {MTX} tx
 * @param {Function} callback - Returns [Error, Number]
 * (total number of scripts built).
 */

Wallet.prototype.template = function template(tx, callback) {
  var total = 0;
  var i, ring;

  this.deriveInputs(tx, function(err, rings) {
    if (err)
      return callback(err);

    for (i = 0; i < rings.length; i++) {
      ring = rings[i];
      total += tx.template(ring);
    }

    callback(null, total);
  });
};

/**
 * Build input scripts and sign inputs for a transaction. Only attempts
 * to build/sign inputs that are redeemable by this wallet.
 * @param {MTX} tx
 * @param {Object|String|Buffer} options - Options or passphrase.
 * @param {Function} callback - Returns [Error, Number] (total number
 * of inputs scripts built and signed).
 */

Wallet.prototype.sign = function sign(tx, options, callback) {
  var self = this;
  var passphrase, timeout;

  if (typeof options === 'function') {
    callback = options;
    options = {};
  }

  if (typeof options === 'string' || Buffer.isBuffer(options))
    options = { passphrase: options };

  passphrase = options.passphrase;
  timeout = options.timeout;

  this.unlock(passphrase, timeout, function(err, master) {
    if (err)
      return callback(err);

    self.deriveInputs(tx, function(err, rings) {
      if (err)
        return callback(err);

      self.signAsync(rings, tx, callback);
    });
  });
};

/**
 * Sign a transaction asynchronously.
 * @param {KeyRing[]} rings
 * @param {MTX} tx
 * @param {Function} callback - Returns [Error, Number] (total number
 * of inputs scripts built and signed).
 */

Wallet.prototype.signAsync = function signAsync(rings, tx, callback) {
  var result;

  if (!this.workerPool) {
    callback = utils.asyncify(callback);
    try {
      result = tx.sign(rings);
    } catch (e) {
      return callback(e);
    }
    return callback(null, result);
  }

  this.workerPool.sign(tx, rings, null, callback);
};

/**
 * Fill transaction with coins (accesses db).
 * @param {TX} tx
 * @param {Function} callback - Returns [Error, {@link TX}].
 */

Wallet.prototype.fillCoins = function fillCoins(tx, callback) {
  return this.tx.fillCoins(tx, callback);
};

/**
 * Fill transaction with historical coins (accesses db).
 * @param {TX} tx
 * @param {Function} callback - Returns [Error, {@link TX}].
 */

Wallet.prototype.fillHistory = function fillHistory(tx, callback) {
  return this.tx.fillHistory(tx, callback);
};

/**
 * Fill transaction with historical coins (accesses db).
 * @param {TX} tx
 * @param {Function} callback - Returns [Error, {@link TX}].
 */

Wallet.prototype.toDetails = function toDetails(tx, callback) {
  return this.tx.toDetails(tx, callback);
};

/**
 * Fill transaction with historical coins (accesses db).
 * @param {TX} tx
 * @param {Function} callback - Returns [Error, {@link TX}].
 */

Wallet.prototype.getDetails = function getDetails(tx, callback) {
  return this.tx.getDetails(tx, callback);
};

/**
 * Get a coin from the wallet (accesses db).
 * @param {Hash} hash
 * @param {Number} index
 * @param {Function} callback - Returns [Error, {@link Coin}].
 */

Wallet.prototype.getCoin = function getCoin(hash, index, callback) {
  return this.tx.getCoin(hash, index, callback);
};

/**
 * Get a transaction from the wallet (accesses db).
 * @param {Hash} hash
 * @param {Function} callback - Returns [Error, {@link TX}].
 */

Wallet.prototype.getTX = function getTX(hash, callback) {
  return this.tx.getTX(hash, callback);
};

/**
 * Add a transaction to the wallets TX history (accesses db).
 * @param {TX} tx
 * @param {Function} callback
 */

Wallet.prototype.addTX = function addTX(tx, callback) {
  this.db.addTX(tx, callback);
};

/**
 * Get all transactions in transaction history (accesses db).
 * @param {(String|Number)?} account
 * @param {Function} callback - Returns [Error, {@link TX}[]].
 */

Wallet.prototype.getHistory = function getHistory(account, callback) {
  this._getIndex(account, callback, function(account, callback) {
    this.tx.getHistory(account, callback);
  });
};

/**
 * Get all available coins (accesses db).
 * @param {(String|Number)?} account
 * @param {Function} callback - Returns [Error, {@link Coin}[]].
 */

Wallet.prototype.getCoins = function getCoins(account, callback) {
  this._getIndex(account, callback, function(account, callback) {
    this.tx.getCoins(account, callback);
  });
};

/**
 * Get all pending/unconfirmed transactions (accesses db).
 * @param {(String|Number)?} account
 * @param {Function} callback - Returns [Error, {@link TX}[]].
 */

Wallet.prototype.getUnconfirmed = function getUnconfirmed(account, callback) {
  this._getIndex(account, callback, function(account, callback) {
    this.tx.getUnconfirmed(account, callback);
  });
};

/**
 * Get wallet balance (accesses db).
 * @param {(String|Number)?} account
 * @param {Function} callback - Returns [Error, {@link Balance}].
 */

Wallet.prototype.getBalance = function getBalance(account, callback) {
  this._getIndex(account, callback, function(account, callback) {
    this.tx.getBalance(account, callback);
  });
};

/**
 * Get a range of transactions between two timestamps (accesses db).
 * @param {(String|Number)?} account
 * @param {Object} options
 * @param {Number} options.start
 * @param {Number} options.end
 * @param {Function} callback - Returns [Error, {@link TX}[]].
 */

Wallet.prototype.getRange = function getRange(account, options, callback) {
  if (typeof options === 'function') {
    callback = options;
    options = account;
    account = null;
  }
  this._getIndex(account, callback, function(account, callback) {
    this.tx.getRange(account, options, callback);
  });
};

/**
 * Get the last N transactions (accesses db).
 * @param {(String|Number)?} account
 * @param {Number} limit
 * @param {Function} callback - Returns [Error, {@link TX}[]].
 */

Wallet.prototype.getLast = function getLast(account, limit, callback) {
  if (typeof limit === 'function') {
    callback = limit;
    limit = account;
    account = null;
  }
  this._getIndex(account, callback, function(account, callback) {
    this.tx.getLast(account, limit, callback);
  });
};

/**
 * Zap stale TXs from wallet (accesses db).
 * @param {(Number|String)?} account
 * @param {Number} age - Age threshold (unix time, default=72 hours).
 * @param {Function} callback - Returns [Error].
 */

Wallet.prototype.zap = function zap(account, age, callback) {
  if (typeof age === 'function') {
    callback = age;
    age = account;
    account = null;
  }
  this._getIndex(account, callback, function(account, callback) {
    this.tx.zap(account, age, callback);
  });
};

/**
 * Abandon transaction (accesses db).
 * @param {Hash} hash
 * @param {Function} callback - Returns [Error].
 */

Wallet.prototype.abandon = function abandon(hash, callback) {
  this.tx.abandon(hash, callback);
};

/**
 * Resolve account index.
 * @private
 * @param {(Number|String)?} account
 * @param {Function} errback - Returns [Error].
 * @param {Function} callback
 */

Wallet.prototype._getIndex = function _getIndex(account, errback, callback) {
  var self = this;

  if (typeof account === 'function') {
    errback = account;
    account = null;
  }

  if (account == null)
    return callback.call(this, null, errback);

  this.db.getAccountIndex(this.wid, account, function(err, index) {
    if (err)
      return errback(err);

    if (index === -1)
      return errback(new Error('Account not found.'));

    callback.call(self, index, errback);
  });
};

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
 * Invoke mutex lock.
 * @private
 */

MasterKey.prototype._lock = function _lock(func, args, force) {
  return this.locker.lock(func, args, force);
};

/**
 * Decrypt the key and set a timeout to destroy decrypted data.
 * @param {Buffer|String} passphrase - Zero this yourself.
 * @param {Number} [timeout=60000] timeout in ms.
 * @param {Function} callback - Returns [Error, {@link HDPrivateKey}].
 */

MasterKey.prototype.unlock = function unlock(passphrase, timeout, callback) {
  var self = this;

  callback = this._lock(unlock, [passphrase, timeout, callback]);

  if (!callback)
    return;

  if (this.key)
    return callback(null, this.key);

  if (!passphrase)
    return callback(new Error('No passphrase.'));

  assert(this.encrypted);

  crypto.decrypt(this.ciphertext, passphrase, this.iv, function(err, data, key) {
    if (err)
      return callback(err);

    try {
      self.key = bcoin.hd.fromExtended(data);
    } catch (e) {
      return callback(e);
    }

    self.start(timeout);

    self.aesKey = key;

    callback(null, self.key);
  });
};

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

MasterKey.prototype.encipher = function encipher(data, iv) {
  if (!this.aesKey)
    return;

  if (typeof iv === 'string')
    iv = new Buffer(iv, 'hex');

  return crypto.encipher(data, this.aesKey, iv.slice(0, 16));
};

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
 * @param {Function} callback
 */

MasterKey.prototype.decrypt = function decrypt(passphrase, callback) {
  var self = this;

  callback = this._lock(decrypt, [passphrase, callback]);

  if (!callback)
    return;

  if (!this.encrypted) {
    assert(this.key);
    return callback();
  }

  if (!passphrase)
    return callback();

  this.destroy();

  crypto.decrypt(this.ciphertext, passphrase, this.iv, function(err, data) {
    if (err)
      return callback(err);

    try {
      self.key = bcoin.hd.fromExtended(data);
    } catch (e) {
      return callback(e);
    }

    self.encrypted = false;
    self.iv = null;
    self.ciphertext = null;

    callback();
  });
};

/**
 * Encrypt the key permanently.
 * @param {Buffer|String} passphrase - Zero this yourself.
 * @param {Function} callback
 */

MasterKey.prototype.encrypt = function encrypt(passphrase, callback) {
  var self = this;
  var data, iv;

  callback = this._lock(encrypt, [passphrase, callback]);

  if (!callback)
    return;

  if (this.encrypted)
    return;

  if (!passphrase)
    return callback();

  data = this.key.toExtended();
  iv = crypto.randomBytes(16);

  this.stop();

  crypto.encrypt(data, passphrase, iv, function(err, data) {
    if (err)
      return callback(err);

    self.key = null;
    self.encrypted = true;
    self.iv = iv;
    self.ciphertext = data;

    callback();
  });
};

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
