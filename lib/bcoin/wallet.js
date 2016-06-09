/*!
 * wallet.js - wallet object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

var bcoin = require('./env');
var EventEmitter = require('events').EventEmitter;
var utils = require('./utils');
var assert = utils.assert;
var BufferReader = require('./reader');
var BufferWriter = require('./writer');

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

function Wallet(options) {
  var master;

  if (!(this instanceof Wallet))
    return new Wallet(options);

  EventEmitter.call(this);

  assert(options, 'Options required.');
  assert(options.db, 'DB required.');

  this.options = options;
  this.network = bcoin.network.get(options.network);
  this.db = options.db;
  this.locker = new bcoin.locker(this);

  master = options.master;

  if (!master)
    master = bcoin.hd.fromMnemonic(null, this.network);

  if (!bcoin.hd.isHD(master) && !MasterKey.isMasterKey(master))
    master = bcoin.hd.fromAny(master, this.network);

  if (!MasterKey.isMasterKey(master))
    master = MasterKey.fromKey(master);

  this.id = options.id || null;
  this.master = master;
  this.initialized = options.initialized || false;
  this.accountDepth = options.accountDepth || 0;

  this.loaded = false;
  this.loading = false;
  this.account = null;

  if (!this.id)
    this.id = this.getID();

  if (this.options.passphrase)
    this.master.encrypt(this.options.passphrase);
}

utils.inherits(Wallet, EventEmitter);

/**
 * Open the wallet, register with the database.
 * @param {Function} callback
 */

Wallet.prototype.open = function open(callback) {
  var self = this;

  callback = utils.ensure(callback);

  if (this.loaded)
    return utils.nextTick(callback);

  if (this.loading)
    return this.once('open', callback);

  this.loading = true;

  try {
    this.db.register(this);
  } catch (e) {
    this.emit('error', e);
    return callback(e);
  }

  this.init(function(err) {
    if (err) {
      self.emit('error', err);
      return callback(err);
    }

    self.loading = false;
    self.loaded = true;
    self.emit('open');

    return callback();
  });
};

/**
 * Close the wallet, unregister with the database.
 * @method
 * @param {Function} callback
 */

Wallet.prototype.close =
Wallet.prototype.destroy = function destroy(callback) {
  callback = utils.ensure(callback);

  if (!this.loaded)
    return utils.nextTick(callback);

  assert(!this.loading);

  this.master.destroy();

  try {
    this.db.unregister(this);
  } catch (e) {
    this.emit('error', e);
    return callback(e);
  }

  this.loaded = false;

  return utils.nextTick(callback);
};

/**
 * Attempt to intialize the wallet (generating
 * the first addresses along with the lookahead
 * addresses). Called automatically from the
 * walletdb and open().
 * @param {Function} callback
 */

Wallet.prototype.init = function init(callback) {
  var self = this;

  function done(err, account) {
    if (err)
      return callback(err);

    if (!account)
      return callback(new Error('Account not found.'));

    self.account = account;

    return callback();
  }

  this.db.open(function(err) {
    if (err)
      return callback(err);

    if (self.initialized)
      return self.getAccount(0, done);

    self.initialized = true;
    self.createAccount(self.options, done);
  });
};

/**
 * Add a public account key to the wallet (multisig).
 * Saves the key in the wallet database.
 * @param {HDPublicKey} key
 * @param {Function} callback
 */

Wallet.prototype.addKey = function addKey(account, key, callback) {
  var unlock;

  if (typeof key === 'function') {
    callback = key;
    key = account;
    account = 0;
  }

  unlock = this.locker.lock(addKey, [account, key, callback]);

  if (!unlock)
    return;

  callback = utils.wrap(callback, unlock);

  this.getAccount(account, function(err, account) {
    if (err)
      return callback(err);

    if (!account)
      return callback(new Error('Account not found.'));

    account.addKey(key, callback);
  }, true);
};

/**
 * Remove a public account key from the wallet (multisig).
 * Remove the key from the wallet database.
 * @param {HDPublicKey} key
 * @param {Function} callback
 */

Wallet.prototype.removeKey = function removeKey(account, key, callback) {
  var unlock;

  if (typeof key === 'function') {
    callback = key;
    key = account;
    account = 0;
  }

  unlock = this.locker.lock(removeKey, [account, key, callback]);

  if (!unlock)
    return;

  callback = utils.wrap(callback, unlock);

  this.getAccount(account, function(err, account) {
    if (err)
      return callback(err);

    if (!account)
      return callback(new Error('Account not found.'));

    account.removeKey(key, callback);
  }, true);
};

/**
 * Change or set master key's passphrase.
 * @param {(String|Buffer)?} old
 * @param {(String|Buffer)?} new_
 * @param {Function} callback
 */

Wallet.prototype.setPassphrase = function setPassphrase(old, new_, callback) {
  if (typeof new_ === 'function') {
    callback = new_;
    new_ = old;
    old = null;
  }

  if (old) {
    try {
      this.master.decrypt(old);
    } catch (e) {
      return callback(e);
    }
  }

  if (new_) {
    try {
      this.master.encrypt(new_);
    } catch (e) {
      return callback(e);
    }
  }

  return this.save(callback);
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

Wallet.prototype.unlock = function unlock(passphrase, timeout) {
  this.master.toKey(passphrase, timeout);
};

/**
 * Generate the wallet ID if none was passed in.
 * It is represented as `m/44'` (public) hashed
 * and converted to an address with a prefix
 * of `0x03be04` (`WLT` in base58).
 * @returns {Base58String}
 */

Wallet.prototype.getID = function getID() {
  var key, p;

  assert(this.master.key, 'Cannot derive id.');

  key = this.master.key.derive(44, true);

  p = new BufferWriter();
  p.writeU8(0x03);
  p.writeU8(0xbe);
  p.writeU8(0x04);
  p.writeBytes(utils.ripesha(key.publicKey));
  p.writeChecksum();

  return utils.toBase58(p.render());
};

/**
 * Create an account. Requires passphrase if master key is encrypted.
 * @param {Object} options - See {@link Account} options.
 * @param {Function} callback - Returns [Error, {@link Account}].
 */

Wallet.prototype.createAccount = function createAccount(options, callback, force) {
  var self = this;
  var master, key, unlock;

  unlock = this.locker.lock(createAccount, [options, callback], force);

  if (!unlock)
    return;

  callback = utils.wrap(callback, unlock);

  try {
    master = this.master.toKey(options.passphrase, options.timeout);
  } catch (e) {
    return callback(e);
  }

  key = master.deriveAccount44(this.accountDepth);

  options = {
    network: this.network,
    id: this.id,
    name: this.accountDepth === 0 ? 'default' : options.name,
    witness: options.witness,
    accountKey: key.hdPublicKey,
    accountIndex: this.accountDepth,
    type: options.type,
    keys: options.keys,
    m: options.m,
    n: options.n
  };

  this.db.createAccount(options, function(err, account) {
    if (err)
      return callback(err);

    self.accountDepth++;

    self.save(function(err) {
      if (err)
        return callback(err);
      return callback(null, account);
    });
  });
};

/**
 * List account names and indexes from the db.
 * @param {Function} callback - Returns [Error, Array].
 */

Wallet.prototype.getAccounts = function getAccounts(callback) {
  this.db.getAccounts(this.id, callback);
};

/**
 * Retrieve an account from the database.
 * @param {Number|String} account
 * @param {Function} callback - Returns [Error, {@link Account}].
 */

Wallet.prototype.getAccount = function getAccount(account, callback, force) {
  var unlock = this.locker.lock(getAccount, [account, callback], force);

  if (!unlock)
    return;

  callback = utils.wrap(callback, unlock);

  if (this.account) {
    if (account === 0 || account === 'default')
      return callback(null, this.account);
  }

  return this.db.getAccount(this.id, account, callback);
};

/**
 * Create a new receiving address (increments receiveDepth).
 * @param {(Number|String)?} account
 * @param {Function} callback - Returns [Error, {@link KeyRing}].
 */

Wallet.prototype.createReceive = function createReceive(account, callback) {
  if (typeof account === 'function') {
    callback = account;
    account = 0;
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
    account = 0;
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
  var unlock;

  if (typeof change === 'function') {
    callback = change;
    change = account;
    account = 0;
  }

  unlock = this.locker.lock(createAddress, [account, change, callback]);

  if (!unlock)
    return;

  callback = utils.wrap(callback, unlock);

  this.getAccount(account, function(err, account) {
    if (err)
      return callback(err);

    if (!account)
      return callback(new Error('Account not found.'));

    account.createAddress(change, callback);
  }, true);
};

/**
 * Save the wallet to the database. Necessary
 * when address depth and keys change.
 * @param {Function} callback
 */

Wallet.prototype.save = function save(callback) {
  return this.db.save(this, callback);
};

/**
 * Test whether the wallet possesses an address.
 * @param {Base58Address} address
 * @param {Function} callback - Returns [Error, Boolean].
 */

Wallet.prototype.hasAddress = function hasAddress(address, callback) {
  return this.db.hasAddress(this.id, address, callback);
};

/**
 * Get path by address hash.
 * @param {Hash} address
 * @param {Function} callback - Returns [Error, {@link Path}].
 */

Wallet.prototype.getPath = function getPath(address, callback) {
  return this.db.getPath(this.id, address, callback);
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
 * @param {Amount?} options.fee - Use a hard fee rather than calculating one.
 * @param {Number|Boolean} options.subtractFee - Whether to subtract the
 * fee from existing outputs rather than adding more inputs.
 */

Wallet.prototype.fill = function fill(tx, options, callback) {
  var self = this;

  if (typeof options === 'function') {
    callback = options;
    options = null;
  }

  if (!options)
    options = {};

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

      try {
        tx.fill(coins, {
          selection: options.selection || 'age',
          round: options.round,
          confirmed: options.confirmed,
          free: options.free,
          fee: options.fee,
          subtractFee: options.subtractFee,
          changeAddress: account.changeAddress.getAddress(),
          height: self.network.height,
          rate: options.rate != null
            ? options.rate
            : self.network.getRate(),
          wallet: self,
          m: self.m,
          n: self.n
        });
      } catch (e) {
        return callback(e);
      }

      return callback();
    });
  });
};

/**
 * Build a transaction, fill it with outputs and inputs,
 * sort the members according to BIP69, set locktime,
 * and sign it (accesses db).
 * @param {Object} options - See {@link Wallet#fill options}.
 * @param {Object[]} outputs - See {@link Script.createOutputScript}.
 * @param {Function} callback - Returns [Error, {@link MTX}].
 */

Wallet.prototype.createTX = function createTX(options, outputs, callback) {
  var self = this;
  var height = 0xffffffff;
  var tx, i;

  if (typeof outputs === 'function') {
    callback = outputs;
    outputs = null;
  }

  if (!outputs) {
    outputs = options;
    options = {};
  }

  if (!Array.isArray(outputs))
    outputs = [outputs];

  if (options.height >= 0)
    height = options.height;

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
  this.fill(tx, options, function(err) {
    if (err)
      return callback(err);

    // Sort members a la BIP69
    tx.sortMembers();

    // Set the locktime to target value or
    // `height - whatever` to avoid fee sniping.
    // if (options.locktime != null)
    //   tx.setLocktime(options.locktime);
    // else
    //   tx.avoidFeeSniping(options.height);

    if (!tx.isSane())
      return callback(new Error('CheckTransaction failed.'));

    if (!tx.checkInputs(height))
      return callback(new Error('CheckInputs failed.'));

    self.scriptInputs(tx, function(err, total) {
      if (err)
        return callback(err);

      if (total === 0)
        return callback(new Error('scriptInputs failed.'));

      return callback(null, tx);
    });
  });
};

/**
 * Derive necessary addresses for signing a transaction.
 * @param {TX|Input} tx
 * @param {Number?} index - Input index.
 * @returns {KeyRing[]}
 */

Wallet.prototype.deriveInputs = function deriveInputs(tx, callback) {
  var self = this;
  var addresses = [];

  this.getInputPaths(tx, function(err, paths) {
    if (err)
      return callback(err);

    utils.forEachSerial(paths, function(path, next) {
      self.getAccount(path.account, function(err, account) {
        if (err)
          return next(err);

        if (!account)
          return next();

        addresses.push(account.deriveAddress(path.change, path.index));

        return next();
      });
    }, function(err) {
      if (err)
        return callback(err);

      return callback(null, addresses);
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
  var hashes;

  function done() {
    utils.forEachSerial(hashes, function(hash, next, i) {
      self.getPath(hash, function(err, path) {
        if (err)
          return next(err);

        if (path)
          paths.push(path);

        return next();
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
    hashes = [tx.coin.getHash()];
    return done();
  }

  this.fillCoins(tx, function(err) {
    if (err)
      return callback(err);

    if (!tx.hasCoins())
      return callback(new Error('Not all coins available.'));

    hashes = tx.getInputHashes();
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
  var hashes;

  if (tx instanceof bcoin.output)
    hashes = [tx.getHash()];
  else
    hashes = tx.getOutputHashes();

  utils.forEachSerial(hashes, function(hash, next, i) {
    self.getPath(hash, function(err, path) {
      if (err)
        return next(err);

      if (path)
        paths.push(path);

      return next();
    });
  }, function(err) {
    if (err)
      return callback(err);
    return callback(null, paths);
  });
};

/**
 * Sync address depths based on a transaction's outputs.
 * This is used for deriving new addresses when
 * a confirmed transaction is seen.
 * @param {TX} tx
 * @param {Function} callback - Returns [Errr, Boolean]
 * (true if new addresses were allocated).
 */

Wallet.prototype.syncOutputDepth = function syncOutputDepth(tx, callback) {
  var self = this;
  var accounts = {};
  var change = [];
  var receive = [];
  var i, path, unlock;

  unlock = this.locker.lock(syncOutputDepth, [tx, callback]);

  if (!unlock)
    return;

  callback = utils.wrap(callback, unlock);

  this.getOutputPaths(tx, function(err, paths) {
    if (err)
      return callback(err);

    for (i = 0; i < paths.length; i++) {
      path = paths[i];

      if (!accounts[path.account])
        accounts[path.account] = [];

      accounts[path.account].push(path);
    }

    utils.forEachSerial(Object.keys(accounts), function(index, next) {
      var paths = accounts[index];
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

      self.getAccount(+index, function(err, account) {
        if (err)
          return next(err);

        if (!account)
          return next();

        account.setDepth(receiveDepth, changeDepth, function(err, rcv, chng) {
          if (err)
            return next(err);

          if (rcv)
            receive.push(rcv);

          if (chng)
            change.push(chng);

          next();
        });
      }, true);
    }, function(err) {
      if (err)
        return callback(err);

      return callback(null, receive, change);
    });
  });
};

/**
 * Get a redeem script or witness script by hash.
 * @param {Hash} hash - Can be a ripemd160 or a sha256.
 * @returns {Script}
 */

Wallet.prototype.getRedeem = function getRedeem(hash, callback) {
  var self = this;
  var address;

  if (typeof hash === 'string')
    hash = new Buffer(hash, 'hex');

  this.getPath(hash.toString('hex'), function(err, path) {
    if (err)
      return callback(err);

    if (!path)
      return callback();

    self.getAccount(path.account, function(err, account) {
      if (err)
        return callback(err);

      if (!account)
        return callback();

      address = account.deriveAddress(path.change, path.index);

      if (address.program && hash.length === 20) {
        if (utils.equal(hash, address.programHash))
          return callback(null, address.program);
      }

      return callback(null, address.script);
    });
  });
};

/**
 * Scan for active accounts and addresses. Used for importing a wallet.
 * @param {Function} getByAddress - Must be a function which accepts
 * a {@link Base58Address} as well as a callback and returns
 * transactions by address.
 * @param {Function} callback - Return [Error, Number] (total number
 * of addresses allocated).
 */

Wallet.prototype.scan = function scan(getByAddress, callback) {
  var self = this;
  var total = 0;
  var unlock;

  unlock = this.locker.lock(scan, [getByAddress, callback]);

  if (!unlock)
    return;

  callback = utils.wrap(callback, unlock);

  if (!this.initialized)
    return callback(new Error('Wallet is not initialized.'));

  (function next(err, account) {
    if (err)
      return callback(err);

    account.scan(getByAddress, function(err, result) {
      if (err)
        return callback(err);

      if (result === 0)
        return callback(null, total);

      total += result;

      self.createAccount(self.options, next, true);
    });
  })(null, this.account);
};

/**
 * Build input scripts templates for a transaction (does not
 * sign, only creates signature slots). Only builds scripts
 * for inputs that are redeemable by this wallet.
 * @param {MTX} tx
 * @param {Number?} index - Index of input. If not present,
 * it will attempt to sign all redeemable inputs.
 * @param {Function} callback - Returns [Error, Number]
 * (total number of scripts built).
 */

Wallet.prototype.scriptInputs = function scriptInputs(tx, callback) {
  var total = 0;
  var i;

  this.deriveInputs(tx, function(err, addresses) {
    if (err)
      return callback(err);

    for (i = 0; i < addresses.length; i++)
      total += addresses[i].scriptInputs(tx);

    return callback(null, total);
  });
};

/**
 * Build input scripts and sign inputs for a transaction. Only attempts
 * to build/sign inputs that are redeemable by this wallet.
 * @param {MTX} tx
 * @param {Number?} index - Index of input. If not present,
 * it will attempt to build and sign all redeemable inputs.
 * @param {SighashType?} type
 * @param {Function} callback - Returns [Error, Number] (total number
 * of inputs scripts built and signed).
 */

Wallet.prototype.sign = function sign(tx, options, callback) {
  var self = this;
  var total = 0;
  var i, address, key, master;

  if (Array.isArray(tx)) {
    utils.forEachSerial(tx, function(tx, next) {
      self.sign(tx, options, next);
    }, callback);
    return;
  }

  if (typeof options === 'function') {
    callback = options;
    options = {};
  }

  if (typeof options === 'string' || Buffer.isBuffer(options))
    options = { passphrase: options };

  this.deriveInputs(tx, function(err, addresses) {
    if (err)
      return callback(err);

    try {
      master = self.master.toKey(options.passphrase, options.timeout);
    } catch (e) {
      return callback(e);
    }

    for (i = 0; i < addresses.length; i++) {
      address = addresses[i];
      key = master.deriveAccount44(address.account);
      key = key.derive(address.change).derive(address.index);
      assert(utils.equal(key.getPublicKey(), address.key));
      total += address.sign(tx, key, options.index, options.type);
    }

    return callback(null, total);
  });
};

/**
 * Fill transaction with coins (accesses db).
 * @param {TX} tx
 * @param {Function} callback - Returns [Error, {@link TX}].
 */

Wallet.prototype.fillCoins = function fillCoins(tx, callback) {
  return this.db.fillCoins(tx, callback);
};

/**
 * Get a coin from the wallet (accesses db).
 * @param {Hash} hash
 * @param {Number} index
 * @param {Function} callback - Returns [Error, {@link Coin}].
 */

Wallet.prototype.getCoin = function getCoin(hash, index, callback) {
  return this.db.getCoin(hash, index, callback);
};

/**
 * Get a transaction from the wallet (accesses db).
 * @param {Hash} hash
 * @param {Function} callback - Returns [Error, {@link TX}].
 */

Wallet.prototype.getTX = function getTX(hash, callback) {
  return this.db.getTX(hash, callback);
};

/**
 * Add a transaction to the wallets TX history (accesses db).
 * @param {TX} tx
 * @param {Function} callback
 */

Wallet.prototype.addTX = function addTX(tx, callback) {
  return this.db.addTX(tx, callback);
};

/**
 * Get all transactions in transaction history (accesses db).
 * @param {(String|Number)?} account
 * @param {Function} callback - Returns [Error, {@link TX}[]].
 */

Wallet.prototype.getHistory = function getHistory(account, callback) {
  return this.db.getHistory(this.id, account, callback);
};

/**
 * Get all available coins (accesses db).
 * @param {(String|Number)?} account
 * @param {Function} callback - Returns [Error, {@link Coin}[]].
 */

Wallet.prototype.getCoins = function getCoins(account, callback) {
  return this.db.getCoins(this.id, account, callback);
};

/**
 * Get all pending/unconfirmed transactions (accesses db).
 * @param {(String|Number)?} account
 * @param {Function} callback - Returns [Error, {@link TX}[]].
 */

Wallet.prototype.getUnconfirmed = function getUnconfirmed(account, callback) {
  return this.db.getUnconfirmed(this.id, account, callback);
};

/**
 * Get wallet balance (accesses db).
 * @param {(String|Number)?} account
 * @param {Function} callback - Returns [Error, {@link Balance}].
 */

Wallet.prototype.getBalance = function getBalance(account, callback) {
  return this.db.getBalance(this.id, account, callback);
};

/**
 * Get last timestamp and height this wallet was active
 * at (accesses db). Useful for resetting the chain
 * to a certain height when in SPV mode.
 * @param {(String|Number)?} account
 * @param {Function} callback - Returns [Error, Number(ts), Number(height)].
 */

Wallet.prototype.getLastTime = function getLastTime(account, callback) {
  return this.db.getLastTime(this.id, account, callback);
};

/**
 * Get the last N transactions (accesses db).
 * @param {(String|Number)?} account
 * @param {Number} limit
 * @param {Function} callback - Returns [Error, {@link TX}[]].
 */

Wallet.prototype.getLast = function getLast(account, limit, callback) {
  return this.db.getLast(this.id, account, limit, callback);
};

/**
 * Get a range of transactions between two timestamps (accesses db).
 * @param {(String|Number)?} account
 * @param {Object} options
 * @param {Number} options.start
 * @param {Number} options.end
 * @param {Function} callback - Returns [Error, {@link TX}[]].
 */

Wallet.prototype.getTimeRange = function getTimeRange(account, options, callback) {
  return this.db.getTimeRange(this.id, account, options, callback);
};

/**
 * Zap stale TXs from wallet (accesses db).
 * @param {(Number|String)?} account
 * @param {Number} age - Age threshold (unix time, default=72 hours).
 * @param {Function} callback - Returns [Error].
 */

Wallet.prototype.zap = function zap(account, age, callback) {
  return this.db.zap(this.id, account, age, callback);
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
 * @returns {Base58Address}
 */

Wallet.prototype.getScriptAddress = function getScriptAddress() {
  if (!this.receiveAddress)
    return;
  return this.receiveAddress.getScriptAddress();
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
 * @returns {Base58Address}
 */

Wallet.prototype.getProgramAddress = function getProgramAddress() {
  if (!this.receiveAddress)
    return;
  return this.receiveAddress.getProgramAddress();
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
 * @returns {Base58Address}
 */

Wallet.prototype.getKeyAddress = function getKeyAddress() {
  if (!this.receiveAddress)
    return;
  return this.receiveAddress.getKeyAddress();
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
 * @returns {Base58Address}
 */

Wallet.prototype.getAddress = function getAddress() {
  if (!this.receiveAddress)
    return;
  return this.receiveAddress.getAddress();
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
    id: this.id,
    network: this.network.type,
    initialized: this.initialized,
    accountDepth: this.accountDepth,
    master: this.master.toJSON(),
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
    id: this.id,
    initialized: this.initialized,
    accountDepth: this.accountDepth,
    master: this.master.toJSON(),
    account: this.account ? this.account.toJSON() : null
  };
};

/**
 * Handle a deserialized JSON wallet object.
 * @returns {Object} A "naked" wallet (a
 * plain javascript object which is suitable
 * for passing to the Wallet constructor).
 * @param {Object} json
 * @param {String?} passphrase
 * @returns {Object}
 * @throws Error on bad decrypt
 */

Wallet.parseJSON = function parseJSON(json) {
  return {
    network: json.network,
    id: json.id,
    initialized: json.initialized,
    accountDepth: json.accountDepth,
    master: MasterKey.fromJSON(json.master)
  };
};

/**
 * Serialize the wallet.
 * @returns {Buffer}
 */

Wallet.prototype.toRaw = function toRaw(writer) {
  var p = new BufferWriter(writer);

  p.writeU32(this.network.magic);
  p.writeVarString(this.id, 'utf8');
  p.writeU8(this.initialized ? 1 : 0);
  p.writeU32(this.accountDepth);
  p.writeVarBytes(this.master.toRaw());

  if (!writer)
    p = p.render();

  return p;
};

/**
 * Parse a serialized wallet. Return a "naked"
 * wallet object, suitable for passing into
 * the wallet constructor.
 * @param {Buffer} data
 * @returns {Object}
 */

Wallet.parseRaw = function parseRaw(data) {
  var p = new BufferReader(data);
  var network = bcoin.network.fromMagic(p.readU32());
  var id = p.readVarString('utf8');
  var initialized = p.readU8() === 1;
  var accountDepth = p.readU32();
  var master = MasterKey.fromRaw(p.readVarBytes());

  return {
    network: network.type,
    id: id,
    initialized: initialized,
    accountDepth: accountDepth,
    master: master
  };
};

/**
 * Instantiate a wallet from serialized data.
 * @param {Buffer} data
 * @returns {Wallet}
 */

Wallet.fromRaw = function fromRaw(data) {
  return new Wallet(Wallet.parseRaw(data));
};

/**
 * Instantiate a Wallet from a
 * jsonified wallet object.
 * @param {Object} json - The jsonified wallet object.
 * @returns {Wallet}
 */

Wallet.fromJSON = function fromJSON(json) {
  return new Wallet(Wallet.parseJSON(json));
};

/**
 * Test an object to see if it is a Wallet.
 * @param {Object} obj
 * @returns {Boolean}
 */

Wallet.isWallet = function isWallet(obj) {
  return obj
    && typeof obj.accountDepth === 'number'
    && obj.scriptInputs === 'function';
};

/**
 * Represents a BIP44 Account belonging to a {@link Wallet}.
 * Note that this object does not enforce locks. Any method
 * that does a write is internal API only and will lead
 * to race conditions if used elsewhere.
 * @exports Account
 * @constructor
 * @param {Object} options
 * @param {WalletDB} options.db
 * @param {HDPublicKey} options.accountKey
 * @param {Boolean?} options.witness - Whether to use witness programs.
 * @param {Number} options.accountIndex - The BIP44 account index.
 * @param {Number?} options.receiveDepth - The index of the _next_ receiving
 * address.
 * @param {Number?} options.changeDepth - The index of the _next_ change
 * address.
 * @param {String?} options.type - Type of wallet (pubkeyhash, multisig)
 * (default=pubkeyhash).
 * @param {Number?} options.m - `m` value for multisig.
 * @param {Number?} options.n - `n` value for multisig.
 * @param {String?} options.id - Wallet ID
 * @param {String?} options.name - Account name
 */

function Account(options) {
  var i;

  if (!(this instanceof Account))
    return new Account(options);

  EventEmitter.call(this);

  assert(options, 'Options are required.');
  assert(options.db, 'Database is required.');
  assert(options.id, 'Wallet ID is required.');
  assert(options.accountKey, 'Account key is required.');
  assert(utils.isNumber(options.accountIndex), 'Account index is required.');

  this.options = options;
  this.network = bcoin.network.get(options.network);
  this.db = options.db;
  this.lookahead = Account.LOOKAHEAD;

  this.id = options.id;
  this.name = options.name;
  this.witness = options.witness || false;
  this.accountKey = options.accountKey;
  this.accountIndex = options.accountIndex;
  this.receiveDepth = options.receiveDepth || 0;
  this.changeDepth = options.changeDepth || 0;
  this.type = options.type || 'pubkeyhash';
  this.keys = [];
  this.m = options.m || 1;
  this.n = options.n || 1;
  this.initialized = options.initialized || false;

  this.loaded = false;
  this.loading = false;
  this.receiveAddress = null;
  this.changeAddress = null;

  this.cache = new bcoin.lru(20, 1);

  if (this.n > 1)
    this.type = 'multisig';

  assert(this.type === 'pubkeyhash' || this.type === 'multisig',
    '`type` must be multisig or pubkeyhash.');

  if (this.m < 1 || this.m > this.n)
    throw new Error('m ranges between 1 and n');

  if (!this.name)
    this.name = this.accountIndex + '';

  this.pushKey(this.accountKey);

  if (options.keys) {
    for (i = 0; i < options.keys.length; i++)
      this.pushKey(options.keys[i]);
  }
}

utils.inherits(Account, EventEmitter);

/*
 * Default address lookahead.
 * @const {Number}
 */

Account.LOOKAHEAD = 5;

/**
 * Open the account, register with the database.
 * @param {Function} callback
 */

Account.prototype.open = function open(callback) {
  var self = this;

  callback = utils.ensure(callback);

  if (this.loaded)
    return utils.nextTick(callback);

  if (this.loading)
    return this.once('open', callback);

  this.loading = true;

  this.init(function(err) {
    if (err) {
      self.emit('error', err);
      return callback(err);
    }

    self.loading = false;
    self.loaded = true;
    self.emit('open');

    return callback();
  });
};

/**
 * Close the account, unregister with the database.
 * @method
 * @param {Function} callback
 */

Account.prototype.close =
Account.prototype.destroy = function destroy(callback) {
  callback = utils.ensure(callback);

  if (!this.loaded)
    return utils.nextTick(callback);

  assert(!this.loading);

  this.loaded = false;

  return utils.nextTick(callback);
};

/**
 * Attempt to intialize the account (generating
 * the first addresses along with the lookahead
 * addresses). Called automatically from the
 * walletdb and open().
 * @param {Function} callback
 */

Account.prototype.init = function init(callback) {
  // Waiting for more keys.
  if (this.keys.length !== this.n) {
    assert(!this.initialized);
    return this.save(callback);
  }

  if (this.initialized) {
    this.receiveAddress = this.deriveReceive(this.receiveDepth - 1);
    this.changeAddress = this.deriveChange(this.changeDepth - 1);
    return callback();
  }

  this.initialized = true;

  assert(this.receiveDepth === 0);
  assert(this.changeDepth === 0);

  this.setDepth(1, 1, callback);
};

/**
 * Add a public account key to the account (multisig).
 * Does not update the database.
 * @param {HDPublicKey} key - Account (bip44)
 * key (can be in base58 form).
 * @throws Error on non-hdkey/non-accountkey.
 */

Account.prototype.pushKey = function pushKey(key) {
  var result = false;
  var index = -1;
  var i;

  assert(key, 'Key required.');

  if (Array.isArray(key)) {
    for (i = 0; i < key.length; i++) {
      if (this.pushKey(key[i]))
        result = true;
    }
    return result;
  }

  if (key.accountKey)
    key = key.accountKey;

  if (bcoin.hd.isExtended(key))
    key = bcoin.hd.fromBase58(key);

  if (key.hdPublicKey)
    key = key.hdPublicKey;

  if (!bcoin.hd.isHD(key))
    throw new Error('Must add HD keys to wallet.');

  if (!key.isAccount44())
    throw new Error('Must add HD account keys to BIP44 wallet.');

  for (i = 0; i < this.keys.length; i++) {
    if (this.keys[i].equal(key)) {
      index = i;
      break;
    }
  }

  if (index !== -1)
    return false;

  if (this.keys.length === this.n)
    throw new Error('Cannot add more keys.');

  this.keys.push(key);

  return true;
};

/**
 * Remove a public account key to the account (multisig).
 * Does not update the database.
 * @param {HDPublicKey} key - Account (bip44)
 * key (can be in base58 form).
 * @throws Error on non-hdkey/non-accountkey.
 */

Account.prototype.spliceKey = function spliceKey(key) {
  var result = false;
  var index = -1;
  var i;

  if (Array.isArray(key)) {
    for (i = 0; i < key.length; i++) {
      if (this.spliceKey(key[i]))
        result = true;
    }
    return result;
  }

  assert(key, 'Key required.');

  if (key.accountKey)
    key = key.accountKey;

  if (bcoin.hd.isExtended(key))
    key = bcoin.hd.fromBase58(key);

  if (key.hdPublicKey)
    key = key.hdPublicKey;

  if (!bcoin.hd.isHD(key))
    throw new Error('Must add HD keys to wallet.');

  if (!key.isAccount44())
    throw new Error('Must add HD account keys to BIP44 wallet.');

  for (i = 0; i < this.keys.length; i++) {
    if (this.keys[i].equal(key)) {
      index = i;
      break;
    }
  }

  if (index === -1)
    return false;

  if (this.keys.length === this.n)
    throw new Error('Cannot remove key.');

  this.keys.splice(index, 1);

  return true;
};

/**
 * Add a public account key to the account (multisig).
 * Saves the key in the wallet database.
 * @param {HDPublicKey} key
 * @param {Function} callback
 */

Account.prototype.addKey = function addKey(key, callback) {
  var result = false;
  var error;

  try {
    result = this.pushKey(key);
  } catch (e) {
    error = e;
  }

  this.init(function(err) {
    if (err)
      return callback(err);

    if (error)
      return callback(error);

    return callback(null, result);
  });
};

/**
 * Remove a public account key from the account (multisig).
 * Remove the key from the wallet database.
 * @param {HDPublicKey} key
 * @param {Function} callback
 */

Account.prototype.removeKey = function removeKey(key, callback) {
  var result = false;
  var error;

  try {
    result = this.spliceKey(key);
  } catch (e) {
    error = e;
  }

  this.save(function(err) {
    if (err)
      return callback(err);

    if (error)
      return callback(error);

    return callback(null, result);
  });
};

/**
 * Create a new receiving address (increments receiveDepth).
 * @returns {KeyRing}
 */

Account.prototype.createReceive = function createReceive(callback) {
  return this.createAddress(false, callback);
};

/**
 * Create a new change address (increments receiveDepth).
 * @returns {KeyRing}
 */

Account.prototype.createChange = function createChange(callback) {
  return this.createAddress(true, callback);
};

/**
 * Create a new address (increments depth).
 * @param {Boolean} change
 * @param {Function} callback - Returns [Error, {@link KeyRing}].
 */

Account.prototype.createAddress = function createAddress(change, callback) {
  var self = this;
  var addresses = [];
  var address;

  if (typeof change === 'function') {
    callback = change;
    change = null;
  }

  if (change) {
    address = this.deriveChange(this.changeDepth);
    addresses.push(address);
    addresses.push(this.deriveChange(this.changeDepth + this.lookahead));
    this.changeDepth++;
    this.changeAddress = address;
  } else {
    address = this.deriveReceive(this.receiveDepth);
    addresses.push(address);
    addresses.push(this.deriveReceive(this.receiveDepth + this.lookahead));
    this.receiveDepth++;
    this.receiveAddress = address;
  }

  this.saveAddress(addresses, function(err) {
    if (err)
      return callback(err);

    self.save(function(err) {
      if (err)
        return callback(err);
      return callback(null, address);
    });
  });
};

/**
 * Derive a receiving address at `index`. Do not increment depth.
 * @param {Number} index
 * @returns {KeyRing}
 */

Account.prototype.deriveReceive = function deriveReceive(index) {
  return this.deriveAddress(false, index);
};

/**
 * Derive a change address at `index`. Do not increment depth.
 * @param {Number} index
 * @returns {KeyRing}
 */

Account.prototype.deriveChange = function deriveChange(index) {
  return this.deriveAddress(true, index);
};

/**
 * Derive an address at `index`. Do not increment depth.
 * @param {Boolean} change - Whether the address on the change branch.
 * @param {Number} index
 * @returns {KeyRing}
 */

Account.prototype.deriveAddress = function deriveAddress(change, index) {
  var keys = [];
  var i, key, shared;

  assert(this.initialized, 'Account is not initialized.');

  change = +change;

  key = this.accountKey.derive(change).derive(index);

  for (i = 0; i < this.keys.length; i++) {
    shared = this.keys[i];
    shared = shared.derive(change).derive(index);
    keys.push(shared.publicKey);
  }

  return new bcoin.keyring({
    network: this.network,
    key: key.publicKey,
    name: this.name,
    account: this.accountIndex,
    change: change,
    index: index,
    type: this.type,
    witness: this.witness,
    m: this.m,
    n: this.n,
    keys: keys
  });
};

/**
 * Save the account to the database. Necessary
 * when address depth and keys change.
 * @param {Function} callback
 */

Account.prototype.save = function save(callback) {
  return this.db.saveAccount(this, callback);
};

/**
 * Save addresses to path map.
 * @param {KeyRing[]} address
 * @param {Function} callback
 */

Account.prototype.saveAddress = function saveAddress(address, callback) {
  return this.db.saveAddress(this.id, address, callback);
};

/**
 * Set change and receiving depth (depth is the index of the _next_ address).
 * Allocate all addresses up to depth. Note that this also allocates
 * new lookahead addresses.
 * @param {Number} depth
 * @param {Function} callback - Returns [Error, {@link KeyRing}, {@link KeyRing}].
 */

Account.prototype.setDepth = function setDepth(receiveDepth, changeDepth, callback) {
  var self = this;
  var addresses = [];
  var i, receive, change;

  if (receiveDepth > this.receiveDepth) {
    for (i = this.receiveDepth; i < receiveDepth; i++) {
      receive = this.deriveReceive(i);
      addresses.push(receive);
    }

    for (i = receiveDepth; i < receiveDepth + this.lookahead; i++)
      addresses.push(this.deriveReceive(i));

    this.receiveAddress = receive;
    this.receiveDepth = receiveDepth;
  }

  if (changeDepth > this.changeDepth) {
    for (i = this.changeDepth; i < changeDepth; i++) {
      change = this.deriveChange(i);
      addresses.push(change);
    }

    for (i = changeDepth; i < changeDepth + this.lookahead; i++)
      addresses.push(this.deriveChange(i));

    this.changeAddress = change;
    this.changeDepth = changeDepth;
  }

  if (addresses.length === 0)
    return callback(null, false);

  this.saveAddress(addresses, function(err) {
    if (err)
      return callback(err);

    self.save(function(err) {
      if (err)
        return callback(err);

      return callback(null, receive, change);
    });
  });
};

/**
 * Scan for addresses.
 * @param {Function} getByAddress - Must be a callback which accepts
 * a callback and returns transactions by address.
 * @param {Function} callback - Return [Error, Number] (total number
 * of addresses allocated).
 */

Account.prototype.scan = function scan(getByAddress, callback) {
  var self = this;
  var total = 0;

  if (!this.initialized)
    return callback(new Error('Account is not initialized.'));

  function addTX(txs, calback) {
    if (!Array.isArray(txs) || txs.length === 0)
      return callback(null, false);

    utils.forEachSerial(txs, function(tx, next) {
      self.db.addTX(tx, next);
    }, function(err) {
      if (err)
        return callback(err);

      return callback(null, true);
    });
  }

  (function chainCheck(change) {
    var address = change ? self.changeAddress : self.receiveAddress;
    var gap = 0;

    (function next(err, address) {
      if (err)
        return callback(err);

      getByAddress(address.getAddress(), function(err, txs) {
        if (err)
          return callback(err);

        addTX(txs, function(err, result) {
          if (err)
            return callback(err);

          if (result) {
            total++;
            gap = 0;
            return self.createAddress(change, next);
          }

          if (++gap < 20)
            return self.createAddress(change, next);

          if (!change)
            return chainCheck(true);

          return callback(null, total);
        });
      });
    })(null, address);
  })(false);
};

/**
 * Convert the account to a more inspection-friendly object.
 * @returns {Object}
 */

Account.prototype.inspect = function inspect() {
  return {
    id: this.id,
    name: this.name,
    network: this.network,
    initialized: this.initialized,
    type: this.type,
    m: this.m,
    n: this.n,
    keyAddress: this.initialized
      ? this.receiveAddress.getKeyAddress()
      : null,
    scriptAddress: this.initialized
      ? this.receiveAddress.getScriptAddress()
      : null,
    programAddress: this.initialized
      ? this.receiveAddress.getProgramAddress()
      : null,
    witness: this.witness,
    accountIndex: this.accountIndex,
    receiveDepth: this.receiveDepth,
    changeDepth: this.changeDepth,
    accountKey: this.accountKey.xpubkey,
    keys: this.keys.map(function(key) {
      return key.xpubkey;
    })
  };
};

/**
 * Convert the account to an object suitable for
 * serialization. Will automatically encrypt the
 * master key based on the `passphrase` option.
 * @returns {Object}
 */

Account.prototype.toJSON = function toJSON() {
  return {
    network: this.network.type,
    id: this.id,
    name: this.name,
    initialized: this.initialized,
    type: this.type,
    m: this.m,
    n: this.n,
    witness: this.witness,
    accountIndex: this.accountIndex,
    receiveDepth: this.receiveDepth,
    changeDepth: this.changeDepth,
    receiveAddress: this.receiveAddress
      ? this.receiveAddress.getAddress()
      : null,
    programAddress: this.receiveAddress
      ? this.receiveAddress.getProgramAddress()
      : null,
    changeAddress: this.changeAddress
      ? this.changeAddress.getAddress()
      : null,
    accountKey: this.accountKey.xpubkey,
    keys: this.keys.map(function(key) {
      return key.xpubkey;
    })
  };
};

/**
 * Handle a deserialized JSON account object.
 * @returns {Object} A "naked" account (a
 * plain javascript object which is suitable
 * for passing to the Account constructor).
 * @param {Object} json
 * @param {String?} passphrase
 * @returns {Object}
 * @throws Error on bad decrypt
 */

Account.parseJSON = function parseJSON(json) {
  return {
    network: json.network,
    id: json.id,
    name: json.name,
    initialized: json.initialized,
    type: json.type,
    m: json.m,
    n: json.n,
    witness: json.witness,
    accountIndex: json.accountIndex,
    receiveDepth: json.receiveDepth,
    changeDepth: json.changeDepth,
    accountKey: bcoin.hd.fromBase58(json.accountKey),
    keys: json.keys.map(function(key) {
      return bcoin.hd.fromBase58(key);
    })
  };
};

/**
 * Serialize the account.
 * @returns {Buffer}
 */

Account.prototype.toRaw = function toRaw(writer) {
  var p = new BufferWriter(writer);
  var i;

  p.writeU32(this.network.magic);
  p.writeVarString(this.id, 'utf8');
  p.writeVarString(this.name, 'utf8');
  p.writeU8(this.initialized ? 1 : 0);
  p.writeU8(this.type === 'pubkeyhash' ? 0 : 1);
  p.writeU8(this.m);
  p.writeU8(this.n);
  p.writeU8(this.witness ? 1 : 0);
  p.writeU32(this.accountIndex);
  p.writeU32(this.receiveDepth);
  p.writeU32(this.changeDepth);
  p.writeBytes(this.accountKey.toRaw());
  p.writeU8(this.keys.length);

  for (i = 0; i < this.keys.length; i++)
    p.writeBytes(this.keys[i].toRaw());

  if (!writer)
    p = p.render();

  return p;
};

/**
 * Parse a serialized account. Return a "naked"
 * account object, suitable for passing into
 * the account constructor.
 * @param {Buffer} data
 * @returns {Object}
 */

Account.parseRaw = function parseRaw(data) {
  var p = new BufferReader(data);
  var network = bcoin.network.fromMagic(p.readU32());
  var id = p.readVarString('utf8');
  var name = p.readVarString('utf8');
  var initialized = p.readU8() === 1;
  var type = p.readU8() === 0 ? 'pubkeyhash' : 'multisig';
  var m = p.readU8();
  var n = p.readU8();
  var witness = p.readU8() === 1;
  var accountIndex = p.readU32();
  var receiveDepth = p.readU32();
  var changeDepth = p.readU32();
  var accountKey = bcoin.hd.fromRaw(p.readBytes(82));
  var count = p.readU8();
  var keys = [];
  var i;

  for (i = 0; i < count; i++)
    keys.push(bcoin.hd.fromRaw(p.readBytes(82)));

  return {
    network: network.type,
    id: id,
    name: name,
    initialized: initialized,
    type: type,
    m: m,
    n: n,
    witness: witness,
    accountIndex: accountIndex,
    receiveDepth: receiveDepth,
    changeDepth: changeDepth,
    accountKey: accountKey,
    keys: keys
  };
};

/**
 * Instantiate a account from serialized data.
 * @param {Buffer} data
 * @returns {Account}
 */

Account.fromRaw = function fromRaw(data) {
  return new Account(Account.parseRaw(data));
};

/**
 * Instantiate a Account from a
 * jsonified account object.
 * @param {Object} json - The jsonified account object.
 * @returns {Account}
 */

Account.fromJSON = function fromJSON(json) {
  return new Account(Account.parseJSON(json));
};

/**
 * Test an object to see if it is a Account.
 * @param {Object} obj
 * @returns {Boolean}
 */

Account.isAccount = function isAccount(obj) {
  return obj
    && typeof obj.receiveDepth === 'number'
    && obj.deriveAddress === 'function';
};

/**
 * Master BIP32 key which can exist
 * in an timed out encrypted state.
 * @exports Master
 * @constructor
 * @param {Object} options
 */

function MasterKey(options) {
  if (!(this instanceof MasterKey))
    return new MasterKey(options);

  this.encrypted = !!options.encrypted;
  this.xprivkey = options.xprivkey;
  this.phrase = options.phrase;
  this.passphrase = options.passphrase;
  this.key = options.key || null;
  this.timer = null;
  this._destroy = this.destroy.bind(this);

  assert(this.encrypted ? !this.key : this.key);
}

/**
 * Decrypt the key and set a timeout to destroy decrypted data.
 * @param {Buffer|String} passphrase - Zero this yourself.
 * @param {Number} [timeout=60000] timeout in ms.
 * @returns {HDPrivateKey}
 */

MasterKey.prototype.toKey = function toKey(passphrase, timeout) {
  var xprivkey;

  if (!this.key) {
    assert(this.encrypted);
    xprivkey = utils.decrypt(this.xprivkey, passphrase);
    this.key = bcoin.hd.fromRaw(xprivkey);
    xprivkey.fill(0);
    this.start(timeout);
  }

  return this.key;
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
  }
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
    this.key.chainCode.fill(0);
    this.key.privateKey.fill(0);
    this.key.publicKey.fill(0);
    this.key = null;
  }
};

/**
 * Decrypt the key permanently.
 * @param {Buffer|String} passphrase - Zero this yourself.
 */

MasterKey.prototype.decrypt = function decrypt(passphrase) {
  if (!this.encrypted) {
    assert(this.key);
    return;
  }

  assert(passphrase, 'Passphrase is required.');

  this.destroy();

  this.encrypted = false;
  this.xprivkey = utils.decrypt(this.xprivkey, passphrase);

  if (this.phrase) {
    this.phrase = utils.decrypt(this.phrase, passphrase);
    this.passphrase = utils.decrypt(this.passphrase, passphrase);
  }

  this.key = bcoin.hd.fromRaw(this.xprivkey);
};

/**
 * Encrypt the key permanently.
 * @param {Buffer|String} passphrase - Zero this yourself.
 */

MasterKey.prototype.encrypt = function encrypt(passphrase) {
  var xprivkey = this.xprivkey;
  var phrase = this.phrase;
  var pass = this.passphrase;

  if (this.encrypted)
    return;

  assert(passphrase, 'Passphrase is required.');

  this.key = null;
  this.encrypted = true;
  this.xprivkey = utils.encrypt(xprivkey, passphrase);
  xprivkey.fill(0);

  if (this.phrase) {
    this.phrase = utils.encrypt(phrase, passphrase);
    this.passphrase = utils.encrypt(pass, passphrase);
    phrase.fill(0);
    pass.fill(0);
  }
};

/**
 * Serialize the key in the form of:
 * `[enc-flag][phrase-marker][phrase?][passphrase?][xprivkey]`
 * @returns {Buffer}
 */

MasterKey.prototype.toRaw = function toRaw(writer) {
  var p = new BufferWriter(writer);

  p.writeU8(this.encrypted ? 1 : 0);

  if (this.phrase) {
    p.writeU8(1);
    p.writeVarBytes(this.phrase);
    p.writeVarBytes(this.passphrase);
  } else {
    p.writeU8(0);
  }

  p.writeBytes(this.xprivkey);

  if (!writer)
    p = p.render();

  return p;
};

/**
 * Instantiate master key from serialized data.
 * @returns {MasterKey}
 */

MasterKey.fromRaw = function fromRaw(raw) {
  var p = new BufferReader(raw);
  var encrypted, phrase, passphrase, xprivkey, key;

  encrypted = p.readU8() === 1;

  if (p.readU8() === 1) {
    phrase = p.readVarBytes();
    passphrase = p.readVarBytes();
  }

  xprivkey = p.readBytes(82);

  if (!encrypted)
    key = bcoin.hd.fromRaw(xprivkey);

  return new MasterKey({
    encrypted: encrypted,
    phrase: phrase,
    passphrase: passphrase,
    xprivkey: xprivkey,
    key: key
  });
};

/**
 * Instantiate master key from an HDPrivateKey.
 * @param {HDPrivateKey} key
 * @returns {MasterKey}
 */

MasterKey.fromKey = function fromKey(key) {
  var phrase, passphrase;

  if (key.mnemonic) {
    phrase = new Buffer(key.mnemonic.phrase, 'utf8');
    passphrase = new Buffer(key.mnemonic.passphrase, 'utf8');
  }

  return new MasterKey({
    encrypted: false,
    phrase: phrase,
    passphrase: passphrase,
    xprivkey: key.toRaw(),
    key: key
  });
};

/**
 * Convert master key to a jsonifiable object.
 * @returns {Object}
 */

MasterKey.prototype.toJSON = function toJSON() {
  var phrase, passphrase, xprivkey;

  if (this.encrypted) {
    if (this.phrase) {
      phrase = this.phrase.toString('hex');
      passphrase = this.passphrase.toString('hex');
    }
    xprivkey = this.xprivkey.toString('hex');
  } else {
    if (this.phrase) {
      phrase = this.phrase.toString('utf8');
      passphrase = this.passphrase.toString('utf8');
    }
    xprivkey = utils.toBase58(this.xprivkey);
  }

  return {
    encrypted: this.encrypted,
    phrase: phrase,
    passphrase: passphrase,
    xprivkey: xprivkey
  };
};

/**
 * Instantiate master key from jsonified object.
 * @returns {MasterKey}
 */

MasterKey.fromJSON = function fromJSON(json) {
  var phrase, passphrase, xprivkey, key;

  if (json.encrypted) {
    if (json.phrase) {
      phrase = new Buffer(json.phrase, 'hex');
      passphrase = new Buffer(json.passphrase, 'hex');
    }
    xprivkey = new Buffer(json.xprivkey, 'hex');
  } else {
    if (json.phrase) {
      phrase = new Buffer(json.phrase, 'utf8');
      passphrase = new Buffer(json.passphrase, 'utf8');
    }
    xprivkey = utils.fromBase58(json.xprivkey);
  }

  if (!json.encrypted)
    key = bcoin.hd.fromRaw(xprivkey);

  return new MasterKey({
    encrypted: json.encrypted,
    phrase: phrase,
    passphrase: passphrase,
    xprivkey: xprivkey,
    key: key
  });
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

exports = Wallet;
exports.Account = Account;
exports.MasterKey = MasterKey;

module.exports = exports;
