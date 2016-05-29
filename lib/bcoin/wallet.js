/*!
 * wallet.js - wallet object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/indutny/bcoin
 */

var bcoin = require('./env');
var EventEmitter = require('events').EventEmitter;
var utils = require('./utils');
var assert = utils.assert;
var constants = bcoin.protocol.constants;
var BufferWriter = require('./writer');

/**
 * HD BIP-44/45 wallet
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
 * @param {Boolean?} options.copayBIP45 - Use copay-style BIP45 if bip45
 * derivation is used.
 * @param {Number?} options.lookahead - Amount of lookahead addresses
 * (default=5).
 * @param {String?} options.type - Type of wallet (pubkeyhash, multisig)
 * (default=pubkeyhash).
 * @param {String?} options.derivation - Derivation type (bip44, bip45)
 * (default=bip44).
 * @param {Boolean?} options.compressed - Whether to use compressed
 * public keys (default=true).
 * @param {Number?} options.m - `m` value for multisig.
 * @param {Number?} options.n - `n` value for multisig.
 * @param {String?} options.id - Wallet ID (used for storage)
 * (default=account key "address").
 */

function Wallet(options) {
  var i, key;

  if (!(this instanceof Wallet))
    return new Wallet(options);

  EventEmitter.call(this);

  if (!options)
    options = {};

  options = utils.merge({}, options);

  this.options = options;
  this.network = bcoin.network.get(options.network);
  this.db = options.db;

  if (!this.db)
    this.db = new bcoin.walletdb({ name: 'wtmp', db: 'memory' });

  if (!options.master)
    options.master = bcoin.hd.fromMnemonic(null, this.network);

  if (!bcoin.hd.isHD(options.master) && !MasterKey.isMasterKey(options.master))
    options.master = bcoin.hd.fromAny(options.master, this.network);

  if (!MasterKey.isMasterKey(options.master))
    options.master = MasterKey.fromKey(options.master);

  this.id = options.id || null;
  this.master = options.master || null;
  this.accountKey = options.accountKey || null;
  this.witness = options.witness || false;
  this.loaded = false;

  this.accountIndex = options.accountIndex || 0;
  this.receiveDepth = options.receiveDepth || 1;
  this.changeDepth = options.changeDepth || 1;
  this.copayBIP45 = options.copayBIP45 || false;
  this.lookahead = options.lookahead != null ? options.lookahead : 5;
  this.cosignerIndex = -1;
  this.initialized = false;

  this.type = options.type || 'pubkeyhash';
  this.derivation = options.derivation || 'bip44';
  this.compressed = options.compressed !== false;
  this.keys = [];
  this.m = options.m || 1;
  this.n = options.n || 1;

  this.cache = new bcoin.lru(20, 1);

  if (this.n > 1)
    this.type = 'multisig';

  assert(this.type === 'pubkeyhash' || this.type === 'multisig',
    '`type` must be multisig or pubkeyhash.');

  if (this.m < 1 || this.m > this.n)
    throw new Error('m ranges between 1 and n');

  if (!this.accountKey) {
    key = this.master.key;

    assert(key);

    if (this.derivation === 'bip45')
      key = key.derivePurpose45().hdPublicKey;
    else if (this.derivation === 'bip44')
      key = key.deriveAccount44(this.accountIndex).hdPublicKey;
    else
      assert(false);

    this.accountKey = key;
  }

  if (!this.id)
    this.id = this.getID();

  // Non-alphanumeric IDs will break leveldb sorting.
  assert(/^[a-zA-Z0-9]+$/.test(this.id), 'Wallet IDs must be alphanumeric.');

  this._addKey(this.accountKey);

  if (options.keys) {
    for (i = 0; i < options.keys.length; i++)
      this._addKey(options.keys[i]);
  }
}

utils.inherits(Wallet, EventEmitter);

Wallet.prototype.init = function init(callback) {
  var self = this;
  var addresses = [];
  var i;

  // Waiting for more keys.
  if (this.keys.length !== this.n) {
    assert(!this.initialized);
    return this.db.open(function(err) {
      if (err)
        return callback(err);
      self.save(callback);
    });
  }

  if (this.initialized) {
    this.receiveAddress = this.deriveReceive(this.receiveDepth - 1);
    this.changeAddress = this.deriveChange(this.changeDepth - 1);
    return this.db.open(callback);
  }

  this.initialized = true;

  for (i = 0; i < this.receiveDepth - 1; i++)
    addresses.push(this.deriveReceive(i));

  for (i = 0; i < this.changeDepth - 1; i++)
    addresses.push(this.deriveChange(i));

  for (i = this.receiveDepth; i < this.receiveDepth + this.lookahead; i++)
    addresses.push(this.deriveReceive(i));

  for (i = this.changeDepth; i < this.changeDepth + this.lookahead; i++)
    addresses.push(this.deriveChange(i));

  this.receiveAddress = this.deriveReceive(this.receiveDepth - 1);
  this.changeAddress = this.deriveChange(this.changeDepth - 1);

  addresses.push(this.receiveAddress);
  addresses.push(this.changeAddress);

  return this.db.open(function(err) {
    if (err)
      return callback(err);
    return self.saveAddress(addresses, function(err) {
      if (err)
        return callback(err);
      return self.save(callback);
    });
  });
};

/**
 * Add a public account/purpose key to the wallet for multisig.
 * @param {HDPublicKey|Base58String} key - Account (bip44) or
 * Purpose (bip45) key (can be in base58 form).
 * @throws Error on non-hdkey/non-accountkey.
 */

Wallet.prototype._addKey = function addKey(key) {
  var result = false;
  var index, i;

  assert(key, 'Key required.');

  if (Array.isArray(key)) {
    for (i = 0; i < key.length; i++) {
      if (this._addKey(key[i]))
        result = true;
    }
    return result;
  }

  if (key instanceof bcoin.wallet) {
    assert(key.derivation === this.derivation);
    key = key.accountKey;
  }

  if (bcoin.hd.isExtended(key))
    key = bcoin.hd.fromBase58(key);

  if (key.hdPublicKey)
    key = key.hdPublicKey;

  if (!bcoin.hd.isHD(key))
    throw new Error('Must add HD keys to wallet.');

  if (this.derivation === 'bip44') {
    if (!key.isAccount44())
      throw new Error('Must add HD account keys to BIP44 wallet.');
  } else if (this.derivation === 'bip45') {
    if (!key.isPurpose45())
      throw new Error('Must add HD purpose keys to BIP45 wallet.');
  }

  for (i = 0; i < this.keys.length; i++) {
    if (this.keys[i].equal(key)) {
      index = i;
      break;
    }
  }

  if (index != null)
    return false;

  assert(!this._keysFinalized);

  this.keys.push(key);

  if (this.keys.length === this.n)
    this._finalizeKeys();

  return true;
};

Wallet.prototype.addKey = function addKey(key, callback) {
  if (this._addKey(key))
    this.init(callback);
};

/**
 * Remove a public account/purpose key to the wallet for multisig.
 * @param {HDPublicKey|Base58String} key - Account (bip44) or Purpose
 * (bip45) key (can be in base58 form).
 * @throws Error on non-hdkey/non-accountkey.
 */

Wallet.prototype._removeKey = function removeKey(key) {
  var result = false;
  var index, i;

  assert(!this._keysFinalized);

  if (Array.isArray(key)) {
    for (i = 0; i < key.length; i++) {
      if (this._removeKey(key[i]))
        result = true;
    }
    return result;
  }

  assert(key, 'Key required.');

  if (key instanceof bcoin.wallet) {
    assert(key.derivation === this.derivation);
    key = key.accountKey;
  }

  if (bcoin.hd.isExtended(key))
    key = bcoin.hd.fromBase58(key);

  if (key.hdPublicKey)
    key = key.hdPublicKey;

  if (!bcoin.hd.isHD(key))
    throw new Error('Must add HD keys to wallet.');

  if (this.derivation === 'bip44') {
    if (!key.isAccount44())
      throw new Error('Must add HD account keys to BIP44 wallet.');
  } else if (this.derivation === 'bip45') {
    if (!key.isPurpose45())
      throw new Error('Must add HD purpose keys to BIP45 wallet.');
  }

  for (i = 0; i < this.keys.length; i++) {
    if (this.keys[i].equal(key)) {
      index = i;
      break;
    }
  }

  if (index == null)
    return false;

  this.keys.splice(index, 1);

  return true;
};

Wallet.prototype.removeKey = function removeKey(key, callback) {
  var self = this;

  if (this.keys.length === this.n)
    return callback(new Error('Cannot remove the fucking key now.'));

  if (this._removeKey(key))
    this.save(callback);
};

Wallet.prototype._finalizeKeys = function _finalizeKeys() {
  var i;

  assert(!this._keysFinalized);
  this._keysFinalized = true;

  this.keys = utils.sortHDKeys(this.keys);

  for (i = 0; i < this.keys.length; i++) {
    if (this.keys[i].equal(this.accountKey)) {
      this.cosignerIndex = i;
      break;
    }
  }

  assert(this.cosignerIndex !== -1);
};

/**
 * Get the wallet ID which is either the passed in `id`
 * option, or the account/purpose key converted to an
 * address with a prefix of `0x03be04` (`WLT`).
 * @returns {Base58String}
 */

Wallet.prototype.getID = function getID() {
  var publicKey = this.accountKey.publicKey;
  var p;

  p = new BufferWriter();
  p.writeU8(0x03);
  p.writeU8(0xbe);
  p.writeU8(0x04);
  p.writeBytes(utils.ripesha(publicKey));
  p.writeChecksum();

  return utils.toBase58(p.render());
};

/**
 * Create a new receiving address (increments receiveDepth).
 * @returns {KeyRing}
 */

Wallet.prototype.createReceive = function createReceive(callback) {
  return this.createAddress(false, callback);
};

/**
 * Create a new change address (increments receiveDepth).
 * @returns {KeyRing}
 */

Wallet.prototype.createChange = function createChange(callback) {
  return this.createAddress(true, callback);
};

/**
 * Create a new address (increments depth).
 * @param {Boolean} change
 * @returns {KeyRing}
 */

Wallet.prototype.createAddress = function createAddress(change, callback) {
  var self = this;
  var addresses = [];
  var address;

  if (typeof change === 'function') {
    callback = change;
    change = null;
  }

  if (typeof change === 'string')
    change = this.parsePath(change).change;

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

Wallet.prototype.deriveReceive = function deriveReceive(index) {
  if (typeof index === 'string')
    index = this.parsePath(index).index;

  return this.deriveAddress(false, index);
};

/**
 * Derive a change address at `index`. Do not increment depth.
 * @param {Number} index
 * @returns {KeyRing}
 */

Wallet.prototype.deriveChange = function deriveChange(index) {
  if (typeof index === 'string')
    index = this.parsePath(index).index;

  return this.deriveAddress(true, index);
};

/**
 * Derive an address at `index`. Do not increment depth.
 * @param {Boolean} change - Whether the address on the change branch.
 * @param {Number} index
 * @returns {KeyRing}
 */

Wallet.prototype.deriveAddress = function deriveAddress(change, index) {
  var self = this;
  var i, path, data, key, options, address;

  assert(this.initialized);

  if (typeof change === 'string')
    path = change;

  if (path) {
    data = this.parsePath(path);
  } else {
    data = {
      path: this.createPath(this.cosignerIndex, change, index),
      cosignerIndex: this.copayBIP45
        ? constants.hd.HARDENED - 1
        : this.cosignerIndex,
      change: change,
      index: index
    };
  }

  if (this.cache.has(data.path))
    return this.cache.get(data.path);

  key = this.accountKey.derive(data.path);

  options = {
    network: this.network,
    key: key.publicKey,
    change: data.change,
    index: data.index,
    path: data.path,
    type: this.type,
    witness: this.witness,
    m: this.m,
    n: this.n,
    keys: []
  };

  for (i = 0; i < this.keys.length; i++) {
    key = this.keys[i];
    path = this.createPath(i, data.change, data.index);
    key = key.derive(path);
    options.keys.push(key.publicKey);
  }

  address = new bcoin.keyring(options);

  this.emit('add address', address);

  this.cache.set(data.path, address);

  return address;
};

Wallet.prototype.save = function save(callback) {
  this.db.save(this, callback);
};

Wallet.prototype.saveAddress = function saveAddress(address, callback) {
  this.db.saveAddress(this.id, address, callback);
};

/**
 * Test whether the wallet posesses an address.
 * @param {Base58Address} address
 * @returns {Boolean}
 */

Wallet.prototype.hasAddress = function hasAddress(address, callback) {
  this.db.hasAddress(this.id, address, callback);
};

/**
 * Create a path.
 * @param {Number} cosignerIndex - The index of the target key.
 * Note that this will always be `0x80000000 - 1` if `copayBIP45`
 * is enabled.
 * @param {Boolean} change - Whether the key is on the change branch.
 * @param {Number} index - The index to derive to.
 * @returns {String} path
 */

Wallet.prototype.createPath = function createPath(cosignerIndex, change, index) {
  if (this.copayBIP45)
    cosignerIndex = constants.hd.HARDENED - 1;

  return 'm'
    + (this.derivation === 'bip45' ? '/' + cosignerIndex : '')
    + '/' + (change ? 1 : 0)
    + '/' + index;
};

/**
 * Parse a path.
 * @param {String} path
 * @returns {Object} {
 *   path: String, cosignerIndex: Number?,
 *   change: Boolean, index: Number
 * }
 */

Wallet.prototype.parsePath = function parsePath(path) {
  var parts;

  if (this.derivation === 'bip45')
    assert(/^m\/\d+\/\d+\/\d+$/.test(path));
  else
    assert(/^m\/\d+\/\d+$/.test(path));

  parts = path.split('/');

  if (this.derivation === 'bip45' && this.copayBIP45)
    assert(+parts[parts.length - 3] === constants.hd.HARDENED - 1);

  return {
    path: path,
    cosignerIndex: this.derivation === 'bip45'
      ? +parts[parts.length - 3]
      : null,
    change: +parts[parts.length - 2] === 1,
    index: +parts[parts.length - 1]
  };
};

/**
 * Set receiving depth (depth is the index of the _next_ address).
 * Allocate all addresses up to depth. Note that this also allocates
 * new lookahead addresses.
 * @param {Number} depth
 * @returns {Boolean} True if new addresses were allocated.
 */

Wallet.prototype.setReceiveDepth = function setReceiveDepth(depth, callback) {
  var self = this;
  var addresses = [];
  var i;

  if (!(depth > this.receiveDepth))
    return callback(null, false);

  for (i = this.receiveDepth; i < depth; i++) {
    this.receiveAddress = this.deriveReceive(i);
    addresses.push(this.receiveAddress);
  }

  for (i = this.receiveDepth + this.lookahead; i < depth + this.lookahead; i++)
    addresses.push(this.deriveReceive(i));

  this.receiveDepth = depth;

  this.saveAddress(addresses, function(err) {
    if (err)
      return callback(err);

    self.save(function(err) {
      if (err)
        return callback(err);

      return callback(null, true);
    });
  });
};

/**
 * Set change depth (depth is the index of the _next_ address).
 * Allocate all addresses up to depth. Note that this also allocates
 * new lookahead addresses.
 * @param {Number} depth
 * @returns {Boolean} True if new addresses were allocated.
 */

Wallet.prototype.setChangeDepth = function setChangeDepth(depth, callback) {
  var self = this;
  var addresses = [];
  var i;

  if (!(depth > this.changeDepth))
    return callback(null, false);

  for (i = this.changeDepth; i < depth; i++) {
    this.changeAddress = this.deriveChange(i);
    addresses.push(this.changeAddress);
  }

  for (i = this.changeDepth + this.lookahead; i < depth + this.lookahead; i++)
    addresses.push(this.deriveChange(i));

  this.changeDepth = depth;

  this.saveAddress(addresses, function(err) {
    if (err)
      return callback(err);
    self.save(function(err) {
      if (err)
        return callback(err);
      return callback(null, true);
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

  assert(this.initialized);

  this.getCoins(function(err, coins) {
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
        changeAddress: self.changeAddress.getAddress(),
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
};

/**
 * Fill transaction with coins (accesses db).
 * @param {TX} tx
 * @param {Function} callback - Returns [Error, {@link TX}].
 */

Wallet.prototype.fillCoins = function fillCoins(tx, callback) {
  return this.db.fillHistory(this.id, tx, callback);
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
  var i;

  this.getInputPaths(tx, function(err, paths) {
    if (err)
      return callback(err);

    for (i = 0; i < paths.length; i++)
      addresses.push(self.deriveAddress(paths[i]));

    return callback(null, addresses);
  });
};

/**
 * Get path by address.
 * @param {Base58Address} address - Base58 address.
 */

Wallet.prototype.getPath = function getPath(address, callback) {
  if (!address || typeof address !== 'string')
    return callback();
  this.db.getPath(this.id, address, callback);
};

/**
 * Map input addresses to paths.
 * @param {TX|Input} tx
 * @param {Number?} index
 * @returns {String[]}
 */

Wallet.prototype.getInputPaths = function getInputPaths(tx, callback) {
  var self = this;
  var paths = [];
  var i, input, address, path;

  if (tx instanceof bcoin.input) {
    return this.getPath(tx.coin.getHash(), function(err, path) {
      if (err)
        return callback(err);

      if (path)
        paths.push(path);

      return callback(null, paths);
    });
  }

  utils.forEachSerial(tx.inputs, function(input, next, i) {
    if (!input.coin)
      return next(new Error('Not all coins available.'));

    self.getPath(input.coin.getHash(), function(err, path) {
      if (err)
        return next(err);

      if (!path)
        return next();

      paths.push(path);

      return next();
    });
  }, function(err) {
    if (err)
      return next(err);
    return callback(null, utils.uniq(paths));
  });
};

/**
 * Map output addresses to paths.
 * @param {TX|Output}
 * @param {Number?} index
 * @returns {String[]}
 */

Wallet.prototype.getOutputPaths = function getOutputPaths(tx, callback) {
  var self = this;
  var paths = [];
  var i, input, address, path;

  if (tx instanceof bcoin.output) {
    return this.getPath(tx.getHash(), function(err, path) {
      if (err)
        return callback(err);
      if (path)
        paths.push(path);
      return callback(null, paths);
    });
  }

  utils.forEachSerial(tx.outputs, function(output, next, i) {
    self.getPath(output.getHash(), function(err, path) {
      if (err)
        return next(err);

      if (!path)
        return next();

      paths.push(path);

      return next();
    });
  }, function(err) {
    if (err)
      return next(err);
    return callback(null, utils.uniq(paths));
  });
};

/**
 * Get the maximum address depth based on a transactions outputs.
 * @param {TX} tx
 * @returns {Object} { changeDepth: Number, receiveDepth: Number }
 */

Wallet.prototype.getOutputDepth = function getOutputDepth(tx, callback) {
  var self = this;
  var depth = { changeDepth: -1, receiveDepth: -1 };
  var i, path;

  this.getOutputPaths(tx, function(err, paths) {
    if (err)
      return callback(err);

    for (i = 0; i < paths.length; i++) {
      path = self.parsePath(paths[i]);
      if (path.change) {
        if (path.index > depth.changeDepth)
          depth.changeDepth = path.index;
      } else {
        if (path.index > depth.receiveDepth)
          depth.receiveDepth = path.index;
      }
    }

    depth.changeDepth++;
    depth.receiveDepth++;

    return callback(null, depth);
  });
};

/**
 * Sync address depths based on a transaction's outputs.
 * This is used for deriving new addresses when
 * a confirmed transaction is seen.
 * @param {TX} tx
 * @returns {Boolean} Whether new addresses were allocated.
 */

Wallet.prototype.syncOutputDepth = function syncOutputDepth(tx, callback) {
  var self = this;
  var result = false;

  this.getOutputDepth(tx, function(err, depth) {
    if (err)
      return callback(err);

    self.setChangeDepth(depth.changeDepth + 1, function(err, res) {
      if (err)
        return callback(err);

      if (res)
        result = true;

      self.setReceiveDepth(depth.receiveDepth + 1, function(err, res) {
        if (err)
          return callback(err);

        if (res)
          result = true;

        return callback(null, result);
      });
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

    address = self.deriveAddress(path);

    if (address.program && hash.length === 20) {
      if (utils.equal(hash, address.programHash))
        return callback(null, address.program);
    }

    return callback(null, address.script);
  });
};

/**
 * Zap stale TXs from wallet (accesses db).
 * @param {Number} now - Current time (unix time).
 * @param {Number} age - Age threshold (unix time, default=72 hours).
 * @param {Function} callback - Returns [Error].
 */

Wallet.prototype.zap = function zap(now, age, callback) {
  return this.db.zapWallet(this.id, now, age, callback);
};

/**
 * Scan for addresses.
 * @param {Function} getByAddress - Must be a callback which accepts
 * a callback and returns transactions by address.
 * @param {Function} callback - Returns [Boolean, TX[]].
 */

Wallet.prototype.scan = function scan(getByAddress, callback) {
  var self = this;
  var result = false;

  return this._scan(getByAddress, function(err, depth, txs) {
    if (err)
      return callback(err);

    self.setChangeDepth(depth.changeDepth + 1, function(err, res) {
      if (err)
        return callback(err);

      if (res)
        result = true;

      self.setReceiveDepth(depth.receiveDepth + 1, function(err, res) {
        if (err)
          return callback(err);

        if (res)
          result = true;

        return callback(null, result, txs);
      });
    });
  });
};

Wallet.prototype._scan = function _scan(getByAddress, callback) {
  var self = this;
  var depth = { changeDepth: 0, receiveDepth: 0 };
  var all = [];

  assert(this.initialized);

  (function chainCheck(change) {
    var addressIndex = 0;
    var total = 0;
    var gap = 0;

    (function next() {
      var address = self.deriveAddress(change, addressIndex++);

      getByAddress(address.getAddress(), function(err, txs) {
        var result;

        if (err)
          return callback(err);

        if (txs) {
          if (typeof txs === 'boolean')
            result = txs;
          else if (typeof txs === 'number')
            result = txs > 0;
          else if (Array.isArray(txs))
            result = txs.length > 0;
          else
            result = false;

          if (Array.isArray(txs) && (txs[0] instanceof bcoin.tx))
            all = all.concat(txs);
        }

        if (result) {
          total++;
          gap = 0;
          return next();
        }

        if (++gap < 20)
          return next();

        assert(depth.receiveDepth === 0 || change === true);

        if (change === false)
          depth.receiveDepth = addressIndex - gap;
        else
          depth.changeDepth = addressIndex - gap;

        if (change === false)
          return chainCheck(true);

        return callback(null, depth, all);
      });
    })();
  })(false);
};

/**
 * Build input scripts templates for a transaction (does not
 * sign, only creates signature slots). Only builds scripts
 * for inputs that are redeemable by this wallet.
 * @param {MTX} tx
 * @param {Number?} index - Index of input. If not present,
 * it will attempt to sign all redeemable inputs.
 * @returns {Number} Total number of scripts built.
 */

Wallet.prototype.scriptInputs = function scriptInputs(tx, callback) {
  var self = this;
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
 * @returns {Number} Total number of inputs scripts built and signed.
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
      master = self.master.decrypt(options.passphrase);
    } catch (e) {
      return callback(null, 0);
    }

    for (i = 0; i < addresses.length; i++) {
      address = addresses[i];
      key = master;

      if (self.derivation === 'bip44') {
        key = key.deriveAccount44(self.accountIndex);
        assert.equal(key.xpubkey, self.accountKey.xpubkey);
      } else if (self.derivation === 'bip45') {
        key = key.derivePurpose45();
        assert.equal(key.xpubkey, self.accountKey.xpubkey);
      } else {
        assert(false);
      }

      key = key.derive(address.path);

      assert(utils.equal(key.getPublicKey(), address.key));

      total += address.sign(tx, key, options.index, options.type);
    }

    return callback(null, total);
  });
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
 * @param {Function} callback - Returns [Error, {@link TX}[]].
 */

Wallet.prototype.getHistory = function getHistory(callback) {
  return this.db.getHistory(this.id, callback);
};

/**
 * Get all available coins (accesses db).
 * @param {Function} callback - Returns [Error, {@link Coin}[]].
 */

Wallet.prototype.getCoins = function getCoins(callback) {
  return this.db.getCoins(this.id, callback);
};

/**
 * Get all pending/unconfirmed transactions (accesses db).
 * @param {Function} callback - Returns [Error, {@link TX}[]].
 */

Wallet.prototype.getUnconfirmed = function getUnconfirmed(callback) {
  return this.db.getUnconfirmed(this.id, callback);
};

/**
 * Get wallet balance (accesses db).
 * @param {Function} callback - Returns [Error, {@link Balance}].
 */

Wallet.prototype.getBalance = function getBalance(callback) {
  return this.db.getBalance(this.id, callback);
};

/**
 * Get last timestamp and height this wallet was active
 * at (accesses db). Useful for resetting the chain
 * to a certain height when in SPV mode.
 * @param {Function} callback - Returns [Error, Number(ts), Number(height)].
 */

Wallet.prototype.getLastTime = function getLastTime(callback) {
  return this.db.getLastTime(this.id, callback);
};

/**
 * Get the last N transactions (accesses db).
 * @param {Number} limit
 * @param {Function} callback - Returns [Error, {@link TX}[]].
 */

Wallet.prototype.getLast = function getLast(limit, callback) {
  return this.db.getLast(this.id, limit, callback);
};

/**
 * Get a range of transactions between two timestamps (accesses db).
 * @param {Object} options
 * @param {Number} options.start
 * @param {Number} options.end
 * @param {Function} callback - Returns [Error, {@link TX}[]].
 */

Wallet.prototype.getTimeRange = function getTimeRange(options, callback) {
  return this.db.getTimeRange(this.id, options, callback);
};

/**
 * Get public key for current receiving address.
 * @param {String?} enc - `"hex"` or `null`.
 * @returns {Buffer}
 */

Wallet.prototype.getPublicKey = function getPublicKey(enc) {
  return this.receiveAddress.getPublicKey(enc);
};

/**
 * Get redeem script for current receiving address.
 * @returns {Script}
 */

Wallet.prototype.getScript = function getScript() {
  return this.receiveAddress.getScript();
};

/**
 * Get scripthash for current receiving address.
 * @param {String?} enc - `"hex"` or `null`.
 * @returns {Buffer}
 */

Wallet.prototype.getScriptHash = function getScriptHash(enc) {
  return this.receiveAddress.getScriptHash(enc);
};

/**
 * Get ripemd160 scripthash for current receiving address.
 * @param {String?} enc - `"hex"` or `null`.
 * @returns {Buffer}
 */

Wallet.prototype.getScriptHash160 = function getScriptHash160(enc) {
  return this.receiveAddress.getScriptHash160(enc);
};

/**
 * Get sha256 scripthash for current receiving address.
 * @param {String?} enc - `"hex"` or `null`.
 * @returns {Buffer}
 */

Wallet.prototype.getScriptHash256 = function getScriptHash256(enc) {
  return this.receiveAddress.getScriptHash256(enc);
};

/**
 * Get scripthash address for current receiving address.
 * @returns {Base58Address}
 */

Wallet.prototype.getScriptAddress = function getScriptAddress() {
  return this.receiveAddress.getScriptAddress();
};

/**
 * Get witness program for current receiving address.
 * @returns {Buffer}
 */

Wallet.prototype.getProgram = function getProgram() {
  return this.receiveAddress.getProgram();
};

/**
 * Get current receiving address' ripemd160 program
 * scripthash (for witness programs behind a scripthash).
 * @param {String?} enc - `"hex"` or `null`.
 * @returns {Buffer}
 */

Wallet.prototype.getProgramHash = function getProgramHash(enc) {
  return this.receiveAddress.getProgramHash(enc);
};

/**
 * Get current receiving address'
 * scripthash address for witness program.
 * @returns {Base58Address}
 */

Wallet.prototype.getProgramAddress = function getProgramAddress() {
  return this.receiveAddress.getProgramAddress();
};

/**
 * Get public key hash for current receiving address.
 * @param {String?} enc - `"hex"` or `null`.
 * @returns {Buffer}
 */

Wallet.prototype.getKeyHash = function getKeyHash(enc) {
  return this.receiveAddress.getKeyHash(enc);
};

/**
 * Get pubkeyhash address for current receiving address.
 * @returns {Base58Address}
 */

Wallet.prototype.getKeyAddress = function getKeyAddress() {
  return this.receiveAddress.getKeyAddress();
};

/**
 * Get hash for current receiving address.
 * @param {String?} enc - `"hex"` or `null`.
 * @returns {Buffer}
 */

Wallet.prototype.getHash = function getHash(enc) {
  return this.receiveAddress.getHash(enc);
};

/**
 * Get base58 address for current receiving address.
 * @returns {Base58Address}
 */

Wallet.prototype.getAddress = function getAddress() {
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

/**
 * Convert the wallet to a more inspection-friendly object.
 * @returns {Object}
 */

Wallet.prototype.inspect = function inspect() {
  return {
    id: this.id,
    type: this.type,
    network: this.network.type,
    m: this.m,
    n: this.n,
    keyAddress: this.initialized
      ? this.keyAddress
      : null,
    scriptAddress: this.initialized
      ? this.scriptAddress
      : null,
    programAddress: this.initialized
      ? this.programAddress
      : null,
    witness: this.witness,
    derivation: this.derivation,
    copayBIP45: this.copayBIP45,
    accountIndex: this.accountIndex,
    receiveDepth: this.receiveDepth,
    changeDepth: this.changeDepth,
    master: this.master.toJSON(),
    accountKey: this.accountKey.xpubkey,
    keys: this.keys.map(function(key) {
      return key.xpubkey;
    })
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
    v: 3,
    name: 'wallet',
    network: this.network.type,
    id: this.id,
    type: this.type,
    m: this.m,
    n: this.n,
    witness: this.witness,
    derivation: this.derivation,
    copayBIP45: this.copayBIP45,
    accountIndex: this.accountIndex,
    receiveDepth: this.receiveDepth,
    changeDepth: this.changeDepth,
    master: this.master.toJSON(),
    accountKey: this.accountKey.xpubkey,
    keys: this.keys.map(function(key) {
      return key.xpubkey;
    })
  };
};

Wallet.prototype.toRaw = function toRaw(writer) {
  var p = new BufferWriter(writer);
  var i;

  p.writeU32(this.network.magic);
  p.writeVarString(this.id, 'ascii');
  p.writeU8(this.type === 'pubkeyhash' ? 0 : 1);
  p.writeU8(this.m);
  p.writeU8(this.n);
  p.writeU8(this.witness ? 1 : 0);
  p.writeU8(this.derivation === 'bip44' ? 44 : 45);
  p.writeU8(this.copayBIP45 ? 1 : 0);
  p.writeU32(this.accountIndex);
  p.writeU32(this.receiveDepth);
  p.writeU32(this.changeDepth);
  p.writeVarBytes(this.master.toRaw());
  p.writeBytes(this.accountKey.toRaw()); // 82 bytes
  p.writeVarint(this.keys.length);

  for (i = 0; i < this.keys.length; i++)
    p.writeBytes(this.keys[i].toRaw());

  if (!writer)
    p = p.render();

  return p;
};

Wallet.fromRaw = function fromRaw(data) {
  return new Wallet(Wallet.parseRaw(data));
};

Wallet.parseRaw = function parseRaw(data) {
  var networks = bcoin.protocol.network;
  var p = new BufferReader(data);
  var magic = p.readU32();
  var id = this.readVarString('ascii');
  var type = p.readU8() === 0 ? 'pubkeyhash' : 'multisig';
  var m = p.readU8();
  var n = p.readU8();
  var witness = p.readU8() === 1;
  var derivation = p.readU8() === 44 ? 'bip44' : 'bip45';
  var copayBIP45 = p.readU8() === 1;
  var accountIndex = p.readU32();
  var receiveDepth = p.readU32();
  var changeDepth = p.readU32();
  var master = MasterKey.fromRaw(p.readVarBytes());
  var accountKey = bcoin.hd.PublicKey.fromRaw(p.readBytes(82));
  var count = p.readVarint();
  var keys = [];
  var i, type, network;

  for (i = 0; i < count; i++)
    keys.push(bcoin.hd.PublicKey.fromRaw(p.readBytes(82)));

  for (i = 0; i < networks.types.length; i++) {
    type = networks.types[i];
    if (magic === networks[type].magic) {
      network = type;
      break;
    }
  }

  assert(network, 'Network not found.');

  return {
    network: network,
    id: id,
    type: type,
    m: m,
    n: n,
    witness: witness,
    derivation: derivation,
    copayBIP45: copayBIP45,
    accountIndex: accountIndex,
    receiveDepth: receiveDepth,
    changeDepth: changeDepth,
    master: master,
    accountKey: accountKey,
    keys: keys
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
  assert.equal(json.v, 3);
  assert.equal(json.name, 'wallet');

  return {
    network: json.network,
    id: json.id,
    type: json.type,
    m: json.m,
    n: json.n,
    witness: json.witness,
    derivation: json.derivation,
    copayBIP45: json.copayBIP45,
    accountIndex: json.accountIndex,
    receiveDepth: json.receiveDepth,
    changeDepth: json.changeDepth,
    master: MasterKey.fromJSON(json.master),
    accountKey: bcoin.hd.fromBase58(json.accountKey),
    keys: json.keys.map(function(key) {
      return bcoin.hd.fromBase58(key);
    })
  };
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
    && typeof obj.receiveDepth === 'number'
    && obj.deriveAddress === 'function';
};

function MasterKey(options) {
  this.json = options.json;
  this.key = options.key || null;
}

MasterKey.prototype.decrypt = function decrypt(passphrase) {
  if (this.key)
    return this.key;

  if (!this.json.encrypted)
    return bcoin.hd.fromJSON(this.json);

  return bcoin.hd.fromJSON(this.json, passphrase);
};

MasterKey.prototype.toJSON = function toJSON() {
  return this.json;
};

MasterKey.fromKey = function fromKey(key) {
  return new MasterKey({
    key: key,
    json: key.toJSON()
  });
};

MasterKey.fromJSON = function fromJSON(json) {
  var key;

  if (!json.encrypted)
    key = bcoin.hd.fromJSON(json);

  return new MasterKey({
    key: key,
    json: json
  });
};

MasterKey.isMasterKey = function isMasterKey(obj) {
  return obj
    && obj.json
    && typeof obj.decrypt === 'function';
};

/*
 * Expose
 */

module.exports = Wallet;

/**
 * HD BIP-44/45 wallet
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
 * @param {Boolean?} options.copayBIP45 - Use copay-style BIP45 if bip45
 * derivation is used.
 * @param {Number?} options.lookahead - Amount of lookahead addresses
 * (default=5).
 * @param {String?} options.type - Type of wallet (pubkeyhash, multisig)
 * (default=pubkeyhash).
 * @param {String?} options.derivation - Derivation type (bip44, bip45)
 * (default=bip44).
 * @param {Boolean?} options.compressed - Whether to use compressed
 * public keys (default=true).
 * @param {Number?} options.m - `m` value for multisig.
 * @param {Number?} options.n - `n` value for multisig.
 * @param {String?} options.id - Wallet ID (used for storage)
 * (default=account key "address").
 */

function CWallet(id, db) {
  var i, key;

  if (!(this instanceof CWallet))
    return new CWallet(id, db);

  EventEmitter.call(this);

  this.network = db.network;
  this.db = db;
  this.id = id;
}

utils.inherits(CWallet, EventEmitter);

/**
 * Open the wallet, wait for the database to load.
 * @param {Function} callback
 */

CWallet.prototype.open = function open(callback) {
  var self = this;

  if (this.loaded)
    return utils.nextTick(callback);

  if (this._loading)
    return this.once('open', callback);

  this.db.register(this.id, this);
  callback();
};

/**
 * Close the wallet, wait for the database to close.
 * @method
 * @param {Function} callback
 */

CWallet.prototype.close =
CWallet.prototype.destroy = function destroy(callback) {
  callback = utils.ensure(callback);

  if (!this.db)
    return utils.nextTick(callback);

  this.db.unregister(this.id, this);
  this.db = null;
};

/**
 * Add a public account/purpose key to the wallet for multisig.
 * @param {HDPublicKey|Base58String} key - Account (bip44) or
 * Purpose (bip45) key (can be in base58 form).
 * @throws Error on non-hdkey/non-accountkey.
 */

CWallet.prototype.addKey = function addKey(key, callback) {
  this.db.addKey(this.id, key, callback);
};

/**
 * Remove a public account/purpose key to the wallet for multisig.
 * @param {HDPublicKey|Base58String} key - Account (bip44) or Purpose
 * (bip45) key (can be in base58 form).
 * @throws Error on non-hdkey/non-accountkey.
 */

CWallet.prototype.removeKey = function removeKey(key, callback) {
  this.db.removeKey(this.id, key, callback);
};

/**
 * Get the wallet ID which is either the passed in `id`
 * option, or the account/purpose key converted to an
 * address with a prefix of `0x03be04` (`WLT`).
 * @returns {Base58String}
 */

CWallet.prototype.getID = function getID() {
  return this.id;
};

/**
 * Create a new receiving address (increments receiveDepth).
 * @returns {KeyRing}
 */

CWallet.prototype.createReceive = function createReceive(callback) {
  return this.db.createAddress(this.id, false, callback);
};

/**
 * Create a new change address (increments receiveDepth).
 * @returns {KeyRing}
 */

CWallet.prototype.createChange = function createChange(callback) {
  return this.db.createAddress(this.id, true, callback);
};

/**
 * Create a new address (increments depth).
 * @param {Boolean} change
 * @returns {KeyRing}
 */

CWallet.prototype.createAddress = function createAddress(change, callback) {
  return this.db.createAddress(this.id, change, callback);
};

/**
 * Test whether the wallet posesses an address.
 * @param {Base58Address} address
 * @returns {Boolean}
 */

CWallet.prototype.hasAddress = function hasAddress(address, callback) {
  this.db.hasAddress(this.id, address, callback);
};

/**
 * Fill a transaction with inputs, estimate
 * transaction size, calculate fee, and add a change output.
 * @see MTX#selectCoins
 * @see MTX#fill
 * @param {MTX} tx - _Must_ be a mutable transaction.
 * @param {Object?} options
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

CWallet.prototype.fill = function fill(tx, options, callback) {
  this.db.fill(this.id, tx, options, callback);
};

/**
 * Fill transaction with coins (accesses db).
 * @param {TX} tx
 * @param {Function} callback - Returns [Error, {@link TX}].
 */

CWallet.prototype.fillCoins = function fillCoins(tx, callback) {
  this.db.fillHistory(this.id, tx, callback);
};

/**
 * Get a coin from the wallet (accesses db).
 * @param {Hash} hash
 * @param {Number} index
 * @param {Function} callback - Returns [Error, {@link Coin}].
 */

CWallet.prototype.getCoin = function getCoin(hash, index, callback) {
  this.db.getCoin(hash, index, callback);
};

/**
 * Get a transaction from the wallet (accesses db).
 * @param {Hash} hash
 * @param {Function} callback - Returns [Error, {@link TX}].
 */

CWallet.prototype.getTX = function getTX(hash, callback) {
  this.db.getTX(hash, callback);
};

/**
 * Build a transaction, fill it with outputs and inputs,
 * sort the members according to BIP69, set locktime,
 * and sign it (accesses db).
 * @param {Object} options - See {@link CWallet#fill options}.
 * @param {Object[]} outputs - See {@link Script.createOutputScript}.
 * @param {Function} callback - Returns [Error, {@link MTX}].
 */

CWallet.prototype.createTX = function createTX(options, outputs, callback) {
  this.db.createTX(this.id, options, outputs, callback);
};

/**
 * Get path by address.
 * @param {Base58Address} address - Base58 address.
 */

CWallet.prototype.getPath = function getPath(address, callback) {
  if (!address || typeof address !== 'string')
    return callback();
  this.db.getPath(this.id, address, callback);
};

/**
 * Get a redeem script or witness script by hash.
 * @param {Hash} hash - Can be a ripemd160 or a sha256.
 * @returns {Script}
 */

CWallet.prototype.getRedeem = function getRedeem(hash, callback) {
  ;
};

/**
 * Zap stale TXs from wallet (accesses db).
 * @param {Number} now - Current time (unix time).
 * @param {Number} age - Age threshold (unix time, default=72 hours).
 * @param {Function} callback - Returns [Error].
 */

CWallet.prototype.zap = function zap(now, age, callback) {
  return this.db.zapWallet(this.id, now, age, callback);
};

/**
 * Build input scripts templates for a transaction (does not
 * sign, only creates signature slots). Only builds scripts
 * for inputs that are redeemable by this wallet.
 * @param {MTX} tx
 * @param {Number?} index - Index of input. If not present,
 * it will attempt to sign all redeemable inputs.
 * @returns {Number} Total number of scripts built.
 */

CWallet.prototype.scriptInputs = function scriptInputs(tx, callback) {
  this.db.scriptInputs(this.id, tx, callback);
};

/**
 * Build input scripts and sign inputs for a transaction. Only attempts
 * to build/sign inputs that are redeemable by this wallet.
 * @param {MTX} tx
 * @param {Number?} index - Index of input. If not present,
 * it will attempt to build and sign all redeemable inputs.
 * @param {SighashType?} type
 * @returns {Number} Total number of inputs scripts built and signed.
 */

CWallet.prototype.sign = function sign(tx, options, callback) {
  this.db.sign(this.id, tx, options, callback);
};

/**
 * Add a transaction to the wallets TX history (accesses db).
 * @param {TX} tx
 * @param {Function} callback
 */

CWallet.prototype.addTX = function addTX(tx, callback) {
  return this.db.addTX(tx, callback);
};

/**
 * Get all transactions in transaction history (accesses db).
 * @param {Function} callback - Returns [Error, {@link TX}[]].
 */

CWallet.prototype.getHistory = function getHistory(callback) {
  return this.db.getHistory(this.id, callback);
};

/**
 * Get all available coins (accesses db).
 * @param {Function} callback - Returns [Error, {@link Coin}[]].
 */

CWallet.prototype.getCoins = function getCoins(callback) {
  return this.db.getCoins(this.id, callback);
};

/**
 * Get all pending/unconfirmed transactions (accesses db).
 * @param {Function} callback - Returns [Error, {@link TX}[]].
 */

CWallet.prototype.getUnconfirmed = function getUnconfirmed(callback) {
  return this.db.getUnconfirmed(this.id, callback);
};

/**
 * Get wallet balance (accesses db).
 * @param {Function} callback - Returns [Error, {@link Balance}].
 */

CWallet.prototype.getBalance = function getBalance(callback) {
  return this.db.getBalance(this.id, callback);
};

/**
 * Get last timestamp and height this wallet was active
 * at (accesses db). Useful for resetting the chain
 * to a certain height when in SPV mode.
 * @param {Function} callback - Returns [Error, Number(ts), Number(height)].
 */

CWallet.prototype.getLastTime = function getLastTime(callback) {
  return this.db.getLastTime(this.id, callback);
};

/**
 * Get the last N transactions (accesses db).
 * @param {Number} limit
 * @param {Function} callback - Returns [Error, {@link TX}[]].
 */

CWallet.prototype.getLast = function getLast(limit, callback) {
  return this.db.getLast(this.id, limit, callback);
};

/**
 * Get a range of transactions between two timestamps (accesses db).
 * @param {Object} options
 * @param {Number} options.start
 * @param {Number} options.end
 * @param {Function} callback - Returns [Error, {@link TX}[]].
 */

CWallet.prototype.getTimeRange = function getTimeRange(options, callback) {
  return this.db.getTimeRange(this.id, options, callback);
};

CWallet.prototype.getReceiveAddress = function getReceiveAddress(callback) {
  return this.db.getReceiveAddress(this.id, callback);
};

CWallet.prototype.getInfo = function getInfo(callback) {
  return this.db.get(this.id, function(err, cwallet, wallet) {
    if (err)
      return callback(err);
    return callback(null, wallet);
  });
};

/**
 * Convert the wallet to a more inspection-friendly object.
 * @returns {Object}
 */

CWallet.prototype.inspect = function inspect() {
  return '<CWallet id=' + this.id + '>';
};

/**
 * Test an object to see if it is a CWallet.
 * @param {Object} obj
 * @returns {Boolean}
 */

CWallet.isCWallet = function isCWallet(obj) {
  return obj
    && obj.db
    && obj.id
    && obj.getInfo === 'function';
};

/*
 * Expose
 */

module.exports = Wallet;
bcoin.cwallet = CWallet;
module.exports.CWallet = CWallet;
