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
 * @param {Provider?} options.provider - Wallet Provider. If not
 * present, no coins will be available.
 * @param {(HDPrivateKey|HDPublicKey)?} options.master - Master HD key. If not
 * present, it will be generated.
 * @param {Object?} options.addressMap - Map of addresses to paths (internal).
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
  var i;

  if (!(this instanceof Wallet))
    return new Wallet(options);

  EventEmitter.call(this);

  if (!options)
    options = {};

  options = utils.merge({}, options);

  this.options = options;
  this.network = bcoin.network.get(options.network);

  if (typeof options.master === 'string')
    options.master = { xkey: options.master };

  if (options.master
      && typeof options.master === 'object'
      && !(options.master instanceof bcoin.hd)) {
    options.master = bcoin.hd.fromAny(options.master, this.network);
  }

  if (!options.master)
    options.master = bcoin.hd.fromSeed(null, this.network);

  this.provider = options.provider || null;
  this.master = options.master || null;
  this.addressMap = options.addressMap || {};
  this.witness = options.witness || false;
  this.loaded = false;

  this.accountIndex = options.accountIndex || 0;
  this.receiveDepth = options.receiveDepth || 1;
  this.changeDepth = options.changeDepth || 1;
  this.copayBIP45 = options.copayBIP45 || false;
  this.lookahead = options.lookahead != null ? options.lookahead : 5;
  this.cosignerIndex = -1;

  this.type = options.type || 'pubkeyhash';
  this.derivation = options.derivation || 'bip44';
  this.compressed = options.compressed !== false;
  this.keys = [];
  this.m = options.m || 1;
  this.n = options.n || 1;

  this.cache = new bcoin.lru(20);

  if (this.n > 1)
    this.type = 'multisig';

  assert(this.type === 'pubkeyhash' || this.type === 'multisig',
    '`type` must be multisig or pubkeyhash.');

  if (this.m < 1 || this.m > this.n)
    throw new Error('m ranges between 1 and n');

  if (this.derivation === 'bip45') {
    this.accountKey = this.master.isPurpose45()
      ? this.master
      : this.master.derivePurpose45();
  } else if (this.derivation === 'bip44') {
    this.accountKey = this.master.isAccount44()
      ? this.master
      : this.master.deriveAccount44(this.accountIndex);
  }

  this.id = this.getID();

  // Non-alphanumeric IDs will break leveldb sorting.
  assert(/^[a-zA-Z0-9]+$/.test(this.id), 'Wallet IDs must be alphanumeric.');

  this.addKey(this.accountKey);

  if (options.keys) {
    for (i = 0; i < options.keys.length; i++)
      this.addKey(options.keys[i]);
  }
}

utils.inherits(Wallet, EventEmitter);

Wallet.prototype._init = function _init() {
  var self = this;
  var i;

  assert(!this._initialized);
  this._initialized = true;

  if (Object.keys(this.addressMap).length === 0) {
    for (i = 0; i < this.receiveDepth - 1; i++)
      this.deriveReceive(i);

    for (i = 0; i < this.changeDepth - 1; i++)
      this.deriveChange(i);

    for (i = this.receiveDepth; i < this.receiveDepth + this.lookahead; i++)
      this.deriveReceive(i);

    for (i = this.changeDepth; i < this.changeDepth + this.lookahead; i++)
      this.deriveChange(i);
  }

  this.receiveAddress = this.deriveReceive(this.receiveDepth - 1);
  this.changeAddress = this.deriveChange(this.changeDepth - 1);

  assert(this.receiveAddress);
  assert(!this.receiveAddress.change);
  assert(this.changeAddress.change);

  if (!this.provider)
    return;

  this.provider.setID(this.id);

  this.on('error', function(err) {
    bcoin.debug('Wallet Error: %s', err.message);
  });

  this.provider.on('error', function(err) {
    self.emit('error', err);
  });

  this.provider.on('tx', function(tx) {
    self.emit('tx', tx);
  });

  this.provider.on('updated', function(tx) {
    self.emit('updated', tx);
  });

  this.provider.on('balance', function(balance) {
    self.emit('balance', balance);
  });

  this.provider.on('confirmed', function(tx) {
    self.syncOutputDepth(tx);
    self.emit('confirmed', tx);
  });

  this.provider.on('unconfirmed', function(tx) {
    self.emit('unconfirmed', tx);
  });

  this.provider.open(function(err) {
    if (err)
      return self.emit('error', err);

    self.loaded = true;
    self.emit('open');
  });
};

/**
 * Open the wallet, wait for the database to load.
 * @param {Function} callback
 */

Wallet.prototype.open = function open(callback) {
  if (this.loaded)
    return utils.nextTick(callback);

  this.once('open', callback);
};

/**
 * Close the wallet, wait for the database to close.
 * @method
 * @param {Function} callback
 */

Wallet.prototype.close =
Wallet.prototype.destroy = function destroy(callback) {
  callback = utils.ensure(callback);

  if (!this.provider)
    return utils.nextTick(callback);

  this.provider.destroy(callback);
  this.provider = null;
};

/**
 * Add a public account/purpose key to the wallet for multisig.
 * @param {HDPublicKey|Base58String} key - Account (bip44) or
 * Purpose (bip45) key (can be in base58 form).
 * @throws Error on non-hdkey/non-accountkey.
 */

Wallet.prototype.addKey = function addKey(key) {
  var index, i;

  assert(key, 'Key required.');

  if (key instanceof bcoin.wallet) {
    assert(key.derivation === this.derivation);
    key = key.accountKey;
  }

  if (bcoin.hd.isExtended(key))
    key = bcoin.hd.fromBase58(key);

  if (key.hdPublicKey)
    key = key.hdPublicKey;

  assert(key instanceof bcoin.hd, 'Must add HD keys to wallet.');

  if (this.derivation === 'bip44') {
    if (!key || !key.isAccount44())
      throw new Error('Must add HD account keys to BIP44 wallet.');
  } else if (this.derivation === 'bip45') {
    if (!key || !key.isPurpose45())
      throw new Error('Must add HD purpose keys to BIP45 wallet.');
  }

  for (i = 0; i < this.keys.length; i++) {
    if (this.keys[i].xpubkey === key.xpubkey) {
      index = i;
      break;
    }
  }

  if (index != null)
    return;

  assert(!this._keysFinalized);

  this.keys.push(key);

  if (this.keys.length === this.n)
    this._finalizeKeys();
};

/**
 * Remove a public account/purpose key to the wallet for multisig.
 * @param {HDPublicKey|Base58String} key - Account (bip44) or Purpose
 * (bip45) key (can be in base58 form).
 * @throws Error on non-hdkey/non-accountkey.
 */

Wallet.prototype.removeKey = function removeKey(key) {
  var index, i;

  assert(!this._keysFinalized);

  assert(key, 'Key required.');

  if (key instanceof bcoin.wallet) {
    assert(key.derivation === this.derivation);
    key = key.accountKey;
  }

  if (bcoin.hd.isExtended(key))
    key = bcoin.hd.fromBase58(key);

  if (key.hdPublicKey)
    key = key.hdPublicKey;

  assert(key instanceof bcoin.hd, 'Must add HD keys to wallet.');

  if (this.derivation === 'bip44') {
    if (!key || !key.isAccount44())
      throw new Error('Must add HD account keys to BIP44 wallet.');
  } else if (this.derivation === 'bip45') {
    if (!key || !key.isPurpose45())
      throw new Error('Must add HD purpose keys to BIP45 wallet.');
  }

  for (i = 0; i < this.keys.length; i++) {
    if (this.keys[i].xpubkey === key.xpubkey) {
      index = i;
      break;
    }
  }

  if (index == null)
    return;

  this.keys.splice(index, 1);
};

Wallet.prototype._finalizeKeys = function _finalizeKeys() {
  var i;

  assert(!this._keysFinalized);
  this._keysFinalized = true;

  this.keys = utils.sortHDKeys(this.keys);

  for (i = 0; i < this.keys.length; i++) {
    if (this.keys[i].xpubkey === this.accountKey.xpubkey) {
      this.cosignerIndex = i;
      break;
    }
  }

  assert(this.cosignerIndex !== -1);

  this._init();
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

  if (this.options.id)
    return this.options.id;

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
 * @returns {Address}
 */

Wallet.prototype.createReceive = function createReceive() {
  return this.createAddress(false);
};

/**
 * Create a new change address (increments receiveDepth).
 * @returns {Address}
 */

Wallet.prototype.createChange = function createChange() {
  return this.createAddress(true);
};

/**
 * Create a new address (increments depth).
 * @param {Boolean} change
 * @returns {Address}
 */

Wallet.prototype.createAddress = function createAddress(change) {
  var address;

  if (typeof change === 'string')
    change = this.parsePath(change).change;

  if (change) {
    address = this.deriveChange(this.changeDepth);
    this.deriveChange(this.changeDepth + this.lookahead);
    this.changeDepth++;
    this.changeAddress = address;
  } else {
    address = this.deriveReceive(this.receiveDepth);
    this.deriveReceive(this.receiveDepth + this.lookahead);
    this.receiveDepth++;
    this.receiveAddress = address;
  }

  if (this.provider && this.provider.sync) {
    assert(!this.provider.update);
    this.provider.sync(this, address);
  }

  return address;
};

/**
 * Derive a receiving address at `index`. Do not increment depth.
 * @param {Number} index
 * @returns {Address}
 */

Wallet.prototype.deriveReceive = function deriveReceive(index) {
  if (typeof index === 'string')
    index = this.parsePath(index).index;

  return this.deriveAddress(false, index);
};

/**
 * Derive a change address at `index`. Do not increment depth.
 * @param {Number} index
 * @returns {Address}
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
 * @returns {Address}
 */

Wallet.prototype.deriveAddress = function deriveAddress(change, index) {
  var path, data, key, options, address;

  assert(this._initialized);

  if (typeof change === 'string')
    path = change;

  if (path) {
    // Map address to path
    if (path.indexOf('/') === -1) {
      path = this.addressMap[path];
      if (!path)
        return;
    }
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
    key: key,
    change: data.change,
    index: data.index,
    path: data.path,
    type: this.type,
    witness: this.witness,
    m: this.m,
    n: this.n,
    keys: [],
    derived: true
  };

  this.keys.forEach(function(key, cosignerIndex) {
    var path = this.createPath(cosignerIndex, data.change, data.index);
    key = key.derive(path);
    options.keys.push(key.publicKey);
  }, this);

  address = new bcoin.address(options);

  this.addressMap[address.getKeyHash('hex')] = data.path;

  if (this.type === 'multisig')
    this.addressMap[address.getScriptHash('hex')] = data.path;

  if (this.witness)
    this.addressMap[address.getProgramHash('hex')] = data.path;

  // Update the DB with the new address.
  if (this.provider && this.provider.update)
    this.provider.update(this, address);

  this.emit('add address', address);

  this.cache.set(data.path, address);

  return address;
};

/**
 * Test whether the wallet posesses an address.
 * @param {Base58Address} address
 * @returns {Boolean}
 */

Wallet.prototype.hasAddress = function hasAddress(address) {
  return this.addressMap[address] != null;
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

Wallet.prototype.setReceiveDepth = function setReceiveDepth(depth) {
  var i;

  if (!(depth > this.receiveDepth))
    return false;

  for (i = this.receiveDepth; i < depth; i++)
    this.receiveAddress = this.deriveReceive(i);

  for (i = this.receiveDepth + this.lookahead; i < depth + this.lookahead; i++)
    this.deriveReceive(i);

  this.receiveDepth = depth;

  return true;
};

/**
 * Set change depth (depth is the index of the _next_ address).
 * Allocate all addresses up to depth. Note that this also allocates
 * new lookahead addresses.
 * @param {Number} depth
 * @returns {Boolean} True if new addresses were allocated.
 */

Wallet.prototype.setChangeDepth = function setChangeDepth(depth) {
  var i;

  if (!(depth > this.changeDepth))
    return false;

  for (i = this.changeDepth; i < depth; i++)
    this.changeAddress = this.deriveChange(i);

  for (i = this.changeDepth + this.lookahead; i < depth + this.lookahead; i++)
    this.deriveChange(i);

  this.changeDepth = depth;

  return true;
};

/**
 * Check whether transaction input belongs to this wallet.
 * @param {TX|Output} tx - Transaction or Output.
 * @param {Number?} index - Output index.
 * @returns {Boolean}
 */

Wallet.prototype.ownInput = function ownInput(tx, index) {
  if (tx instanceof bcoin.input)
    return tx.test(this.addressMap);

  return tx.testInputs(this.addressMap, index);
};

/**
 * Check whether transaction output belongs to this wallet.
 * @param {TX|Output} tx - Transaction or Output.
 * @param {Number?} index - Output index.
 * @returns {Boolean}
 */

Wallet.prototype.ownOutput = function ownOutput(tx, index) {
  if (tx instanceof bcoin.output)
    return tx.test(this.addressMap);

  return tx.testOutputs(this.addressMap, index);
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
 * @param {Boolean} options.accurate - Whether to use "accurate"
 * fee calculatation rather than rounding to the nearest kilobyte.
 * See {@link TX#getMinFee} vs. {@link TX#getMaxFee}.
 * @param {Boolean} options.confirmed - Select only confirmed coins.
 * @param {Boolean} options.free - Do not apply a fee if the
 * transaction priority is high enough to be considered free.
 * @param {BN?} options.fee - Use a hard fee rather than calculating one.
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

  assert(this._initialized);

  this.getCoins(function(err, coins) {
    if (err)
      return callback(err);

    try {
      tx.fill(coins, {
        selection: options.selection || 'age',
        accurate: options.accurate,
        confirmed: options.confirmed,
        free: options.free,
        fee: options.fee,
        subtractFee: options.subtractFee,
        changeAddress: self.changeAddress.getAddress(),
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
 * Fill transaction with coins (accesses provider).
 * @param {TX} tx
 * @param {Function} callback - Returns [Error, {@link TX}].
 */

Wallet.prototype.fillCoins = function fillCoins(tx, callback) {
  if (!this.provider)
    return callback(new Error('No wallet provider available.'));

  return this.provider.fillHistory(tx, callback);
};

/**
 * Get a coin from the wallet (accesses provider).
 * @param {Hash} hash
 * @param {Number} index
 * @param {Function} callback - Returns [Error, {@link Coin}].
 */

Wallet.prototype.getCoin = function getCoin(hash, index, callback) {
  if (!this.provider)
    return callback(new Error('No wallet provider available.'));

  return this.provider.getCoin(hash, index, callback);
};

/**
 * Get a transaction from the wallet (accesses provider).
 * @param {Hash} hash
 * @param {Function} callback - Returns [Error, {@link TX}].
 */

Wallet.prototype.getTX = function getTX(hash, callback) {
  if (!this.provider)
    return callback(new Error('No wallet provider available.'));

  return this.provider.getTX(hash, callback);
};

/**
 * Build a transaction, fill it with outputs and inputs,
 * sort the members according to BIP69, set locktime,
 * and sign it (accesses provider).
 * @param {Object} options - See {@link Wallet#fill options}.
 * @param {Object[]} outputs - See {@link Script.createOutputScript}.
 * @param {Function} callback - Returns [Error, {@link MTX}].
 */

Wallet.prototype.createTX = function createTX(options, outputs, callback) {
  var self = this;
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

  // Create mutable tx
  tx = bcoin.mtx();

  // Add the outputs
  for (i = 0; i < outputs.length; i++) {
    try {
      tx.addOutput(outputs[i]);
    } catch (e) {
      return utils.asyncify(callback)(e);
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
    //   tx.avoidFeeSniping();

    // Sign the transaction
    if (!self.sign(tx))
      return callback(new Error('Could not sign transaction.'));

    return callback(null, tx);
  });
};

/**
 * Derive an address for a single transaction input.
 * @param {TX} tx
 * @param {Number} index
 * @returns {Address}
 */

Wallet.prototype.deriveInput = function deriveInput(tx, index) {
  return this.deriveInputs(tx, index)[0];
};

/**
 * Derive necessary addresses for signing a transaction.
 * @param {TX|Input} tx
 * @param {Number?} index - Input index.
 * @returns {Address[]}
 */

Wallet.prototype.deriveInputs = function deriveInputs(tx, index) {
  var paths = this.getInputPaths(tx, index);
  var addresses = [];
  var i;

  for (i = 0; i < paths.length; i++)
    addresses.push(this.deriveAddress(paths[i]));

  return addresses;
};

/**
 * Get path by address.
 * @param {Base58Address} address - Base58 address.
 */

Wallet.prototype.getPath = function getPath(address) {
  if (!address || typeof address !== 'string')
    return;
  return this.addressMap[address];
};

/**
 * Map input addresses to paths.
 * @param {TX|Input} tx
 * @param {Number?} index
 * @returns {String[]}
 */

Wallet.prototype.getInputPaths = function getInputPaths(tx, index) {
  var paths = [];
  var i, input, address, path;

  if (tx instanceof bcoin.input) {
    path = this.getPath(tx.coin.getHash());
    if (path)
      paths.push(path);
    return paths;
  }

  for (i = 0; i < tx.inputs.length; i++) {
    input = tx.inputs[i];

    if (index != null && i !== index)
      continue;

    assert(input.coin, 'Not all coins available.');

    address = input.coin.getHash();
    path = this.getPath(address);

    if (!path)
      continue;

    paths.push(path);
  }

  return utils.uniq(paths);
};

/**
 * Map output addresses to paths.
 * @param {TX|Output}
 * @param {Number?} index
 * @returns {String[]}
 */

Wallet.prototype.getOutputPaths = function getOutputPaths(tx, index) {
  var paths = [];
  var i, output, address, path;

  if (tx instanceof bcoin.output) {
    path = this.getPath(tx.getHash());
    if (path)
      paths.push(path);
    return paths;
  }

  for (i = 0; i < tx.outputs.length; i++) {
    output = tx.outputs[i];

    if (index != null && i !== index)
      continue;

    address = output.getHash();
    path = this.getPath(address);

    if (!path)
      continue;

    paths.push(path);
  }

  return utils.uniq(paths);
};

/**
 * Get the maximum address depth based on a transactions outputs.
 * @param {TX} tx
 * @returns {Object} { changeDepth: Number, receiveDepth: Number }
 */

Wallet.prototype.getOutputDepth = function getOutputDepth(tx) {
  var paths = this.getOutputPaths(tx);
  var depth = { changeDepth: -1, receiveDepth: -1 };
  var i, path;

  for (i = 0; i < paths.length; i++) {
    path = this.parsePath(paths[i]);
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

  return depth;
};

/**
 * Sync address depths based on a transaction's outputs.
 * This is used for deriving new addresses when
 * a confirmed transaction is seen.
 * @param {TX} tx
 * @returns {Boolean} Whether new addresses were allocated.
 */

Wallet.prototype.syncOutputDepth = function syncOutputDepth(tx) {
  var depth = this.getOutputDepth(tx);
  var res = false;

  if (this.setChangeDepth(depth.changeDepth + 1))
    res = true;

  if (this.setReceiveDepth(depth.receiveDepth + 1))
    res = true;

  return res;
};

/**
 * Get a redeem script or witness script by hash.
 * @param {Hash} hash - Can be a ripemd160 or a sha256.
 * @param {Number} prefix - See {@link network.address.prefixes}.
 * @returns {Script}
 */

Wallet.prototype.getRedeem = function getRedeem(hash, prefix) {
  var addr, address;

  if (typeof hash === 'string')
    hash = new Buffer(hash, 'hex');

  address = this.deriveAddress(hash.toString('hex'));

  if (!address)
    return;

  if (address.program && hash.length === 20) {
    if (utils.equal(hash, address.programHash))
      return address.program;
  }

  return address.script;
};

/**
 * Zap stale TXs from wallet (accesses provider).
 * @param {Number} now - Current time (unix time).
 * @param {Number} age - Age threshold (unix time, default=72 hours).
 * @param {Function} callback - Returns [Error].
 */

Wallet.prototype.zap = function zap(now, age, callback) {
  if (!this.provider.zap) {
    return utils.asyncify(callback)(
      new Error('Provider does not support zapping.'));
  }
  return this.provider.zap(now, age, callback);
};

/**
 * Scan for addresses.
 * @param {Function} getByAddress - Must be a callback which accepts
 * a callback and returns transactions by address.
 * @param {Function} callback - Returns [Boolean, TX[]].
 */

Wallet.prototype.scan = function scan(getByAddress, callback) {
  var self = this;
  var res = false;
  var i;

  return this._scan({}, getByAddress, function(err, depth, txs) {
    if (err)
      return callback(err);

    if (self.setChangeDepth(depth.changeDepth + 1))
      res = true;

    if (self.setReceiveDepth(depth.receiveDepth + 1))
      res = true;

    if (self.provider && self.provider.addTX) {
      utils.forEachSerial(txs, function(tx, next) {
        self.addTX(tx, next);
      }, function(err) {
        if (err)
          return callback(err);
        return callback(null, res, txs);
      });
      return;
    }

    return callback(null, res, txs);
  });
};

/**
 * Clone the wallet (used for scanning).
 * @returns {Wallet}
 */

Wallet.prototype.clone = function clone() {
  var passphrase = this.options.passphrase;
  var wallet;

  delete this.options.passphrase;

  wallet = Wallet.fromJSON(this.toJSON());

  this.options.passphrase = passphrase;

  return wallet;
};

Wallet.prototype._scan = function _scan(options, getByAddress, callback) {
  var depth = { changeDepth: 0, receiveDepth: 0 };
  var wallet = this.clone();
  var all = [];

  assert(this._initialized);

  (function chainCheck(change) {
    var addressIndex = 0;
    var total = 0;
    var gap = 0;

    (function next() {
      var address = wallet.deriveAddress(change, addressIndex++);

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

Wallet.prototype.scriptInputs = function scriptInputs(tx, index) {
  var addresses = this.deriveInputs(tx, index);
  var total = 0;
  var i;

  for (i = 0; i < addresses.length; i++)
    total += addresses[i].scriptInputs(tx, index);

  return total;
};

/**
 * Sign inputs for a transaction. Only attempts to sign inputs
 * that are redeemable by this wallet.
 * @param {MTX} tx
 * @param {Number?} index - Index of input. If not present,
 * it will attempt to sign all redeemable inputs.
 * @param {SighashType?} type
 * @returns {Number} Total number of inputs signed.
 */

Wallet.prototype.signInputs = function signInputs(tx, index, type) {
  var addresses = this.deriveInputs(tx, index);
  var total = 0;
  var i;

  for (i = 0; i < addresses.length; i++)
    total += addresses[i].signInputs(tx, index, type);

  return total;
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

Wallet.prototype.sign = function sign(tx, index, type) {
  var addresses = this.deriveInputs(tx, index);
  var total = 0;
  var i;

  for (i = 0; i < addresses.length; i++)
    total += addresses[i].sign(tx, index, type);

  return total;
};

/**
 * Add a transaction to the wallets TX history (accesses provider).
 * @param {TX} tx
 * @param {Function} callback
 */

Wallet.prototype.addTX = function addTX(tx, callback) {
  if (!this.provider || !this.provider.addTX)
    return utils.asyncify(callback)(new Error('No transaction pool available.'));

  return this.provider.addTX(tx, callback);
};

/**
 * Get all transactions in transaction history (accesses provider).
 * @param {Function} callback - Returns [Error, {@link TX}[]].
 */

Wallet.prototype.getHistory = function getHistory(callback) {
  if (!this.provider)
    return utils.asyncify(callback)(new Error('No wallet provider available.'));

  return this.provider.getHistory(callback);
};

/**
 * Get all available coins (accesses provider).
 * @param {Function} callback - Returns [Error, {@link Coin}[]].
 */

Wallet.prototype.getCoins = function getCoins(callback) {
  if (!this.provider)
    return utils.asyncify(callback)(new Error('No wallet provider available.'));

  return this.provider.getCoins(callback);
};

/**
 * Get all pending/unconfirmed transactions (accesses provider).
 * @param {Function} callback - Returns [Error, {@link TX}[]].
 */

Wallet.prototype.getUnconfirmed = function getUnconfirmed(callback) {
  if (!this.provider)
    return utils.asyncify(callback)(new Error('No wallet provider available.'));

  return this.provider.getUnconfirmed(callback);
};

/**
 * Get wallet balance (accesses provider).
 * @param {Function} callback - Returns [Error, {@link Balance}].
 */

Wallet.prototype.getBalance = function getBalance(callback) {
  if (!this.provider)
    return utils.asyncify(callback)(new Error('No wallet provider available.'));

  return this.provider.getBalance(callback);
};

/**
 * Get last timestamp and height this wallet was active
 * at (accesses provider). Useful for resetting the chain
 * to a certain height when in SPV mode.
 * @param {Function} callback - Returns [Error, Number(ts), Number(height)].
 */

Wallet.prototype.getLastTime = function getLastTime(callback) {
  if (!this.provider)
    return utils.asyncify(callback)(new Error('No wallet provider available.'));

  return this.provider.getLastTime(callback);
};

/**
 * Get the last N transactions (accesses provider).
 * @param {Number} limit
 * @param {Function} callback - Returns [Error, {@link TX}[]].
 */

Wallet.prototype.getLast = function getLast(limit, callback) {
  if (!this.provider)
    return utils.asyncify(callback)(new Error('No wallet provider available.'));

  return this.provider.getLast(limit, callback);
};

/**
 * Get a range of transactions between two timestamps (accesses provider).
 * @param {Object} options
 * @param {Number} options.start
 * @param {Number} options.end
 * @param {Function} callback - Returns [Error, {@link TX}[]].
 */

Wallet.prototype.getTimeRange = function getTimeRange(options, callback) {
  if (!this.provider)
    return utils.asyncify(callback)(new Error('No wallet provider available.'));

  return this.provider.getTimeRange(options, callback);
};

/**
 * Get private key for current receiving address.
 * @param {String?} enc - `"hex"` or `null`.
 * @returns {Buffer}
 */

Wallet.prototype.getPrivateKey = function getPrivateKey(enc) {
  return this.receiveAddress.getPrivateKey(enc);
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

Wallet.prototype.__defineGetter__('privateKey', function() {
  return this.getPrivateKey();
});

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
    keyAddress: this._initialized
      ? this.keyAddress
      : null,
    scriptAddress: this._initialized
      ? this.scriptAddress
      : null,
    programAddress: this._initialized
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
    addressMap: this.addressMap,
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
    master: this.master.toJSON(this.options.passphrase),
    accountKey: this.accountKey.xpubkey,
    addressMap: this.addressMap,
    keys: this.keys.map(function(key) {
      return key.xpubkey;
    })
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

Wallet.parseJSON = function parseJSON(json, passphrase) {
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
    master: bcoin.hd.fromJSON(json.master, passphrase),
    addressMap: json.addressMap,
    keys: json.keys,
    passphrase: passphrase
  };
};

/**
 * Instantiate a Wallet from a
 * jsonified wallet object.
 * @param {Object} json - The jsonified wallet object.
 * @param {String?} passphrase
 * @returns {Wallet}
 */

Wallet.fromJSON = function fromJSON(json, passphrase) {
  return new Wallet(Wallet.parseJSON(json, passphrase));
};

Wallet._syncDepth = function _syncDepth(json, options) {
  var master, wallet;
  var res = false;

  assert.equal(json.v, 3);
  assert.equal(json.name, 'wallet');

  master = json.master;
  json.master = json.accountKey;
  wallet = new Wallet(json);

  if (!wallet._initialized)
    return;

  if (options.tx != null) {
    if (wallet.syncOutputDepth(options.tx))
      res = true;
  }

  if (options.receiveDepth != null) {
    if (wallet.setReceiveDepth(options.receiveDepth))
      res = true;
  }

  if (options.changeDepth != null) {
    if (wallet.setChangeDepth(options.changeDepth))
      res = true;
  }

  if (!res)
    return;

  wallet = wallet.toJSON();
  wallet.master = master;

  return wallet;
};

/**
 * Sync output depth of a jsonified wallet object.
 * Useful for increasing depth without decrypting
 * the key and instantiating the wallet.
 * @param {json}
 * @param {TX} tx
 * @returns {json}
 */

Wallet.syncOutputDepth = function syncOutputDepth(json, tx) {
  return Wallet._syncDepth(json, { tx: tx });
};

/**
 * Increase receive depth of a jsonified wallet object.
 * Useful for increasing depth without decrypting
 * the key and instantiating the wallet.
 * @param {json}
 * @param {Number} receiveDepth
 * @returns {json}
 */

Wallet.setReceiveDepth = function setReceiveDepth(json, receiveDepth) {
  return Wallet._syncDepth(json, {
    receiveDepth: receiveDepth || 0
  });
};

/**
 * Increase change depth of a jsonified wallet object.
 * Useful for increasing depth without decrypting
 * the key and instantiating the wallet.
 * @param {json}
 * @param {Number} changeDepth
 * @returns {json}
 */

Wallet.setChangeDepth = function setChangeDepth(json, changeDepth) {
  return Wallet._syncDepth(json, {
    changeDepth: changeDepth || 0
  });
};

/**
 * Increase depths of a jsonified wallet object.
 * Useful for increasing depth without decrypting
 * the key and instantiating the wallet.
 * @param {json}
 * @param {Number} receiveDepth
 * @param {Number} changeDepth
 * @returns {json}
 */

Wallet.setDepth = function setDepth(json, receiveDepth, changeDepth) {
  return Wallet._syncDepth(json, {
    receiveDepth: receiveDepth || 0,
    changeDepth: changeDepth || 0
  });
};

Wallet._addKey = function _addKey(json, keys, remove) {
  var master, wallet;

  assert.equal(json.v, 3);
  assert.equal(json.name, 'wallet');

  if (!Array.isArray(keys))
    keys = [keys];

  master = json.master;
  json.master = json.accountKey;
  wallet = new Wallet(json);
  keys.forEach(function(key) {
    if (remove)
      wallet.removeKey(key);
    else
      wallet.addKey(key);
  });
  wallet = wallet.toJSON();
  wallet.master = master;

  return wallet;
};

/**
 * Add keys to a jsonified wallet object.
 * Useful for managing keys without decrypting
 * the key and instantiating the wallet.
 * @param {json}
 * @param {Buffer[]|Base58String[]} keys
 * @returns {json}
 */

Wallet.addKey = function addKey(json, keys) {
  return Wallet._addKey(json, keys, false);
};

/**
 * Remove keys from a jsonified wallet object.
 * Useful for managing keys without decrypting
 * the key and instantiating the wallet.
 * @param {json}
 * @param {Buffer[]|Base58String[]} keys
 * @returns {json}
 */

Wallet.removeKey = function removeKey(json, keys) {
  return Wallet._addKey(json, keys, true);
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

module.exports = Wallet;
