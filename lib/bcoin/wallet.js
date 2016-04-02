/**
 * wallet.js - wallet object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

var bcoin = require('../bcoin');
var EventEmitter = require('events').EventEmitter;
var utils = require('./utils');
var assert = utils.assert;
var constants = bcoin.protocol.constants;
var network = bcoin.protocol.network;

/**
 * Wallet
 */

function Wallet(options) {
  if (!(this instanceof Wallet))
    return new Wallet(options);

  EventEmitter.call(this);

  if (!options)
    options = {};

  options = utils.merge({}, options);

  if (typeof options.master === 'string')
    options.master = { xkey: options.master };

  if (options.master
      && typeof options.master === 'object'
      && !(options.master instanceof bcoin.hd)) {
    options.master = bcoin.hd(options.master);
  }

  if (!options.master)
    options.master = bcoin.hd.fromSeed();

  this.options = options;
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

  assert(this.type === 'pubkeyhash' || this.type === 'multisig');

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
  if (!/^[a-zA-Z0-9]+$/.test(this.id))
    throw new Error('Wallet IDs must be alphanumeric.');

  this.addKey(this.accountKey);

  (options.keys || []).forEach(function(key) {
    this.addKey(key);
  }, this);
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

  this.provider.on('error', function(err) {
    utils.debug('Wallet Error: %s', err.message);
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

Wallet.prototype.open = function open(callback) {
  if (this.loaded)
    return utils.nextTick(callback);

  this.once('open', callback);
};

Wallet.prototype.close =
Wallet.prototype.destroy = function destroy(callback) {
  callback = utils.ensure(callback);

  if (!this.provider)
    return utils.nextTick(callback);

  this.provider.destroy(callback);
  this.provider = null;
};

Wallet.prototype.addKey = function addKey(key) {
  var has;

  if (key instanceof bcoin.wallet) {
    assert(key.derivation === this.derivation);
    key = key.accountKey;
  }

  if (bcoin.hd.privateKey.isExtended(key))
    key = bcoin.hd.privateKey(key);
  else if (bcoin.hd.publicKey.isExtended(key))
    key = bcoin.hd.publicKey(key);

  if (key instanceof bcoin.hd.privateKey)
    key = key.hdPublicKey;

  if (this.derivation === 'bip44') {
    if (!key || !key.isAccount44())
      throw new Error('Must add HD account keys to BIP44 wallet.');
  } else if (this.derivation === 'bip45') {
    if (!key || !key.isPurpose45())
      throw new Error('Must add HD purpose keys to BIP45 wallet.');
  }

  has = this.keys.some(function(k) {
    return k.xpubkey === key.xpubkey;
  });

  if (has)
    return;

  assert(!this._keysFinalized);

  this.keys.push(key);

  if (this.keys.length === this.n)
    this._finalizeKeys();
};

Wallet.prototype.removeKey = function removeKey(key) {
  var index;

  assert(!this._keysFinalized);

  if (key instanceof bcoin.wallet) {
    assert(key.derivation === this.derivation);
    key = key.accountKey;
  }

  if (bcoin.hd.privateKey.isExtended(key))
    key = bcoin.hd.privateKey(key);
  else if (bcoin.hd.publicKey.isExtended(key))
    key = bcoin.hd.publicKey(key);

  if (key instanceof bcoin.hd.privateKey)
    key = key.hdPublicKey;

  if (this.derivation === 'bip44') {
    if (!key || !key.isAccount44())
      throw new Error('Must add HD account keys to BIP44 wallet.');
  } else if (this.derivation === 'bip45') {
    if (!key || !key.isPurpose45())
      throw new Error('Must add HD purpose keys to BIP45 wallet.');
  }

  index = this.keys.map(function(k, i) {
    return k.xpubkey === key.xpubkey ? i : null;
  }).filter(function(i) {
    return i !== null;
  })[0];

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

// Wallet ID:
// bip45: Purpose key "address" (prefix: WLT)
// bip44: Account key "address" (prefix: WLT)
Wallet.prototype.getID = function getID() {
  var publicKey = this.accountKey.publicKey;
  var id;

  if (this.options.id)
    return this.options.id;

  id = new Buffer(27);
  utils.copy(new Buffer([0x03, 0xbe, 0x04]), id, 0);
  utils.copy(utils.ripesha(publicKey), id, 3);
  utils.copy(utils.checksum(id.slice(0, 23)), id, 23);

  return utils.toBase58(id);
};

Wallet.prototype.createReceive = function createReceive() {
  return this.createAddress(false);
};

Wallet.prototype.createChange = function createChange() {
  return this.createAddress(true);
};

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

Wallet.prototype.deriveReceive = function deriveReceive(index) {
  if (typeof index === 'string')
    index = this.parsePath(index).index;

  return this.deriveAddress(false, index);
};

Wallet.prototype.deriveChange = function deriveChange(index) {
  if (typeof index === 'string')
    index = this.parsePath(index).index;

  return this.deriveAddress(true, index);
};

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
        ? constants.hd.hardened - 1
        : this.cosignerIndex,
      change: change,
      index: index
    };
  }

  if (this.cache.has(data.path))
    return this.cache.get(data.path);

  key = this.accountKey.derive(data.path);

  options = {
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

  this.addressMap[address.getKeyAddress()] = data.path;

  if (this.type === 'multisig')
    this.addressMap[address.getScriptAddress()] = data.path;

  if (this.witness)
    this.addressMap[address.getProgramAddress()] = data.path;

  // Update the DB with the new address.
  if (this.provider && this.provider.update)
    this.provider.update(this, address);

  this.emit('add address', address);

  this.cache.set(data.path, address);

  return address;
};

Wallet.prototype.hasAddress = function hasAddress(address) {
  return this.addressMap[address] != null;
};

Wallet.prototype.createPath = function createPath(cosignerIndex, change, index) {
  if (this.copayBIP45)
    cosignerIndex = constants.hd.hardened - 1;

  return 'm'
    + (this.derivation === 'bip45' ? '/' + cosignerIndex : '')
    + '/' + (change ? 1 : 0)
    + '/' + index;
};

Wallet.prototype.parsePath = function parsePath(path) {
  var parts;

  if (this.derivation === 'bip45')
    assert(/^m\/\d+\/\d+\/\d+$/.test(path));
  else
    assert(/^m\/\d+\/\d+$/.test(path));

  parts = path.split('/');

  if (this.derivation === 'bip45' && this.copayBIP45)
    assert(+parts[parts.length - 3] === constants.hd.hardened - 1);

  return {
    path: path,
    cosignerIndex: this.derivation === 'bip45'
      ? +parts[parts.length - 3]
      : null,
    change: +parts[parts.length - 2] === 1,
    index: +parts[parts.length - 1]
  };
};

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

Wallet.prototype.ownInput = function ownInput(tx, index) {
  if (tx instanceof bcoin.input)
    return tx.test(this.addressMap);

  return tx.testInputs(this.addressMap, index);
};

Wallet.prototype.ownOutput = function ownOutput(tx, index) {
  if (tx instanceof bcoin.output)
    return tx.test(this.addressMap);

  return tx.testOutputs(this.addressMap, index);
};

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

Wallet.prototype.fillCoins = function fillCoins(tx, callback) {
  if (!this.provider)
    return callback(new Error('No wallet provider available.'));

  return this.provider.fillTX(tx, callback);
};

Wallet.prototype.getCoin = function getCoin(id, callback) {
  if (!this.provider)
    return callback(new Error('No wallet provider available.'));

  return this.provider.getCoin(id, callback);
};

Wallet.prototype.getTX = function getTX(hash, callback) {
  if (!this.provider)
    return callback(new Error('No wallet provider available.'));

  return this.provider.getTX(hash, callback);
};

Wallet.prototype.createTX = function createTX(options, outputs, callback) {
  var self = this;
  var tx;

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
  outputs.forEach(function(output) {
    tx.addOutput(output);
  });

  // Fill the inputs with unspents
  this.fill(tx, options, function(err) {
    if (err)
      return callback(err);

    // Sort members a la BIP69
    tx.sortMembers();

    // Set the locktime to target value or
    // `height - whatever` to avoid fee sniping.
    if (options.locktime != null)
      tx.setLocktime(options.locktime);
    else
      tx.avoidFeeSniping();

    // Sign the transaction
    if (!self.sign(tx))
      return callback(new Error('Could not sign transaction.'));

    return callback(null, tx);
  });
};

Wallet.prototype.deriveInputs = function deriveInputs(tx) {
  var paths = this.getInputPaths(tx);
  var addresses = [];
  var i;

  for (i = 0; i < paths.length; i++)
    addresses.push(this.deriveAddress(paths[i]));

  return addresses;
};

Wallet.prototype.getPath = function getPath(address) {
  if (!address || typeof address !== 'string')
    return;
  return this.addressMap[address];
};

Wallet.prototype.getInputPaths = function getInputPaths(tx) {
  var paths = [];
  var i, input, output, address, path;

  if (tx instanceof bcoin.input) {
    path = this.getPath(tx.coin.getAddress());
    if (path)
      paths.push(path);
    return paths;
  }

  for (i = 0; i < tx.inputs.length; i++) {
    input = tx.inputs[i];
    output = input.coin;
    assert(output);

    address = output.getAddress();
    path = this.getPath(address);

    if (!path)
      continue;

    paths.push(path);
  }

  return utils.uniqs(paths);
};

Wallet.prototype.getOutputPaths = function getOutputPaths(tx) {
  var paths = [];
  var i, output, address, path;

  if (tx instanceof bcoin.output) {
    path = this.getPath(tx.getAddress());
    if (path)
      paths.push(path);
    return paths;
  }

  for (i = 0; i < tx.outputs.length; i++) {
    output = tx.outputs[i];

    address = output.getAddress();
    path = this.getPath(address);

    if (!path)
      continue;

    paths.push(path);
  }

  return utils.uniqs(paths);
};

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

Wallet.prototype.syncOutputDepth = function syncOutputDepth(tx) {
  var depth = this.getOutputDepth(tx);
  var res = false;

  if (this.setChangeDepth(depth.changeDepth + 1))
    res = true;

  if (this.setReceiveDepth(depth.receiveDepth + 1))
    res = true;

  return res;
};

Wallet.prototype.getRedeem = function getRedeem(hash, prefix) {
  var addr, address;

  if (!prefix) {
    if (hash.length === 20)
      prefix = 'scripthash';
    else if (hash.length === 32)
      prefix = 'witnessscripthash';
    else
      assert(false, 'Unknown hash length.');
  }

  addr = bcoin.address.compileHash(hash, prefix);
  address = this.deriveAddress(addr);

  if (!address)
    return;

  if (address.program && hash.length === 20) {
    if (utils.isEqual(hash, address.programHash))
      return address.program;
  }

  return address.script;
};

Wallet.prototype.zap = function zap(now, age, callback) {
  if (!this.provider.zap) {
    return utils.asyncify(callback)(
      new Error('Provider does not support zapping.'));
  }
  return this.provider.zap(now, age, callback);
};

Wallet.prototype.scan = function scan(txByAddress, callback) {
  var self = this;
  var res = false;

  return this._scan({}, txByAddress, function(err, depth) {
    if (err)
      return callback(err);

    if (self.setChangeDepth(depth.changeDepth + 1))
      res = true;

    if (self.setReceiveDepth(depth.receiveDepth + 1))
      res = true;

    return callback(null, res);
  });
};

Wallet.prototype._scan = function _scan(options, txByAddress, callback) {
  var self = this;
  var depth = { changeDepth: 0, receiveDepth: 0 };

  assert(this._initialized);

  return (function chainCheck(change) {
    var addressIndex = 0;
    var total = 0;
    var gap = 0;

    return (function next() {
      var address = self.deriveAddress(change, addressIndex++);

      return txByAddress(address.getAddress(), function(err, txs) {
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
            txs.forEach(function(tx) { self.addTX(tx); });
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

        return callback(null, depth);
      });
    })();
  })(false);
};

Wallet.prototype.scriptInputs = function scriptInputs(tx, index) {
  var addresses = this.deriveInputs(tx);

  return addresses.reduce(function(total, address) {
    return total + address.scriptInputs(tx, index);
  }, 0);
};

Wallet.prototype.signInputs = function signInputs(tx, type, index) {
  var addresses = this.deriveInputs(tx);

  return addresses.reduce(function(total, address) {
    return total + address.signInputs(tx, type, index);
  }, 0);
};

Wallet.prototype.sign = function sign(tx, type, index) {
  var addresses = this.deriveInputs(tx);

  return addresses.reduce(function(total, address) {
    return total + address.sign(tx, type, index);
  }, 0);
};

Wallet.prototype.addTX = function addTX(tx, callback) {
  if (!this.provider || !this.provider.addTX)
    return callback(new Error('No transaction pool available.'));

  return this.provider.addTX(tx, callback);
};

Wallet.prototype.getAll = function getAll(callback) {
  if (!this.provider)
    return callback(new Error('No wallet provider available.'));

  return this.provider.getAll(callback);
};

Wallet.prototype.getCoins = function getCoins(callback) {
  if (!this.provider)
    return callback(new Error('No wallet provider available.'));

  return this.provider.getCoins(callback);
};

Wallet.prototype.getPending = function getPending(callback) {
  if (!this.provider)
    return callback(new Error('No wallet provider available.'));

  return this.provider.getPending(callback);
};

Wallet.prototype.getBalance = function getBalance(callback) {
  if (!this.provider)
    return callback(new Error('No wallet provider available.'));

  return this.provider.getBalance(callback);
};

Wallet.prototype.getLastTime = function getLastTime(callback) {
  if (!this.provider)
    return callback(new Error('No wallet provider available.'));

  return this.provider.getLastTime(callback);
};

Wallet.prototype.getLast = function getLast(limit, callback) {
  if (!this.provider)
    return callback(new Error('No wallet provider available.'));

  return this.provider.getLast(limit, callback);
};

Wallet.prototype.getTimeRange = function getTimeRange(options, callback) {
  if (!this.provider)
    return callback(new Error('No wallet provider available.'));

  return this.provider.getTimeRange(options, callback);
};

Wallet.prototype.getPrivateKey = function getPrivateKey(enc) {
  return this.receiveAddress.getPrivateKey(enc);
};

Wallet.prototype.getPublicKey = function getPublicKey(enc) {
  return this.receiveAddress.getPublicKey(enc);
};

Wallet.prototype.getScript = function getScript() {
  return this.receiveAddress.getScript();
};

Wallet.prototype.getScriptHash = function getScriptHash() {
  return this.receiveAddress.getScriptHash();
};

Wallet.prototype.getScriptHash160 = function getScriptHash160() {
  return this.receiveAddress.getScriptHash160();
};

Wallet.prototype.getScriptHash256 = function getScriptHash256() {
  return this.receiveAddress.getScriptHash256();
};

Wallet.prototype.getScriptAddress = function getScriptAddress() {
  return this.receiveAddress.getScriptAddress();
};

Wallet.prototype.getProgram = function getProgram() {
  return this.receiveAddress.getProgram();
};

Wallet.prototype.getProgramHash = function getProgramHash() {
  return this.receiveAddress.getProgramHash();
};

Wallet.prototype.getProgramAddress = function getProgramAddress() {
  return this.receiveAddress.getProgramAddress();
};

Wallet.prototype.getKeyHash = function getKeyHash() {
  return this.receiveAddress.getKeyHash();
};

Wallet.prototype.getKeyAddress = function getKeyAddress() {
  return this.receiveAddress.getKeyAddress();
};

Wallet.prototype.getHash = function getHash() {
  return this.receiveAddress.getHash();
};

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

Wallet.prototype.inspect = function inspect() {
  return {
    id: this.id,
    type: this.type,
    network: network.type,
    m: this.m,
    n: this.n,
    keyAddress: this.keyAddress,
    scriptAddress: this.scriptAddress,
    programAddress: this.programAddress,
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

Wallet.prototype.toJSON = function toJSON() {
  return {
    v: 3,
    name: 'wallet',
    network: network.type,
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

Wallet._fromJSON = function _fromJSON(json, passphrase) {
  assert.equal(json.v, 3);
  assert.equal(json.name, 'wallet');

  if (json.network)
    assert.equal(json.network, network.type);

  return {
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

Wallet.fromJSON = function fromJSON(json, passphrase) {
  return new Wallet(Wallet._fromJSON(json, passphrase));
};

// For updating the address table quickly
// without decrypting the master key.
Wallet._syncDepth = function sync(json, options) {
  var master, wallet;
  var res = false;

  assert.equal(json.v, 3);
  assert.equal(json.name, 'wallet');

  if (json.network)
    assert.equal(json.network, network.type);

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

Wallet.syncOutputDepth = function syncOutputDepth(json, tx) {
  return Wallet._syncDepth(json, { tx: tx });
};

Wallet.setReceiveDepth = function setReceiveDepth(json, receiveDepth) {
  return Wallet._syncDepth(json, {
    receiveDepth: receiveDepth || 0
  });
};

Wallet.setChangeDepth = function setChangeDepth(json, changeDepth) {
  return Wallet._syncDepth(json, {
    changeDepth: changeDepth || 0
  });
};

Wallet.setDepth = function setDepth(json, receiveDepth, changeDepth) {
  return Wallet._syncDepth(json, {
    receiveDepth: receiveDepth || 0,
    changeDepth: changeDepth || 0
  });
};

Wallet.isWallet = function isWallet(obj) {
  return obj
    && typeof obj.receiveDepth === 'number'
    && obj.deriveAddress === 'function';
};

/**
 * Expose
 */

module.exports = Wallet;
