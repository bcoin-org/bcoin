/**
 * wallet.js - wallet object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

var bcoin = require('../bcoin');
var hash = require('hash.js');
var bn = require('bn.js');
var inherits = require('inherits');
var EventEmitter = require('events').EventEmitter;
var utils = bcoin.utils;
var assert = utils.assert;
var constants = bcoin.protocol.constants;
var network = bcoin.protocol.network;

/**
 * Wallet
 */

function Wallet(options) {
  var key, receiving;

  if (!(this instanceof Wallet))
    return new Wallet(options);

  EventEmitter.call(this);

  if (!options)
    options = {};

  options = utils.merge({}, options);

  if (options.derivation === 'bip44' || options.derivation === 'bip45')
    options.hd = true;

  if (options.hd && !options.master) {
    options.master = options.hd === true
      ? bcoin.hd.privateKey()
      : bcoin.hd.privateKey(options.hd);
    delete options.hd;
  }

  if (options.key) {
    options.pair = options.key;
    delete options.key;
  }

  if (options.priv) {
    options.privateKey = options.priv;
    delete options.priv;
  }

  if (options.pub) {
    options.publicKey = options.pub;
    delete options.pub;
  }

  if ((options.pair instanceof bcoin.hd.privateKey)
      || (options.pair instanceof bcoin.hd.publicKey)) {
    options.master = options.pair;
    delete options.pair;
  } else if (options.privateKey instanceof bcoin.hd.privateKey) {
    options.master = options.privateKey;
    delete options.privateKey;
  } else if (options.publicKey instanceof bcoin.hd.publicKey) {
    options.master = options.publicKey;
    delete options.publicKey;
  }

  this.options = options;
  this.addresses = [];
  this.master = options.master || null;
  this._addressTable = {};
  this._labelMap = {};

  this.accountIndex = options.accountIndex || 0;
  this.addressDepth = options.addressDepth || 0;
  this.changeDepth = options.changeDepth || 0;
  this.cosignerIndex = -1;
  this.sharedCosignerIndex = constants.hd.hardened - 1;
  this.purposeKeys = options.purposeKeys || [];
  this.keys = options.keys || [];

  this.hd = !!this.master;
  this.type = options.type || 'pubkeyhash';
  this.subtype = options.subtype || null;
  this.derivation = options.derivation || null;
  this.compressed = options.compressed !== false;
  this.keys = [];
  this.m = options.m || 1;
  this.n = options.n || 1;
  this.nmax = this.type === 'scripthash'
    ? (this.compressed ? 15 : 7)
    : 3;

  if (this.n > 1) {
    if (this.type !== 'multisig')
      this.type = 'scripthash';
    if (this.type === 'scripthash')
      this.subtype = 'multisig';
  }

  if (!this.derivation) {
    if (this.master) {
      if (this.type === 'scripthash' && this.subtype === 'multisig')
        this.derivation = 'bip45';
      else
        this.derivation = 'bip44';
    } else {
      this.derivation = 'normal';
    }
  }

  if (network.prefixes[this.type] == null)
    throw new Error('Unknown prefix: ' + this.type);

  if (this.m < 1 || this.m > this.n)
    throw new Error('m ranges between 1 and n');

  if (this.n < 1 || this.n > this.nmax)
    throw new Error('n ranges between 1 and ' + this.nmax);

  if (this.derivation === 'bip45') {
    this.purposeKey = this.master.isPurpose45()
      ? this.master
      : this.master.derivePurpose45();
  } else if (this.derivation === 'bip44') {
    this.purposeKey = this.master.isAccount44()
      ? this.master
      : this.master.deriveAccount44(this.accountIndex);
  }

  if (!options.addresses)
    options.addresses = [];

  if (this._isKeyOptions(options)) {
    options.addresses.unshift({
      privateKey: options.privateKey,
      publicKey: options.publicKey,
      pair: options.pair,
      type: this.type,
      subtype: this.subtype,
      m: this.m,
      n: this.n,
      keys: [],
      change: false
    });
  }

  this.storage = options.storage;
  this.loading = true;
  this.lastTs = 0;

  // This is a chicken and egg problem for BIP45. Real address keys cannot be
  // generated until all shared keys have been added to the wallet. The flow of
  // this wallet is, the actual address objects will be generated once all
  // shared keys have been added. This presents a problem for non-bip45
  // wallets: if they want to use the addKey() interface with
  // wallet.getPublicKey(), we need to expose a key for them to use. Here, we
  // generate the last receiving address. However, since "normal" wallets
  // cannot deterministically generate keys, we have to buffer the generated
  // key for later.
  if (this.derivation === 'bip44') {
    // Generate the last known receiving address
    key = this.createKey(false, Math.max(0, this.addressDepth - 1));
    this.currentAddress = bcoin.address({
      privateKey: key.privateKey,
      publicKey: key.publicKey,
      compressed: key.compressed,
      index: key.index,
      path: key.path,
      type: this.type,
      subtype: this.subtype,
      m: this.m,
      n: this.n,
      keys: options.keys,
      derived: true
    });
  } else if (this.derivation === 'normal') {
    // Try to find the last receiving address if there is one.
    receiving = options.addresses.filter(function(address) {
      return !address.change && this._isKeyOptions(address);
    }, this).pop();
    if (receiving) {
      this.currentAddress = bcoin.address(receiving);
    } else {
      // No receiving address is in this wallet yet, generate
      // it and save it so createKey can recreate it later.
      key = this.createKey();
      this._firstKey = key;
      this.currentAddress = bcoin.address({
        privateKey: key.privateKey,
        publicKey: key.publicKey,
        compressed: key.compressed,
        index: key.index,
        path: key.path,
        type: this.type,
        subtype: this.subtype,
        m: this.m,
        n: this.n,
        keys: options.keys
      });
    }
  }

  if (this.derivation === 'bip44' || this.derivation === 'bip45')
    this.addKey(this.purposeKey);
  else
    this.addKey(this.currentAddress.publicKey);

  (options.keys || []).forEach(function(key) {
    this.addKey(key);
  }, this);
}

inherits(Wallet, EventEmitter);

Wallet.prototype._pruneAddresses = function _pruneAddresses(options) {
  var addresses = this.addresses.slice();
  var address;

  for (i = 0; i < addresses.length; i++) {
    address = addresses[i];

    if (address === this.currentAddress || address === this.changeAddress)
      continue;

    if (!address.change)
      continue;

    if (!address.derived)
      continue;

    if (address.getBalance().cmpn(0) === 0)
      this.removeAddress(address);
  }
};

Wallet.prototype._isKeyOptions = function _isKeyOptions(options) {
  return (options.priv || options.privateKey)
    || (options.pub || options.publicKey)
    || (options.key || options.pair);
};

// Wallet ID:
// bip45: Purpose key address
// bip44: Account key address
// normal: Address of first key in wallet
Wallet.prototype.getID = function getID() {
  if (this.derivation === 'bip45')
    return bcoin.address.key2addr(this.purposeKey.publicKey);

  if (this.derivation === 'bip44')
    return bcoin.address.key2addr(this.purposeKey.publicKey);

  if (this.derivation === 'normal') {
    if (this.addresses.length)
      return this.addresses[0].getKeyAddress();

    if (this._firstKey)
      return bcoin.address.key2addr(this._firstKey.publicKey);
  }

  assert(false);
};

Wallet.prototype._initAddresses = function _initAddresses() {
  var options = this.options;
  var i;

  assert(!this._initialized);
  this._initialized = true;

  if (this.copayBIP45)
    this.cosignerIndex = this.sharedCosignerIndex;

  delete this.currentAddress;

  options.addresses.forEach(function(address) {
    address = this.addAddress(address);
    if (!this.master) {
      if (!address.change)
        this.currentAddress = address;
      else
        this.changeAddress = address;
    }
  }, this);

  if (this.master) {
    for (i = 0; i < this.addressDepth; i++)
      this.currentAddress = this.createAddress(false, i);

    for (i = 0; i < this.changeDepth; i++)
      this.changeAddress = this.createAddress(true, i);
  }

  if (!this.currentAddress)
    this.currentAddress = this.createAddress();

  if (!this.changeAddress)
    this.changeAddress = this.createAddress(true);

  assert(this.currentAddress);
  assert(!this.currentAddress.change);
  assert(this.changeAddress.change);

  this.prefix = 'bt/wallet/' + this.getID() + '/';

  this.tx = options.tx || bcoin.txPool(this);

  this._init();
};

Wallet.prototype.addKey = function addKey(key) {
  var hdKey, has, i;

  if (bcoin.hd.privateKey.isExtended(key))
    key = bcoin.hd.privateKey(key);
  else if (bcoin.hd.publicKey.isExtended(key))
    key = bcoin.hd.publicKey(key);

  if (key instanceof bcoin.keypair)
    key = key.hd;

  if (key instanceof bcoin.hd.privateKey)
    key = key.hdpub;

  if (key instanceof bcoin.hd.publicKey) {
    hdKey = key;
    key = hdKey.publicKey;
  }

  if (this.derivation === 'bip44' || this.derivation === 'bip45') {
    if (this.derivation === 'bip44') {
      if (!hdKey || !hdKey.isAccount44())
        throw new Error('Must add HD account keys to BIP44 wallet.');
    }

    if (this.derivation === 'bip45') {
      if (!hdKey || !hdKey.isPurpose45())
        throw new Error('Must add HD purpose keys to BIP45 wallet.');
    }

    has = this.purposeKeys.some(function(k) {
      return k.xpubkey === hdKey.xpubkey;
    });

    if (has)
      return;

    assert(!this._keysFinalized);

    this.purposeKeys.push(hdKey);

    if (this.purposeKeys.length === this.n)
      this.finalizeKeys();

    return;
  }

  key = utils.toBuffer(key);

  has = this.keys.some(function(k) {
    return utils.isEqual(k, key);
  });

  if (has)
    return;

  assert(!this._keysFinalized);

  this.keys.push(key);

  if (this.keys.length === this.n)
    this.finalizeKeys();
};

Wallet.prototype.finalizeKeys = function finalizeKeys(key) {
  assert(!this._keysFinalized);
  this._keysFinalized = true;

  if (this.derivation === 'bip44' || this.derivation === 'bip45') {
    this.purposeKeys = utils.sortHDKeys(this.purposeKeys);

    for (i = 0; i < this.purposeKeys.length; i++) {
      if (this.purposeKeys[i].xpubkey === this.purposeKey.xpubkey) {
        this.cosignerIndex = i;
        break;
      }
    }

    assert(this.cosignerIndex !== -1);

    this._initAddresses();
    return;
  }

  this.keys = utils.sortKeys(this.keys);

  for (i = 0; i < this.keys.length; i++) {
    if (utils.isEqual(this.keys[i], this.currentAddress.publicKey)) {
      this.cosignerIndex = i;
      break;
    }
  }

  assert(this.cosignerIndex !== -1);

  this._initAddresses();
};

Wallet.prototype.removeKey = function removeKey(key) {
  var hdKey, index;

  assert(!this._keysFinalized);

  if (bcoin.hd.privateKey.isExtended(key))
    key = bcoin.hd.privateKey(key);
  else if (bcoin.hd.publicKey.isExtended(key))
    key = bcoin.hd.publicKey(key);

  if (key instanceof bcoin.keypair)
    key = key.hd;

  if (key instanceof bcoin.hd.privateKey)
    key = key.hdpub;

  if (key instanceof bcoin.hd.publicKey) {
    hdKey = key;
    key = hd.publicKey;
  }

  if (this.derivation === 'bip44' || this.derivation === 'bip45') {
    if (this.derivation === 'bip44') {
      if (!hdKey || !hdKey.isAccount44())
        throw new Error('Must add HD account keys to BIP44 wallet.');
    }

    if (this.derivation === 'bip45') {
      if (!hdKey || !hdKey.isPurpose45())
        throw new Error('Must add HD purpose keys to BIP45 wallet.');
    }

    index = this.purposeKeys.map(function(k, i) {
      return k.xpubkey === hdKey.xpubkey ? i : null;
    }).filter(function(i) {
      return i !== null;
    })[0];

    if (index == null)
      return;

    this.purposeKeys.splice(index, 1);

    return;
  }

  key = utils.toBuffer(key);

  index = this.keys.map(function(k, i) {
    return utils.isEqual(k, key) ? i : null;
  }).filter(function(i) {
    return i !== null;
  })[0];

  if (index == null)
    return;

  this.keys.splice(index, 1);
};

Wallet.prototype._init = function init() {
  var self = this;
  var prevBalance = null;

  if (this.tx._loaded) {
    this.loading = false;
    this._pruneAddresses();
    return;
  }

  // Notify owners about new accepted transactions
  this.tx.on('update', function(lastTs, tx) {
    var b = this.getBalance();
    if (prevBalance && prevBalance.cmp(b) !== 0)
      self.emit('balance', b);
    self.emit('update', tx);
    prevBalance = b;
  });

  this.tx.on('tx', function(tx) {
    // TX using this address was confirmed.
    // Allocate a new address.
    if (tx.block) {
      if (self.currentAddress.ownOutput(tx))
        self.currentAddress = self.createAddress();
      if (self.changeAddress.ownOutput(tx))
        self.changeAddress = self.createAddress(true);
      self._pruneAddresses();
    }
    self.emit('tx', tx);
  });

  this.tx.once('load', function(ts) {
    self.loading = false;
    self.lastTs = ts;
    self._pruneAddresses();
    self.emit('load', ts);
  });

  this.tx.on('error', function(err) {
    self.emit('error', err);
  });
};

Wallet.prototype._getAddressTable = function() {
  var addresses = {};
  var i, address;

  for (i = 0; i < this.addresses.length; i++) {
    address = this.addresses[i];
    if (address.type === 'scripthash')
      addresses[address.getScriptAddress()] = i;
    addresses[address.getKeyAddress()] = i;
  }

  return addresses;
};

// Faster than indexOf if we have tons of addresses
Wallet.prototype._addressIndex = function _addressIndex(address) {
  var addr;

  if (typeof address === 'string')
    return this._addressTable[addr];

  if (!(address instanceof bcoin.address))
    address = bcoin.address(address);

  if (address.type === 'scripthash') {
    addr = address.getScriptAddress();
    if (this._addressTable[addr] != null)
      return this._addressTable[addr];
  }

  addr = address.getKeyAddress();
  if (this._addressTable[addr] != null)
    return this._addressTable[addr];

  return -1;
};

// TODO: fromPath here
Wallet.prototype.createAddress = function createAddress(change, index) {
  var self = this;
  var key = this.createKey(change, index);
  var address;

  assert(this._initialized);

  var options = {
    privateKey: key.privateKey,
    publicKey: key.publicKey,
    compressed: key.compressed,
    index: key.index,
    path: key.path,
    type: this.type,
    subtype: this.subtype,
    m: this.m,
    n: this.n,
    keys: [],
    change: change,
    derived: !!this.hd
  };

  if (index == null) {
    index = change ? self.changeDepth : self.addressDepth;
    if (this.master) {
      if (change)
        this.changeDepth++;
      else
        this.addressDepth++;
    }
  }

  if (this.derivation === 'bip44') {
    this.purposeKeys.forEach(function(key, cosignerIndex) {
      key = key
        .derive(change ? 1 : 0)
        .derive(index);
      options.keys.push(key.publicKey);
    });
    this.keys = utils.sortKeys(options.keys);
  } else if (this.derivation === 'bip45') {
    this.purposeKeys.forEach(function(key, cosignerIndex) {
      key = key
        .derive(cosignerIndex)
        .derive(change ? 1 : 0)
        .derive(index);
      options.keys.push(key.publicKey);
    });
    this.keys = utils.sortKeys(options.keys);
  } else if (this.derivation === 'normal') {
    this.keys.forEach(function(key, i) {
      if (i !== this.cosignerIndex)
        options.keys.push(key);
    }, this);
    options.keys.push(key.publicKey);
  }

  address = this.addAddress(options);

  return address;
};

Wallet.prototype.hasAddress = function hasAddress(address) {
  return this._addressIndex(address) != -1;
};

Wallet.prototype.findAddress = function findAddress(address) {
  var i = this._addressIndex(address);

  if (i === -1)
    return;

  return this.addresses[i];
};

Wallet.prototype.addAddress = function addAddress(address) {
  var self = this;
  var index;

  assert(this._initialized);

  if (!(address instanceof bcoin.address))
    address = bcoin.address(address);

  if (this._addressIndex(address) !== -1)
    return;

  if (address._wallet)
    address._wallet.removeAddress(address);

  address._wallet = this;

  index = this.addresses.push(address) - 1;

  address.on('update script', address._onUpdate = function(old, cur) {
    self._addressTable[cur] = self._addressTable[old];
    delete self._addressTable[old];
    self.emit('add address', address);
  });

  if (address.type === 'scripthash')
    this._addressTable[address.getScriptAddress()] = index;

  this._addressTable[address.getKeyAddress()] = index;

  if (address.label && this._labelTable[address.label] == null)
    this._labelTable[address.label] = index;

  this.emit('add address', address);

  return address;
};

Wallet.prototype.removeAddress = function removeAddress(address) {
  var i;

  assert(this._initialized);

  assert(address instanceof bcoin.address);

  i = this._addressIndex(address);

  if (i === -1)
    return;

  assert(address._wallet === this);
  assert(address._onUpdate);

  this.addresses.splice(i, 1);

  address.removeListener('update script', address._onUpdate);

  this._addressTable = this._getAddressTable();

  delete address._onUpdate;
  delete address._wallet;

  if (this._labelTable[address.label] === i)
    delete this._labelTable[address.label];

  this.emit('remove address', address);

  return address;
};

Wallet.prototype.getPrivateKey = function getPrivateKey(enc) {
  return this.currentAddress.getPrivateKey(enc);
};

Wallet.prototype.getScript = function getScript() {
  return this.currentAddress.getScript();
};

Wallet.prototype.getScriptHash = function getScriptHash() {
  return this.currentAddress.getScriptHash();
};

Wallet.prototype.getScriptAddress = function getScriptAddress() {
  return this.currentAddress.getScriptAddress();
};

Wallet.prototype.getPublicKey = function getPublicKey(enc) {
  return this.currentAddress.getPublicKey(enc);
};

Wallet.prototype.createKey = function createKey(change, index) {
  var key;

  if (this.derivation === 'normal') {
    if (this._firstKey) {
      key = this._firstKey;
      delete this._firstKey;
      return key;
    }
    key = bcoin.keypair({
      compressed: this.compressed
    });
    return {
      privateKey: key.privateKey,
      publicKey: key.publicKey,
      compressed: key.compressed
    };
  }

  if (index == null)
    index = change ? this.changeDepth : this.addressDepth;

  if (this.derivation === 'bip44') {
    key = this.purposeKey
      .derive(change ? 1 : 0)
      .derive(index);
  } else if (this.derivation === 'bip45') {
    key = this.purposeKey
      .derive(this.cosignerIndex)
      .derive(change ? 1 : 0)
      .derive(index);
  }

  return {
    privateKey: key.privateKey,
    publicKey: key.publicKey,
    compressed: true,
    index: index,
    path: 'm'
      // + (this.derivation === 'bip45' ? '/' + this.cosignerIndex : '')
      + '/' + (change ? 1 : 0)
      + '/' + index
  };
};

Wallet.prototype.setAddressDepth = function setAddressDepth(depth) {
  var i;

  assert(this.derivation !== 'normal');

  if (depth <= this.addressDepth)
    return false;

  for (i = this.addressDepth; i < depth; i++)
    this.currentAddress = this.createAddress(false, i);

  this.addressDepth = depth;

  return true;
};

Wallet.prototype.setChangeDepth = function setChangeDepth(depth) {
  var i;

  assert(this.derivation !== 'normal');

  if (depth <= this.changeDepth)
    return false;

  for (i = this.changeDepth; i < depth; i++)
    this.changeAddress = this.createAddress(true, i);

  this.changeDepth = depth;

  return true;
};

Wallet.prototype.getKeyHash =
Wallet.prototype.getKeyhash = function getKeyhash() {
  return this.currentAddress.getKeyHash();
};

Wallet.prototype.getKeyAddress =
Wallet.prototype.getKeyaddress = function getKeyaddress() {
  return this.currentAddress.getKeyAddress();
};

Wallet.prototype.getHash = function getHash() {
  return this.currentAddress.getHash();
};

Wallet.prototype.getAddress = function getAddress() {
  return this.currentAddress.getAddress();
};

Wallet.prototype.ownInput = function ownInput(tx, index) {
  if (tx instanceof bcoin.input) {
    var input = tx;
    var scriptAddress = input.getScriptAddress();
    if (this._addressTable[scriptAddress] != null)
      return true;
    var addresses = input.getAddresses();
    var address;
    for (var i = 0; i < addresses.length; i++) {
      address = addresses[i];
      if (this._addressTable[address] != null)
        return true;
    }
    return false;
  }
  this.fillPrevout(tx);
  return tx.testInputs(this._addressTable, index, true);
};

Wallet.prototype.ownOutput = function ownOutput(tx, index) {
  if ((tx instanceof bcoin.output) || (tx instanceof bcoin.output.prev)) {
    var output = tx;
    var scriptAddress = output.getScriptAddress();
    if (this._addressTable[scriptAddress] != null)
      return true;
    var addresses = output.getAddresses();
    var address;
    for (var i = 0; i < addresses.length; i++) {
      address = addresses[i];
      if (this._addressTable[address] != null)
        return true;
    }
    return false;
  }
  return tx.testOutputs(this._addressTable, index, true);
};

Wallet.prototype.fill = function fill(tx, address, fee) {
  var unspent, items, result;

  assert(this._initialized);

  if (!address)
    address = this.changeAddress.getKeyAddress();

  unspent = this.getUnspent();

  items = unspent.filter(function(coin) {
    if (bcoin.script.isScripthash(coin.script))
      return this.type === 'scripthash';

    if (bcoin.script.isMultisig(coin.script))
      return this.type === 'multisig';

    return true;
  }, this);

  if (tx.getInputs(unspent, address, fee).inputs)
    unspent = items;

  result = tx.fill(unspent, address, fee);

  if (!result.inputs)
    return false;

  return true;
};

// Legacy
Wallet.prototype.fillUnspent = Wallet.prototype.fill;
Wallet.prototype.fillInputs = Wallet.prototype.fill;

Wallet.prototype.fillPrevout = function fillPrevout(tx) {
  return tx.fillPrevout(this);
};

// Legacy
Wallet.prototype.fillTX = Wallet.prototype.fillPrevout;

Wallet.prototype.createTX = function createTX(outputs, fee) {
  var tx = bcoin.tx();
  var target;

  if (!Array.isArray(outputs))
    outputs = [outputs];

  // Add the outputs
  outputs.forEach(function(output) {
    tx.addOutput(output);
  });

  // Fill the inputs with unspents
  if (!this.fill(tx, null, fee))
    return;

  // Sort members a la BIP69
  tx.sortMembers();

  // Find the necessary locktime if there is
  // a checklocktimeverify script in the unspents.
  target = tx.getTargetLocktime();

  // No target value. The unspents have an
  // incompatible locktime type.
  if (!target)
    return;

  // Set the locktime to target value or
  // `height - whatever` to avoid fee snipping.
  if (target.value > 0)
    tx.setLocktime(target.value);
  else
    tx.avoidFeeSnipping();

  return tx;
};

Wallet.prototype.scriptInputs = function scriptInputs(tx) {
  this.fillPrevout(tx);
  return this.addresses.reduce(function(total, address) {
    return total + address.scriptInputs(tx);
  }, 0);
};

Wallet.prototype.signInputs = function signInputs(tx, type) {
  this.fillPrevout(tx);
  return this.addresses.reduce(function(total, address) {
    return total + address.signInputs(tx, type);
  }, 0);
};

Wallet.prototype.sign = function sign(tx, type) {
  this.fillPrevout(tx);
  return this.addresses.reduce(function(total, address) {
    return total + address.sign(tx, type);
  }, 0);
};

Wallet.prototype.addTX = function addTX(tx, block) {
  return this.tx.add(tx);
};

Wallet.prototype.getAll = function getAll() {
  return this.tx.getAll();
};

Wallet.prototype.getUnspent = function getUnspent() {
  return this.tx.getUnspent();
};

Wallet.prototype.getPending = function getPending() {
  return this.tx.getPending();
};

Wallet.prototype.getBalance = function getBalance() {
  return this.tx.getBalance();
};

// Legacy
Wallet.prototype.all = Wallet.prototype.getAll;
Wallet.prototype.unspent = Wallet.prototype.getUnspent;
Wallet.prototype.pending = Wallet.prototype.getPending;
Wallet.prototype.balance = Wallet.prototype.getBalance;

Wallet.prototype.toAddress = function toAddress() {
  var self = this;
  var received = new bn(0);
  var sent = new bn(0);

  var txs = Object.keys(this.tx._all).reduce(function(out, hash) {
    out.push(self.tx._all[hash]);
    return out;
  }, []);

  txs.forEach(function(tx) {
    tx.inputs.forEach(function(input, i) {
      if (self.ownInput(tx, i))
        sent.iadd(input.value);
    });
    tx.outputs.forEach(function(output, i) {
      if (self.ownOutput(tx, i))
        received.iadd(output.value);
    });
  });

  return {
    address: this.getAddress(),
    hash: utils.toHex(this.getHash()),
    received: received,
    sent: sent,
    balance: this.getBalance(),
    txs: txs
  };
};

Wallet.prototype.__defineGetter__('script', function() {
  return this.getScript();
});

Wallet.prototype.__defineGetter__('scriptHash', function() {
  return this.getScriptHash();
});

Wallet.prototype.__defineGetter__('scriptAddress', function() {
  return this.getScriptAddress();
});

Wallet.prototype.__defineGetter__('privateKey', function() {
  return this.getPrivateKey();
});

Wallet.prototype.__defineGetter__('publicKey', function() {
  return this.getPublicKey();
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

Wallet.prototype.toJSON = function toJSON(encrypt) {
  assert(this._initialized);
  return {
    v: 3,
    name: 'wallet',
    network: network.type,
    type: this.type,
    subtype: this.subtype,
    m: this.m,
    n: this.n,
    derivation: this.derivation,
    accountIndex: this.accountIndex,
    addressDepth: this.addressDepth,
    changeDepth: this.changeDepth,
    cosignerIndex: this.cosignerIndex,
    master: this.master ? this.master.toJSON(encrypt) : null,
    addresses: this.addresses.filter(function(address) {
      return !address.derived;
    }, this).map(function(address) {
      return address.toJSON(encrypt);
    }),
    keys: this.derivation === 'bip44' || this.derivation === 'bip45'
      ? this.purposeKeys.map(function(key) {
        return key.xpubkey;
      })
      : this.keys.map(function(key) {
        return utils.toBase58(key);
      }),
    balance: utils.toBTC(this.getBalance()),
    tx: this.tx.toJSON()
  };
};

Wallet.fromJSON = function fromJSON(json, decrypt) {
  var wallet;

  assert.equal(json.v, 3);
  assert.equal(json.name, 'wallet');

  if (json.network)
    assert.equal(json.network, network.type);

  wallet = new Wallet({
    type: json.type,
    subtype: json.subtype,
    m: json.m,
    n: json.n,
    derivation: json.derivation,
    accountIndex: json.accountIndex,
    addressDepth: json.addressDepth,
    changeDepth: json.changeDepth,
    cosignerIndex: json.cosignerIndex,
    master: json.master
      ? bcoin.hd.fromJSON(json.master, decrypt)
      : null,
    addresses: json.addresses.map(function(address) {
      return bcoin.address.fromJSON(address, decrypt);
    }),
    keys: json.keys
  });

  wallet.tx.fromJSON(json.tx);

  return wallet;
};

// Compat - Legacy
Wallet.toSecret = function toSecret(privateKey, compressed) {
  return bcoin.keypair.toSecret(privateKey, compressed);
};

Wallet.fromSecret = function fromSecret(privateKey) {
  return bcoin.keypair.fromSecret(privateKey);
};

Wallet.key2hash = function key2hash(key) {
  return bcoin.address.key2hash(key);
};

Wallet.hash2addr = function hash2addr(hash, prefix) {
  return bcoin.address.hash2addr(hash, prefix);
};

Wallet.addr2hash = function addr2hash(addr, prefix) {
  return bcoin.address.addr2hash(addr, prefix);
};

Wallet.validateAddress = function validateAddress(addr, prefix) {
  return bcoin.address.validateAddress(addr, prefix);
};

/**
 * Expose
 */

module.exports = Wallet;
