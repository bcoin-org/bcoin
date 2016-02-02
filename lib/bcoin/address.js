/**
 * address.js - address object for bcoin
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
 * Address
 */

function Address(options) {
  if (!(this instanceof Address))
    return new Address(options);

  EventEmitter.call(this);

  if (!options)
    options = {};

  this.options = options;
  this.storage = options.storage;
  this.label = options.label || '';
  this.change = !!options.change;

  this.key = bcoin.keypair({
    priv: options.priv,
    pub: options.pub,
    hd: options.hd,
    key: options.key,
    personalization: options.personalization,
    entropy: options.entropy,
    compressed: options.compressed
  });

  // Compatability
  if (options.multisig) {
    if (options.multisig.type)
      options.type = options.multisig.type;
    if (options.multisig.keys)
      options.keys = options.multisig.keys;
    if (options.multisig.m)
      options.m = options.multisig.m;
    if (options.multisig.n)
      options.n = options.multisig.n;
  }

  this.type = options.type || 'pubkeyhash';
  this.subtype = options.subtype;
  this.keys = [];
  this.m = options.m || 1;
  this.n = options.n || 1;
  this.redeem = null;

  if (this.n > 1) {
    if (this.type !== 'multisig')
      this.type = 'scripthash';
    if (this.type === 'scripthash')
      this.subtype = 'multisig';
  }

  if (network.prefixes[this.type] == null)
    throw new Error('Unknown prefix: ' + this.type);

  this.nmax = this.type === 'scripthash'
    ? (this.key.compressed ? 15 : 7)
    : 3;

  if (this.m < 1 || this.m > this.n)
    throw new Error('m ranges between 1 and n');

  if (this.n < 1 || this.n > this.nmax)
    throw new Error('n ranges between 1 and ' + this.nmax);

  this.addKey(this.getPublicKey());

  (options.keys || []).forEach(function(key) {
    this.addKey(key);
  }, this);

  if (options.redeem)
    this.setRedeem(options.redeem);

  this.prefix = 'bt/address/' + this.getKeyAddress() + '/';
}

inherits(Address, EventEmitter);

Address.prototype.setRedeem = function setRedeem(redeem) {
  var old = this.getScriptAddress();

  if (!utils.isBytes(redeem))
    redeem = bcoin.script.encode(redeem);

  this.type = 'scripthash';
  this.subtype = null;
  this.redeem = redeem;
  this.emit('scriptaddress', old, this.getScriptAddress());
};

Address.prototype.addKey = function addKey(key) {
  var old = this.getScriptAddress();

  key = utils.toBuffer(key);

  var has = this.keys.some(function(k) {
    return utils.isEqual(k, key);
  });

  if (has)
    return;

  this.keys.push(key);

  this.keys = utils.sortKeys(this.keys);
  this.emit('scriptaddress', old, this.getScriptAddress());
};

Address.prototype.removeKey = function removeKey(key) {
  var old = this.getScriptAddress();

  key = utils.toBuffer(key);

  var index = this.keys.map(function(key, i) {
    return utils.isEqual(key, pub) ? i : null;
  }).filter(function(i) {
    return i !== null;
  })[0];

  if (index == null)
    return;

  this.keys.splice(index, 1);

  this.keys = utils.sortKeys(this.keys);
  this.emit('scriptaddress', old, this.getScriptAddress());
};

Address.prototype.getPrivateKey = function getPrivateKey(enc) {
  return this.key.getPrivate(enc);
};

Address.toSecret = function toSecret(priv, compressed) {
  return bcoin.keypair.toSecret(priv, compressed);
};

Address.fromSecret = function fromSecret(priv) {
  return bcoin.keypair.fromSecret(priv);
};

Address.prototype.getScript = function getScript() {
  if (this.type !== 'scripthash')
    return;

  if (this.redeem)
    return this.redeem.slice();

  if (this.subtype === 'pubkey')
    return bcoin.script.encode([this.getPublicKey(), 'checksig']);

  if (this.subtype === 'pubkeyhash' || this.keys.length < this.n) {
    return bcoin.script.encode([
      'dup',
      'hash160',
      this.getKeyHash(),
      'equalverify',
      'checksig'
    ]);
  }

  return bcoin.script.encode(
    bcoin.script.createMultisig(this.keys, this.m, this.n)
  );
};

Address.prototype.getScriptHash = function getScriptHash() {
  if (this.type !== 'scripthash')
    return;

  return utils.ripesha(this.getScript());
};

Address.prototype.getScriptAddress = function getScriptAddress() {
  if (this.type !== 'scripthash')
    return;

  return Address.hash2addr(this.getScriptHash(), this.type);
};

Address.prototype.getPublicKey = function getPublicKey(enc) {
  return this.key.getPublic(enc);
};

Address.prototype.getKeyHash = function getKeyHash() {
  return Address.key2hash(this.getPublicKey());
};

Address.prototype.getKeyAddress = function getKeyAddress() {
  return Address.hash2addr(this.getKeyHash(), 'pubkeyhash');
};

Address.prototype.getHash = function getHash() {
  if (this.type === 'scripthash')
    return this.getScriptHash();
  return this.getKeyHash();
};

Address.prototype.getAddress = function getAddress() {
  if (this.type === 'scripthash')
    return this.getScriptAddress();
  return this.getKeyAddress();
};

Address.key2hash = function key2hash(key) {
  key = utils.toBuffer(key);
  return utils.ripesha(key);
};

Address.hash2addr = function hash2addr(hash, prefix) {
  var addr;

  hash = utils.toArray(hash, 'hex');

  prefix = network.prefixes[prefix || 'pubkeyhash'];
  hash = [ prefix ].concat(hash);

  addr = hash.concat(utils.checksum(hash));

  return utils.toBase58(addr);
};

Address.__defineGetter__('prefixes', function() {
  if (Address._prefixes)
    return Address._prefixes;

  Address._prefixes = ['pubkeyhash', 'scripthash'].reduce(function(out, prefix) {
    var ch = Address.hash2addr(Address.key2hash([]), prefix)[0];
    out[ch] = prefix;
    return out;
  }, {});

  return Address._prefixes;
});

Address.addr2hash = function addr2hash(addr, prefix) {
  var chk;

  if (prefix == null && typeof addr === 'string')
    prefix = Address.prefixes[addr[0]];

  if (!utils.isBuffer(addr))
    addr = utils.fromBase58(addr);

  prefix = network.prefixes[prefix || 'pubkeyhash'];

  if (addr.length !== 25)
    return [];

  if (addr[0] !== prefix)
    return [];

  chk = utils.checksum(addr.slice(0, -4));

  if (utils.readU32(chk, 0) !== utils.readU32(addr, 21))
    return [];

  return addr.slice(1, -4);
};

Address.validate = function validateAddress(addr, prefix) {
  if (!addr || typeof addr !== 'string')
    return false;

  var p = Address.addr2hash(addr, prefix);

  return p.length !== 0;
};

Address.validateAddress = Address.validate;

Address.prototype.ownOutput = function ownOutput(tx, index) {
  var scripthash = this.getScriptHash();
  var hash = this.getKeyHash();
  var key = this.getPublicKey();
  var keys = this.keys;

  var outputs = tx.outputs.filter(function(output, i) {
    var s = output.script;

    if (index != null && index !== i)
      return false;

    if (bcoin.script.isPubkey(s, key))
      return true;

    if (bcoin.script.isPubkeyhash(s, hash))
      return true;

    if (bcoin.script.isMultisig(s, keys))
      return true;

    if (scripthash) {
      if (bcoin.script.isScripthash(s, scripthash))
        return true;
    }

    return false;
  }, this);

  if (outputs.length === 0)
    return false;

  return outputs;
};

Address.prototype.ownInput = function ownInput(tx, index) {
  var scripthash = this.getScriptHash();
  var hash = this.getKeyHash();
  var key = this.getPublicKey();
  var redeem = this.getScript();
  var keys = this.keys;

  var inputs = tx.inputs.filter(function(input, i) {
    var s;

    if (!input.prevout.tx && this.tx._all[input.prevout.hash])
      input.prevout.tx = this.tx._all[input.prevout.hash];

    if (index != null && index !== i)
      return false;

    // if (bcoin.script.isPubkeyInput(input.script, key, tx, i))
    //   return true;

    if (bcoin.script.isPubkeyhashInput(input.script, key))
      return true;

    // if (bcoin.script.isMultisigInput(input.script, keys, tx, i))
    //   return true;

    if (redeem) {
      if (bcoin.script.isScripthashInput(input.script, redeem))
        return true;
    }

    if (!input.prevout.tx)
      return false;

    s = input.prevout.tx.getSubscript(input.prevout.index);

    if (bcoin.script.isPubkey(s, key))
      return true;

    if (bcoin.script.isPubkeyhash(s, hash))
      return true;

    if (bcoin.script.isMultisig(s, keys))
      return true;

    if (scripthash) {
      if (bcoin.script.isScripthash(s, scripthash))
        return true;
    }

    return false;
  }, this);

  if (inputs.length === 0)
    return false;

  return inputs;
};

Address.prototype.toJSON = function toJSON(encrypt) {
  return {
    v: 1,
    name: 'address',
    network: network.type,
    label: this.label,
    change: this.change,
    address: this.getKeyAddress(),
    scriptaddress: this.getScriptAddress(),
    key: this.key.toJSON(encrypt),
    type: this.type,
    subtype: this.subtype,
    redeem: this.redeem ? utils.toHex(this.redeem) : null,
    keys: this.keys.map(utils.toBase58),
    m: this.m,
    n: this.n
  };
};

Address.fromJSON = function fromJSON(json, decrypt) {
  var priv, pub, xprivkey, multisig, compressed, key, w;

  assert.equal(json.v, 1);
  assert.equal(json.name, 'address');

  if (json.network)
    assert.equal(json.network, network.type);

  w = new Address({
    label: json.label,
    change: json.change,
    key: bcoin.keypair.fromJSON(json.key, decrypt),
    multisig: multisig,
    type: json.type,
    subtype: json.subtype,
    redeem: json.redeem ? utils.toArray(json.redeem, 'hex') : null,
    keys: json.keys.map(utils.fromBase58),
    m: json.m,
    n: json.n
  });

  return w;
};

/**
 * Expose
 */

module.exports = Address;
