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

function Wallet(options, passphrase) {
  if (!(this instanceof Wallet))
    return new Wallet(options, passphrase);

  EventEmitter.call(this);

  if (typeof options === 'string' && typeof passphrase === 'string') {
    options = {
      scope: options,
      passphrase: passphrase
    };
  }

  if (!options)
    options = {};

  this.options = options;
  this.compressed = typeof options.compressed !== 'undefined'
    ? options.compressed
    : true;
  this.storage = options.storage;
  this.label = options.label || '';
  this.key = null;
  this.loaded = false;
  this.lastTs = 0;

  if (options.priv instanceof bcoin.hd.priv) {
    this.hd = options.priv;
    this.key = this.hd;
  } else if (options.pub instanceof bcoin.hd.pub) {
    this.hd = options.pub;
    this.key = this.hd;
  } else if (options.hd) {
    this.hd = typeof options.hd === 'object'
      ? bcoin.hd.priv(options.hd)
      : bcoin.hd.priv();
    this.key = this.hd;
  } else if (options.key) {
    if ((options.key instanceof bcoin.hd.priv)
        || (options.key instanceof bcoin.hd.pub)) {
      this.hd = options.key;
      this.key = options.key;
    } else {
      this.key = options.key;
    }
  } else if (options.passphrase) {
    this.key = bcoin.ecdsa.genKeyPair({
      pers: options.scope,
      entropy: hash.sha256().update(options.passphrase).digest()
    });
  } else if (options.priv || options.pub) {
    this.key = bcoin.ecdsa.keyPair({
      priv: options.priv,
      pub: options.pub
    });
  } else {
    this.key = bcoin.ecdsa.genKeyPair();
  }

  this.type = 'pubkeyhash';
  this.keys = [];
  this.m = 1;
  this.n = 1;

  this.multisig(options.multisig || {});

  this.prefix = 'bt/' + this.getOwnAddress() + '/';
  this.tx = new bcoin.txPool(this);

  // Just a constants, actually
  this.fee = 10000;
  this.dust = 5460;

  this._init();
}

inherits(Wallet, EventEmitter);

Wallet.prototype._init = function init() {
  var self = this;
  var prevBalance = null;

  if (this.tx._loaded) {
    this.loaded = true;
    return;
  }

  // Notify owners about new accepted transactions
  this.tx.on('update', function(lastTs, tx) {
    var b = this.balance();
    if (prevBalance && prevBalance.cmp(b) !== 0)
      self.emit('balance', b);
    self.emit('update', tx);
    prevBalance = b;
  });

  this.tx.on('tx', function(tx) {
    self.emit('tx', tx);
  });

  this.tx.once('load', function(ts) {
    self.loaded = true;
    self.lastTs = ts;
    self.emit('load', ts);
  });

  this.tx.on('error', function(err) {
    self.emit('error', err);
  });
};

Wallet.prototype.multisig = function multisig(options) {
  var pub = this.getOwnPublicKey();

  options.type = options.type || options.prefix;
  options.keys = options.keys || options.pubkeys || [];

  this.type = options.type || 'pubkeyhash';
  // this.keys = (options.keys || []).map(utils.toKeyArray);
  this.keys = [];
  this.m = options.m || 1;
  this.n = options.n || 1;
  this.nmax = this.type === 'scripthash'
    ? (this.compressed ? 15 : 7)
    : 3;

  this.addKey(pub);

  if (network.prefixes[this.type] == null)
    throw new Error('Unknown prefix: ' + this.type);

  options.keys.forEach(function(key) {
    this.addKey(key);
  }, this);

  // Use p2sh multisig by default
  if (!options.type && this.keys.length > 1)
    this.type = 'scripthash';

  if (this.m < 1 || this.m > this.n)
    throw new Error('m ranges between 1 and n');

  if (this.n < 1 || this.n > this.nmax)
    throw new Error('n ranges between 1 and ' + this.nmax);

  if (this.keys.length > this.n)
    throw new Error('No more than ' + this.n + ' are necessary');
};

Wallet.prototype.addKey = function addKey(key) {
  key = utils.toKeyArray(key);

  var has = this.keys.some(function(k) {
    return utils.isEqual(k, key);
  });

  if (has)
    return;

  this.keys.push(key);

  this.keys = utils.sortKeys(this.keys);
};

Wallet.prototype.removeKey = function removeKey(key) {
  key = utils.toKeyArray(key);

  var index = this.keys.map(function(key, i) {
    return utils.isEqual(key, pub) ? i : null;
  }).filter(function(i) {
    return i !== null;
  })[0];

  if (index == null)
    return;

  this.keys.splice(index, 1);

  this.keys = utils.sortKeys(this.keys);
};

Wallet.prototype.derive = function derive() {
  var options = this.options;

  if (!this.hd)
    throw new Error('Wallet is not HD');

  options.priv = this.hd.derive.apply(this.hd, arguments);

  return bcoin.wallet(options);
};

Wallet.prototype.getPrivateKey = function getPrivateKey(enc) {
  var priv = this.key.getPrivate();
  var arr, chk;

  if (priv)
    priv = priv.toArray();
  else
    return;

  if (!enc)
    return priv;

  if (enc === 'base58') {
    // We'll be using ncompressed public key as an address
    arr = [ network.prefixes.privkey ];

    // 0-pad key
    while (arr.length + priv.length < 33)
      arr.push(0);

    arr = arr.concat(priv);

    if (this.compressed)
      arr.push(1);

    chk = utils.checksum(arr);

    return utils.toBase58(arr.concat(chk));
  }

  return priv;
};

Wallet.prototype.getFullPublicKey = function getFullPublicKey(enc) {
  var pub = this.getOwnPublicKey();
  var keys;

  if (this.type === 'scripthash') {
    keys = this.getPublicKeys();
    pub = bcoin.script.encode(bcoin.script.multisig(keys, this.m, this.n));
  }

  if (enc === 'base58')
    return utils.toBase58(pub);
  else if (enc === 'hex')
    return utils.toHex(pub);
  else
    return pub;
};

Wallet.prototype.getOwnPublicKey = function getOwnPublicKey(enc) {
  var pub = this.key.getPublic(this.compressed, 'array');

  if (enc === 'base58')
    return utils.toBase58(pub);
  else if (enc === 'hex')
    return utils.toHex(pub);
  else
    return pub;
};

Wallet.prototype.getPublicKey = function getPublicKey(enc) {
  return this.getFullPublicKey(enc);
};

Wallet.prototype.getPublicKeys = function getPublicKeys() {
  var keys = this.keys.slice().map(utils.toKeyArray);

  keys = utils.sortKeys(keys);

  return keys;
};

Wallet.prototype.getFullHash = function getFullHash() {
  return Wallet.key2hash(this.getFullPublicKey());
};

Wallet.prototype.getFullAddress = function getFullAddress() {
  return Wallet.hash2addr(this.getFullHash(), this.type);
};

Wallet.prototype.getOwnHash = function getOwnHash() {
  return Wallet.key2hash(this.getOwnPublicKey());
};

Wallet.prototype.getOwnAddress = function getOwnAddress() {
  return Wallet.hash2addr(this.getOwnHash(), this.type);
};

Wallet.prototype.getHash = function getHash() {
  return Wallet.key2hash(this.getFullPublicKey());
};

Wallet.prototype.getAddress = function getAddress() {
  return Wallet.hash2addr(this.getFullHash(), this.type);
};

Wallet.key2hash = function key2hash(key) {
  if (typeof key === 'string')
    key = utils.toArray(key, 'hex');
  return utils.ripesha(key);
};

Wallet.hash2addr = function hash2addr(hash, prefix) {
  var addr;

  hash = utils.toArray(hash, 'hex');

  prefix = network.prefixes[prefix || 'pubkeyhash'];
  hash = [ prefix ].concat(hash);

  addr = hash.concat(utils.checksum(hash));

  return utils.toBase58(addr);
};

Wallet.__defineGetter__('prefixes', function() {
  if (Wallet._prefixes) return Wallet._prefixes;
  Wallet._prefixes = ['pubkeyhash', 'scripthash'].reduce(function(out, prefix) {
    var ch = Wallet.hash2addr(Wallet.key2hash([]), prefix)[0];
    out[ch] = prefix;
    return out;
  }, {});
  return Wallet._prefixes;
});

Wallet.addr2hash = function addr2hash(addr, prefix) {
  var chk;

  if (prefix == null && typeof addr === 'string')
    prefix = Wallet.prefixes[addr[0]];

  if (!Array.isArray(addr))
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

Wallet.prototype.validateAddress = function validateAddress(addr, prefix) {
  if (!addr)
    return false;
  var p = Wallet.addr2hash(addr, prefix);
  return p.length !== 0;
};
Wallet.validateAddress = Wallet.prototype.validateAddress;

Wallet.prototype.ownOutput = function ownOutput(tx, index) {
  var scriptHash = this.getFullHash();
  var hash = this.getOwnHash();
  var key = this.getOwnPublicKey();
  var keys = this.getPublicKeys();

  var outputs = tx.outputs.filter(function(output, i) {
    var s = output.script;

    if (index !== undefined && index !== i)
      return false;

    if (bcoin.script.isPubkey(s, key))
      return true;

    if (bcoin.script.isPubkeyhash(s, hash))
      return true;

    if (bcoin.script.isMultisig(s, keys))
      return true;

    if (bcoin.script.isScripthash(s, scriptHash))
      return true;

    return false;
  }, this);

  if (outputs.length === 0)
    return false;

  return outputs;
};

Wallet.prototype.ownInput = function ownInput(tx, index) {
  var scriptHash = this.getFullHash();
  var hash = this.getOwnHash();
  var key = this.getOwnPublicKey();
  var redeem = this.getFullPublicKey();
  var keys = this.getPublicKeys();

  var inputs = tx.inputs.filter(function(input, i) {
    var s;

    if (index !== undefined && index !== i)
      return false;

    // if (bcoin.script.isPubkeyInput(input.script, key, tx, i))
    //   return true;

    if (bcoin.script.isPubkeyhashInput(input.script, key))
      return true;

    if (bcoin.script.isScripthashInput(input.script, redeem))
      return true;

    // if (bcoin.script.isMultisigInput(input.script, key, tx, i))
    //   return true;

    if (!input.out.tx)
      return false;

    s = input.out.tx.outputs[input.out.index].script;

    if (bcoin.script.isPubkey(s, key))
      return true;

    if (bcoin.script.isPubkeyhash(s, hash))
      return true;

    if (bcoin.script.isMultisig(s, keys))
      return true;

    if (bcoin.script.isScripthash(s, scriptHash))
      return true;

    return false;
  }, this);

  if (inputs.length === 0)
    return false;

  return inputs;
};

Wallet.prototype.scriptOutputs = function scriptOutputs(tx, options, outputs) {
  options = options || {};

  if (this.n > 1) {
    options.keys = this.keys;
    options.m = this.m || 1;
    options.n = this.n || 1;
  }

  outputs = outputs || tx.outputs;

  outputs.forEach(function(output) {
    tx.scriptOutput(output, options);
  });

  return outputs.length;
};

Wallet.prototype.fillUnspent = function fillUnspent(tx, unspent, change) {
  return tx.fillUnspent(tx, unspent, change);
};

Wallet.prototype.scriptInputs = function scriptInputs(tx, inputs) {
  var pub = this.getFullPublicKey();

  inputs = inputs || tx.inputs;

  inputs = inputs.filter(function(input) {
    // Filter inputs that this wallet own
    if (!input.out.tx || !this.ownOutput(input.out.tx))
      return false;

    tx.scriptInput(input, pub);

    return true;
  }, this);

  return inputs.length;
};

Wallet.prototype.signInputs = function signInputs(tx, type, inputs) {
  var key = this.key;

  if (!type)
    type = 'all';

  inputs = inputs || tx.inputs;

  inputs = inputs.filter(function(input) {
    if (!input.out.tx || !this.ownOutput(input.out.tx))
      return false;

    tx.signInput(input, key, type);

    return true;
  }, this);

  return inputs.length;
};

Wallet.prototype.sign = function sign(tx, type, inputs) {
  if (!type)
    type = 'all';

  var pub = this.getFullPublicKey();
  var key = this.key;

  inputs = inputs || tx.inputs;

  // Add signature script to each input
  inputs = inputs.filter(function(input) {
    // Filter inputs that this wallet own
    if (!input.out.tx || !this.ownOutput(input.out.tx))
      return false;

    tx.scriptSig(input, key, pub, type);

    return true;
  }, this);

  return inputs.length;
};

Wallet.prototype.addTX = function addTX(tx, block) {
  return this.tx.add(tx);
};

Wallet.prototype.all = function all() {
  return this.tx.all();
};

Wallet.prototype.unspent = function unspent() {
  return this.tx.unspent();
};

Wallet.prototype.pending = function pending() {
  return this.tx.pending();
};

Wallet.prototype.balance = function balance() {
  return this.tx.balance();
};

Wallet.prototype.fill = function fill(tx, cb) {
  var result = tx.fillUnspent(this.unspent(), this.getAddress());
  var err;

  cb = utils.asyncify(cb);

  if (!result) {
    err = new Error('Not enough funds');
    err.minBalance = tx.total;
    cb(err);
    return null;
  }

  this.sign(tx);

  cb(null, tx);

  return tx;
};

Wallet.prototype.toJSON = function toJSON(encrypt) {
  return {
    v: 1,
    type: 'wallet',
    network: network.type,
    encrypted: encrypt ? true : false,
    label: this.label,
    address: this.getAddress(),
    balance: utils.toBTC(this.balance()),
    pub: this.getOwnPublicKey('base58'),
    priv: encrypt
      ? encrypt(this.getPrivateKey('base58'))
      : this.getPrivateKey('base58'),
    tx: this.tx.toJSON(),
    ntx: this.tx.all().length,
    hd: this.hd ? {
      // seed: this.hd.seed ? {
      //   mnemonic: this.hd.seed.mnemonic,
      //   passphrase: this.hd.seed.passphrase
      // } : undefined,
      depth: this.hd.data.depth,
      parentFingerPrint: utils.toHex(this.hd.data.parentFingerPrint),
      childIndex: this.hd.data.childIndex,
      chainCode: utils.toHex(this.hd.data.chainCode)
    } : undefined,
    multisig: this.n > 1 ? {
      type: this.type,
      keys: this.keys.map(utils.toHex),
      m: this.m,
      n: this.n
    } : undefined
  };
};

Wallet.fromJSON = function fromJSON(json, decrypt) {
  assert.equal(json.v, 1);
  assert.equal(json.type, 'wallet');

  if (json.network)
    assert.equal(json.network, network.type);

  if (json.encrypted && decrypt)
    json.priv = decrypt(json.priv);

  var priv, pub, compressed, key, w;

  if (json.priv) {
    key = bcoin.utils.fromBase58(json.priv);
    assert(utils.isEqual(key.slice(-4), utils.checksum(key.slice(0, -4))));
    assert.equal(key[0], network.prefixes.privkey);

    key = key.slice(0, -4);
    if (key.length === 34) {
      assert.equal(key[33], 1);
      priv = key.slice(1, -1);
      compressed = true;
    } else {
      priv = key.slice(1);
      compressed = false;
    }
  } else {
    pub = bcoin.utils.fromBase58(json.pub);
    compressed = pub[0] !== 0x04;
  }

  if (json.multisig)
    json.multisig.keys = json.multisig.keys.map(utils.toKeyArray);

  if (json.hd) {
    json.hd.privateKey = priv;
    priv = new hd.priv(json.hd);
  }

  w = new Wallet({
    label: json.label,
    priv: priv,
    pub: pub,
    compressed: compressed,
    multisig: json.multisig
  });

  w.tx.fromJSON(json.tx);

  return w;
};

/**
 * Expose
 */

module.exports = Wallet;
