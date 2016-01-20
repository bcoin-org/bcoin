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
  this.compressed = options.compressed !== false;
  this.storage = options.storage;
  this.label = options.label || '';
  this.key = null;
  this.loaded = false;
  this.lastTs = 0;
  this.changeAddress = options.changeAddress || null;
  this.redeem = options.redeem || options.script;

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

  if (this.n > 1) {
    if (this.type !== 'multisig')
      this.type = 'scripthash';
    if (this.type === 'scripthash')
      this.subtype = 'multisig';
  }

  if (network.prefixes[this.type] == null)
    throw new Error('Unknown prefix: ' + this.type);

  this.nmax = this.type === 'scripthash'
    ? (this.compressed ? 15 : 7)
    : 3;

  if (this.m < 1 || this.m > this.n)
    throw new Error('m ranges between 1 and n');

  if (this.n < 1 || this.n > this.nmax)
    throw new Error('n ranges between 1 and ' + this.nmax);

  this.addKey(this.getPublicKey());

  (options.keys || []).forEach(function(key) {
    this.addKey(key);
  }, this);

  if (this.redeem) {
    if (!utils.isBytes(this.redeem))
      this.redeem = bcoin.script.encode(this.redeem);
    this.type = 'scripthash';
    this.subtype = null;
  }

  this.prefix = 'bt/wallet/' + this.getKeyAddress() + '/';

  this.tx = new bcoin.txPool(this);

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

Wallet.prototype.addKey = function addKey(key) {
  key = utils.toBuffer(key);

  var has = this.keys.some(function(k) {
    return utils.isEqual(k, key);
  });

  if (has)
    return;

  this.keys.push(key);

  this.keys = utils.sortKeys(this.keys);
};

Wallet.prototype.removeKey = function removeKey(key) {
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
};

Wallet.prototype.derive = function derive() {
  var options = this.options;

  if (!this.hd)
    throw new Error('Wallet is not HD');

  options.priv = this.hd.derive.apply(this.hd, arguments);

  return new Wallet(options);
};

Wallet.prototype.getPrivateKey = function getPrivateKey(enc) {
  var priv = this.key.getPrivate();
  var arr, chk;

  if (!priv)
    return;

  priv = priv.toArray();

  if (!enc)
    return priv;

  if (enc === 'base58')
    return Wallet.toSecret(priv, this.compressed);
  else if (enc === 'hex')
    return utils.toHex(priv);
  else
    return priv;
};

Wallet.toSecret = function toSecret(priv, compressed) {
  var arr, chk;

  // We'll be using ncompressed public key as an address
  arr = [network.prefixes.privkey];

  // 0-pad key
  while (arr.length + priv.length < 33)
    arr.push(0);

  arr = arr.concat(priv);

  if (compressed)
    arr.push(1);

  chk = utils.checksum(arr);

  return utils.toBase58(arr.concat(chk));
};

Wallet.fromSecret = function fromSecret(priv) {
  var key, compressed;

  key = bcoin.utils.fromBase58(priv);
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

  return {
    priv: priv,
    compressed: compressed
  };
};

Wallet.prototype.getScript = function getScript() {
  if (this.type !== 'scripthash')
    return;

  if (this.redeem)
    return this.redeem.slice();

  if (this.subtype === 'pubkey')
    return bcoin.script.encode([this.getPublicKey(), 'checksig']);

  if (this.subtype === 'pubkeyhash') {
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

Wallet.prototype.getScriptHash = function getScriptHash() {
  if (this.type !== 'scripthash')
    return;

  return utils.ripesha(this.getScript());
};

Wallet.prototype.getScriptAddress = function getScriptAddress() {
  if (this.type !== 'scripthash')
    return;

  return Wallet.hash2addr(this.getScriptHash(), this.type);
};

Wallet.prototype.getPublicKey = function getPublicKey(enc) {
  var pub = this.key.getPublic(this.compressed, 'array');

  if (enc === 'base58')
    return utils.toBase58(pub);
  else if (enc === 'hex')
    return utils.toHex(pub);
  else
    return pub;
};

Wallet.prototype.getKeyHash = function getKeyHash() {
  return Wallet.key2hash(this.getPublicKey());
};

Wallet.prototype.getKeyAddress = function getKeyAddress() {
  return Wallet.hash2addr(this.getKeyHash(), 'pubkeyhash');
};

Wallet.prototype.getHash = function getHash() {
  if (this.type === 'scripthash')
    return this.getScriptHash();
  return this.getKeyHash();
};

Wallet.prototype.getAddress = function getAddress() {
  if (this.type === 'scripthash')
    return this.getScriptAddress();
  return this.getKeyAddress();
};

Wallet.key2hash = function key2hash(key) {
  key = utils.toBuffer(key);
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

Wallet.validateAddress = function validateAddress(addr, prefix) {
  if (!addr)
    return false;

  var p = Wallet.addr2hash(addr, prefix);

  return p.length !== 0;
};

Wallet.prototype.ownOutput = function ownOutput(tx, index) {
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

Wallet.prototype.ownInput = function ownInput(tx, index) {
  var scripthash = this.getScriptHash();
  var hash = this.getKeyHash();
  var key = this.getPublicKey();
  var redeem = this.getScript();
  var keys = this.keys;

  var inputs = tx.inputs.filter(function(input, i) {
    var s;

    if (!input.out.tx && this.tx._all[input.out.hash])
      input.out.tx = this.tx._all[input.out.hash];

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

    if (!input.out.tx)
      return false;

    s = input.out.tx.getSubscript(input.out.index);

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

Wallet.prototype.fillUnspent = function fillUnspent(tx, address, fee) {
  if (!address)
    address = this.changeAddress || this.getAddress();

  return tx.fillUnspent(this.unspent(), address, fee);
};

Wallet.prototype.fillTX = function fillTX(tx) {
  return tx.fill(this);
};

Wallet.prototype.scriptInputs = function scriptInputs(tx) {
  var pub = this.getPublicKey();
  var redeem = this.getScript();
  var inputs = tx.inputs;

  inputs = inputs.filter(function(input, i) {
    if (!input.out.tx && this.tx._all[input.out.hash])
      input.out.tx = this.tx._all[input.out.hash];

    if (!input.out.tx || !this.ownOutput(input.out.tx))
      return false;

    tx.scriptInput(i, pub, redeem);

    return true;
  }, this);

  return inputs.length;
};

Wallet.prototype.signInputs = function signInputs(tx, type) {
  var key = this.key;
  var inputs = tx.inputs;

  inputs = inputs.filter(function(input, i) {
    if (!input.out.tx && this.tx._all[input.out.hash])
      input.out.tx = this.tx._all[input.out.hash];

    if (!input.out.tx || !this.ownOutput(input.out.tx))
      return false;

    tx.signInput(i, key, type);

    return true;
  }, this);

  return inputs.length;
};

Wallet.prototype.sign = function sign(tx, type) {
  var pub = this.getPublicKey();
  var redeem = this.getScript();
  var key = this.key;
  var inputs = tx.inputs;

  // Add signature script to each input
  inputs = inputs.filter(function(input, i) {
    if (!input.out.tx && this.tx._all[input.out.hash])
      input.out.tx = this.tx._all[input.out.hash];

    // Filter inputs that this wallet own
    if (!input.out.tx || !this.ownOutput(input.out.tx))
      return false;

    tx.scriptSig(i, key, pub, redeem, type);

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

Wallet.prototype.fill = function fill(tx, changeAddress, cb) {
  var result, err;

  if (typeof changeAddress === 'function') {
    cb = changeAddress;
    changeAddress = null;
  }

  cb = utils.asyncify(cb);

  result = this.fillUnspent(tx, changeAddress);

  if (!result.inputs) {
    err = new Error('Not enough funds');
    err.minBalance = result.total;
    cb(err);
    return null;
  }

  this.sign(tx);

  cb(null, tx);

  return tx;
};

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
    balance: this.balance(),
    txs: txs
  };
};

Wallet.prototype.toJSON = function toJSON(encrypt) {
  return {
    v: 2,
    name: 'wallet',
    network: network.type,
    encrypted: encrypt ? true : false,
    label: this.label,
    address: this.getKeyAddress(),
    scriptaddress: this.getScriptAddress(),
    balance: utils.toBTC(this.balance()),
    pub: this.getPublicKey('hex'),
    priv: encrypt
      ? encrypt(this.getPrivateKey('base58'))
      : this.getPrivateKey('base58'),
    xprivkey: this.hd
      ? (encrypt ? encrypt(this.hd.xprivkey) : this.hd.xprivkey)
      : null,
    type: this.type,
    subtype: this.subtype,
    redeem: this.redeem ? utils.toHex(this.redeem) : null,
    keys: this.keys.map(utils.toBase58),
    m: this.m,
    n: this.n,
    tx: this.tx.toJSON()
  };
};

Wallet.fromJSON = function fromJSON(json, decrypt) {
  var priv, pub, xprivkey, multisig, compressed, key, w;

  assert.equal(json.v, 2);
  assert.equal(json.name, 'wallet');

  if (json.network)
    assert.equal(json.network, network.type);

  if (json.encrypted && !decrypt)
    throw new Error('Cannot decrypt wallet');

  if (json.priv) {
    priv = json.priv;
    if (json.encrypted)
      priv = decrypt(priv);

    key = Wallet.fromSecret(json.priv);
    priv = key.priv;
    compressed = key.compressed;
  } else {
    pub = bcoin.utils.toArray(json.pub, 'hex');
    compressed = pub[0] !== 0x04;
  }

  if (json.xprivkey) {
    xprivkey = json.xprivkey;
    if (json.encrypted)
      xprivkey = decrypt(xprivkey);
    priv = bcoin.hd.priv(xprivkey);
  }

  w = new Wallet({
    label: json.label,
    priv: priv,
    pub: pub,
    compressed: compressed,
    multisig: multisig,
    type: json.type,
    subtype: json.subtype,
    redeem: json.redeem ? utils.toArray(json.redeem, 'hex') : null,
    keys: json.keys.map(utils.fromBase58),
    m: json.m,
    n: json.n
  });

  w.tx.fromJSON(json.tx);

  return w;
};

/**
 * Expose
 */

module.exports = Wallet;
