var bcoin = require('../bcoin');
var hash = require('hash.js');
var bn = require('bn.js');
var inherits = require('inherits');
var EventEmitter = require('events').EventEmitter;
var utils = bcoin.utils;
var assert = utils.assert;
var constants = bcoin.protocol.constants;

function Wallet(options, passphrase) {
  if (!(this instanceof Wallet))
    return new Wallet(options, passphrase);

  EventEmitter.call(this);

  // bcoin.wallet('scope', 'password')
  if (typeof options === 'string' && typeof passphrase === 'string') {
    options = {
      scope: options,
      passphrase: passphrase
    };
  }
  if (!options)
    options = {};

  this.compressed = typeof options.compressed !== 'undefined' ?
      options.compressed : true;
  this.storage = options.storage;
  this.key = null;
  this.loaded = false;
  this.lastTs = 0;
  this.sharedKeys = options.sharedKeys;

  if (options.priv instanceof bcoin.hd.priv) {
    this.hd = options.priv;
    this.key = this.hd.pair;
  } else if (options.pub instanceof bcoin.hd.pub) {
    this.hd = options.pub;
    this.key = this.hd.pair;
  } else if (options.hd) {
    this.hd = bcoin.hd.priv(options);
    this.key = this.hd.pair;
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

  this.addressType = options.addressType || 'normal';

  // Multisig
  this.sharedKeys = (options.sharedKeys || []).map(utils.toKeyArray);
  this.m = options.m || 1;
  this.n = options.n || 1;

  // Use p2sh multisig by default
  if (!options.addressType && this.sharedKeys.length) {
    this.addressType = 'p2sh';
  }

  if (this.m < 1 || this.m > this.n) {
    throw new Error('m ranges between 1 and n');
  }

  if (this.n < 1 || this.n > 7) {
    throw new Error('n ranges between 1 and 7');
  }

  if (this.sharedKeys.length !== this.m - 1) {
    throw new Error(this.m + ' public keys required');
  }

  this.prefix = 'bt/' + this.getAddress() + '/';
  this.tx = new bcoin.txPool(this);

  // Just a constants, actually
  this.fee = 10000;
  this.dust = 5460;

  this._init();
}
inherits(Wallet, EventEmitter);
module.exports = Wallet;

Wallet.prototype._init = function init() {
  if (this.tx._loaded) {
    this.loaded = true;
    return;
  }

  // Notify owners about new accepted transactions
  var self = this;
  var prevBalance = null;
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

Wallet.prototype.getPrivateKey = function getPrivateKey(enc) {
  var priv = this.key.getPrivate();
  if (priv)
    priv = priv.toArray();
  else
    return;
  if (!enc)
    return priv;

  if (enc === 'base58') {
    // We'll be using ncompressed public key as an address
    var arr = [ 128 ];

    // 0-pad key
    while (arr.length + priv.length < 33)
      arr.push(0);
    arr = arr.concat(priv);
    if (this.compressed)
      arr.push(1);
    var chk = utils.checksum(arr);
    return utils.toBase58(arr.concat(chk));
  } else {
    return priv;
  }
};

Wallet.prototype.getPublicKey = function getPublicKey(enc) {
  var pub;
  if (this.addressType === 'p2sh')
    pub = this.getRedemption();
  else
    pub = this.key.getPublic(this.compressed, 'array');

  if (enc === 'base58')
    return utils.toBase58(pub);
  else if (enc === 'hex')
    return utils.toHex(pub);
  else
    return pub;
};

Wallet.prototype.getHash = function getHash() {
  return utils.ripesha(this.getPublicKey());
};

Wallet.prototype.getAddress = function getAddress() {
  return Wallet.hash2addr(this.getHash(), this.addressType);
};

Wallet.hash2addr = function hash2addr(hash, version) {
  hash = utils.toArray(hash, 'hex');

  version = constants.addr[version || 'normal'];
  hash = [ version ].concat(hash);

  var addr = hash.concat(utils.checksum(hash));
  return utils.toBase58(addr);
};

Wallet.addr2hash = function addr2hash(addr, version) {
  if (!Array.isArray(addr))
    addr = utils.fromBase58(addr);

  version = constants.addr[version || 'normal'];

  if (addr.length !== 25)
    return [];
  if (addr[0] !== version)
    return [];

  var chk = utils.checksum(addr.slice(0, -4));
  if (utils.readU32(chk, 0) !== utils.readU32(addr, 21))
    return [];

  return addr.slice(1, -4);
};

Wallet.prototype.validateAddress = function validateAddress(addr, version) {
  var p = Wallet.addr2hash(addr, version);
  return p.length !== 0;
};
Wallet.validateAddress = Wallet.prototype.validateAddress;

Wallet.prototype.ownOutput = function ownOutput(tx, index) {
  var hash = this.getHash();
  var key = this.getPublicKey();

  var outputs = tx.outputs.filter(function(output, i) {
    if (index !== undefined && index !== i)
      return false;

    var s = output.script;

    if (bcoin.script.isPubkeyhash(s, hash))
      return true;

    if (bcoin.script.isSimplePubkeyhash(s, hash))
      return true;

    if (bcoin.script.isMultisig(s, key))
      return true;

    if (bcoin.script.isScripthash(s, hash))
      return true;

    return false;
  }, this);
  if (outputs.length === 0)
    return false;

  return outputs;
};

Wallet.prototype.ownInput = function ownInput(tx, index) {
  var hash = this.getHash();
  var key = this.getPublicKey();

  var inputs = tx.inputs.filter(function(input, i) {
    if (index !== undefined && index !== i)
      return false;

    if (bcoin.script.isPubkeyhashInput(input.script) &&
        utils.isEqual(input.script[1], key))
      return true;

    if (!input.out.tx)
      return false;

    var s = input.out.tx.outputs[input.out.index].script;
    if (bcoin.script.isPubkeyhash(s, hash))
      return true;

    if (bcoin.script.isMultisig(s, key))
      return true;

    if (bcoin.script.isScripthash(s, hash))
      return true;

    return false;
  }, this);
  if (inputs.length === 0)
    return false;

  return inputs;
};

Wallet.prototype.sign = function sign(tx, type, inputs, off) {
  if (!type)
    type = 'all';

  if (!off)
    off = 0;

  var pub = this.getPublicKey();
  inputs = inputs || tx.inputs;

  // Add signature script to each input
  inputs = inputs.filter(function(input, i) {
    // Filter inputs that this wallet own
    if (!input.out.tx || !this.ownOutput(input.out.tx))
      return false;

    // Get the previous output's subscript
    var s = input.out.tx.getSubscript(input.out.index);

    // Get the hash of the current tx, minus the other inputs, plus the sighash.
    // `off` is used here in a case where we have multiple wallet objects
    // signing the same tx.
    var hash = tx.subscriptHash(off + i, s, type);

    // Sign the transaction with our one input
    var signature = bcoin.ecdsa.sign(hash, this.key).toDER();

    // Add the sighash as a single byte to the signature
    signature = signature.concat(bcoin.protocol.constants.hashType[type]);

    // P2PKH and simple tx
    if (bcoin.script.isPubkeyhash(s) || bcoin.script.isSimplePubkeyhash(s)) {
      input.script = [ signature, pub ];
      return true;
    }

    // Multisig
    // empty array == OP_FALSE == OP_0
    // raw format: OP_FALSE [sig-1] [sig-2] ...
    // p2sh format: OP_FALSE [sig-1] [sig-2] ... [redeem-script]
    if (bcoin.script.isMultisig(s) || bcoin.script.isScripthash(s)) {
      if (!input.script || !input.script.length) {
        input.script = [ [], signature ];
      } else if (!~input.script.indexOf(signature)) {
        input.script.push(signature);
      }
    }

    // P2SH requires a redeem script after signatures
    if (bcoin.script.isScripthash(s)) {
      if (input.script.length - 1 === this.m) {
        input.script.push(this.getRedemption());
      }
    }

    return true;
  }, this);

  return inputs.length;
};

Wallet.prototype.sign = function sign(tx, type, inputs) {
  if (!type)
    type = 'all';

  var pub = this.getPublicKey();
  var key = this.key;
  var nsigs = this.m;

  inputs = inputs || tx.inputs;

  // Add signature script to each input
  inputs = inputs.filter(function(input) {
    // Filter inputs that this wallet own
    if (!input.out.tx || !this.ownOutput(input.out.tx))
      return false;

    tx.scriptSig(input, key, pub, nsigs);

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
  cb = utils.asyncify(cb);

  // NOTE: tx should be prefilled with all outputs
  var cost = tx.funds('out');

  // Use initial fee for starters
  var fee = 1;

  // total = cost + fee
  var total = cost.add(new bn(this.fee));

  var lastAdded = 0;
  function addInput(unspent, i) {
    // Add new inputs until TX will have enough funds to cover both
    // minimum post cost and fee
    tx.input(unspent);
    lastAdded++;
    return tx.funds('in').cmp(total) < 0;
  }

  // Transfer `total` funds maximum
  var unspent = this.unspent();
  unspent.every(addInput, this);

  // Add dummy output (for `left`) to calculate maximum TX size
  tx.out(this, new bn(0));

  // Change fee value if it is more than 1024 bytes
  // (10000 satoshi for every 1024 bytes)
  do {
    // Calculate maximum possible size after signing
    var byteSize = tx.maxSize();

    var addFee = Math.ceil(byteSize / 1024) - fee;
    total.iadd(new bn(addFee * this.fee));
    fee += addFee;

    // Failed to get enough funds, add more inputs
    if (tx.funds('in').cmp(total) < 0)
      unspent.slice(lastAdded).every(addInput, this);
  } while (tx.funds('in').cmp(total) < 0 && lastAdded < unspent.length);

  // Still failing to get enough funds, notify caller
  if (tx.funds('in').cmp(total) < 0) {
    var err = new Error('Not enough funds');
    err.minBalance = total;
    return cb(err);
  }

  // How much money is left after sending outputs
  var left = tx.funds('in').sub(total);

  // Not enough money, transfer everything to owner
  if (left.cmpn(this.dust) < 0) {
    // NOTE: that this output is either `postCost` or one of the `dust` values
    tx.outputs[tx.outputs.length - 2].value.iadd(left);
    left = new bn(0);
  }

  // Change or remove last output if there is some money left
  if (left.cmpn(0) === 0)
    tx.outputs.pop();
  else
    tx.outputs[tx.outputs.length - 1].value = left;

  // Sign transaction
  // XXX Do not necessarily call this here
  this.sign(tx);

  cb(null, tx);

  return tx;
};

// P2SH Multisig redeem script
Wallet.prototype.getRedemption = function() {
  var sharedKeys = this.sharedKeys.slice().map(utils.toKeyArray);
  if (sharedKeys.length < this.m) {
    var pub = this.key.getPublic(this.compressed, 'array');
    sharedKeys.push(pub);
  }
  return bcoin.script.redemption(sharedKeys, m, n);
};

Wallet.prototype.toJSON = function toJSON() {
  return {
    v: 1,
    type: 'wallet',
    pub: utils.toBase58(this.key.getPublic(this.compressed, 'array')),
    priv: this.getPrivateKey('base58'),
    tx: this.tx.toJSON(),
    addressType: this.addressType,
    sharedKeys: utils.toBase58(this.sharedKeys),
    m: this.m,
    n: this.n
  };
};

Wallet.fromJSON = function fromJSON(json) {
  assert.equal(json.v, 1);
  assert.equal(json.type, 'wallet');

  var priv;
  var pub;
  var compressed;

  if (json.priv) {
    var key = bcoin.utils.fromBase58(json.priv);
    assert(utils.isEqual(key.slice(-4), utils.checksum(key.slice(0, -4))));
    assert.equal(key[0], 128);

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

  var w = new Wallet({
    priv: priv,
    pub: pub,
    compressed: compressed,
    addressType: json.addressType,
    sharedKeys: json.sharedKeys,
    m: json.m,
    n: json.n
  });

  w.tx.fromJSON(json.tx);

  return w;
};
