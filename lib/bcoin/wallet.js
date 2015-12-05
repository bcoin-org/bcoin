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
  this.publicKeys = options.publicKeys;

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
    this.key = bcoin.ecdsa.keyPair(options.priv || options.pub, 'hex');
  } else {
    this.key = bcoin.ecdsa.genKeyPair();
  }

  this.prefix = 'bt/' + this.getAddress() + '/';
  this.tx = new bcoin.txPool(this);

  // Just a constants, actually
  this.fee = 10000;
  this.dust = 5460;

  if (options.m != null) {
    this.m = options.m;
    this.n = options.n;
    this.publicKeys = options.publicKeys || [];

    if (this.n < this.publicKeys.length) {
      this.publicKeys.push(this.getPublicKey('base58'));
    }

    if (this.m < 1 || this.m > this.n) {
      throw new Error('m ranges between 1 and n');
    }
    if (this.n < 1 || this.n > 7) {
      throw new Error('n ranges between 1 and 7');
    }
    if (this.publicKeys.length !== this.n) {
      throw new Error(this.n + ' public keys required');
    }
  }

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
  var pub = this.key.getPublic(this.compressed, 'array');
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
  return Wallet.hash2addr(this.getHash());
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

Wallet.validAddress = function validAddr(addr, version) {
  if (!addr)
    return false;

  return !!Wallet.addr2hash(addr, version).length;
};

Wallet.prototype.validateAddress = function validateAddress(addr) {
  var p = Wallet.addr2hash(addr);
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

    if (bcoin.script.isScripthash(s)
        && utils.isEqual(s[1], this.getP2SHHash())) {
      return true;
    }

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

    if (bcoin.script.isScripthash(s)
        && utils.isEqual(s[1], this.getP2SHHash())) {
      return true;
    }

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
      // XXX Check own?
      // || (bcoin.script.isScripthash(s) && utils.isEqual(s[1], this.getP2SHHash())) {
      if (!input.script || !input.script.length) {
        input.script = [ [], signature ];
      } else if (!~input.script.indexOf(signature)) {
        input.script.push(signature);
      }
    }

    // P2SH requires a redeem script after signatures
    if (bcoin.script.isScripthash(s)) {
      if (input.script.length - 1 === this.n) {
        input.script.push(this.getP2SHRedemption());
      }
    }

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

Wallet.prototype.fill = function fill(tx, options, cb) {
  if ((cb && typeof cb === 'object') || options == null) {
    cb = options;
    options = {};
  }
  cb = utils.asyncify(cb);

  if (options._getChange) {
    tx = tx.clone();
  }

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
  tx.out(options.change || this, new bn(0));

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

  if (options._getChange) {
    return left;
  }

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
  if (options.sign === false) {
    this.signEmpty(tx);
  } else {
    this.sign(tx);
  }

  cb(null, tx);

  return tx;
};

Wallet.prototype.getChange = function fill(tx) {
  return this.fill(tx, { _getChange: true });
};

/**
 * P2SH (and Multisig)
 */

Wallet.prototype.getP2SHHash = function() {
  return this.getP2SH().hash;
};

Wallet.prototype.getP2SHAddress = function() {
  return this.getP2SH().address;
};

Wallet.prototype.getP2SHRedemption = function() {
  return this.getP2SH().redemption;
};

Wallet.prototype.getP2SH = function(redeem) {
  this.publicKeys = this.publicKeys.map(function(key) {
    return utils.toKeyArray(key);
  });
  var redemption = redeem || this._createMultisigRedemption();
  var hash = utils.ripasha(redemption);
  return {
    hash: hash,
    address: Wallet.hash2addr(hash, 'p2sh'),
    redemption: redemption
  };
};

Wallet.prototype._createMultisigRedemption = function() {
  var publicKeys = this.publicKeys;
  var mcode = constants.opcodes['1'] + (this.m - 1);
  var ncode = constants.opcodes['1'] + (this.n - 1);
  var redemption = [];
  redemption.push(mcode);
  this.publicKeys.forEach(function(pubkey) {
    redemption.push(pubkey.length);
    redemption = redemption.concat(pubkey);
  }, this);
  redemption.push(ncode);
  redemption.push(constants.opcodes.checkmultisig);
  return redemption;
};

Wallet.prototype.toJSON = function toJSON() {
  return {
    v: 1,
    type: 'wallet',
    pub: this.getPublicKey('base58'),
    priv: this.getPrivateKey('base58'),
    tx: this.tx.toJSON()
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
    compressed: compressed
  });

  w.tx.fromJSON(json.tx);

  return w;
};
