var assert = require('assert');
var bcoin = require('../bcoin');
var hash = require('hash.js');
var utils = bcoin.utils;

function Wallet(options, passphrase) {
  if (!(this instanceof Wallet))
    return new Wallet(options, passphrase);

  // bcoin.wallet('scope', 'password')
  if (typeof options === 'string' && typeof passphrase === 'string') {
    options = {
      scope: options,
      passphrase: passphrase
    };
  }
  if (!options)
    options = {};

  this.compressed = true;
  this.tx = new bcoin.txPool();
  this.key = null;

  if (options.passphrase) {
    this.key = bcoin.ecdsa.genKeyPair({
      pers: options.scope,
      entropy: hash.sha256().update(options.passphrase).digest()
    });
  } else if (options.priv) {
    this.key = bcoin.ecdsa.keyPair(options.priv);
  } else {
    this.key = bcoin.ecdsa.genKeyPair();
  }
}
module.exports = Wallet;

Wallet.prototype.getPrivateKey = function getPrivateKey(enc) {
  var priv = this.key.getPrivate().toArray();
  if (!enc)
    return priv;

  if (enc === 'base58') {
    // We'll be using ncompressed public key as an address
    var arr = [ 128 ].concat(priv);
    if (this.compressed)
      arr.push(1);
    var chk = utils.checksum(arr);
    return utils.toBase58(arr.concat(chk));
  } else {
    return priv;
  }
};

Wallet.prototype.getPublicKey = function getPublicKey() {
  return this.key.getPublic(this.compressed, 'array');
};

Wallet.prototype.getHash = function getHash() {
  return utils.ripesha(this.getPublicKey());
};

Wallet.prototype.getAddress = function getAddress() {
  return Wallet.hash2addr(this.getHash());
};

Wallet.hash2addr = function hash2addr(hash) {
  hash = utils.toArray(hash, 'hex');

  // Add version
  hash = [ 0 ].concat(hash);

  var addr = hash.concat(utils.checksum(hash));
  return utils.toBase58(addr);
};

Wallet.addr2hash = function addr2hash(addr) {
  if (!Array.isArray(addr))
    addr = utils.fromBase58(addr);

  if (addr.length !== 25)
    return [];
  if (addr[0] !== 0)
    return [];

  var chk = utils.checksum(addr.slice(0, -4));
  if (utils.readU32(chk, 0) !== utils.readU32(addr, 21))
    return [];

  return addr.slice(1, -4);
};

Wallet.prototype.validateAddress = function validateAddress(addr) {
  var p = Wallet.addr2hash(addr);
  return p.length !== 0;
};
Wallet.validateAddress = Wallet.prototype.validateAddress;

Wallet.prototype.own = function own(tx, index) {
  var hash = this.getHash();
  var key = this.getPublicKey();
  var outputs = tx.outputs.filter(function(output, i) {
    if (index && index !== i)
      return false;

    var s = output.script;

    if (bcoin.script.isPubkeyhash(s, hash))
      return true;

    if (bcoin.script.isMultisig(s, key))
      return true;

    return false;
  }, this);
  if (outputs.length === 0)
    return false;

  return outputs;
};

Wallet.prototype.sign = function sign(tx, type) {
  if (!type)
    type = 'all';
  assert.equal(type, 'all');

  // Filter inputs that this wallet own
  var inputs = tx.inputs.filter(function(input) {
    return input.out.tx && this.own(input.out.tx);
  }, this);
  var pub = this.getPublicKey();

  // Add signature script to each input
  inputs.forEach(function(input, i) {
    var s = input.out.tx.getSubscript(input.out.index);
    var hash = tx.subscriptHash(i, s, type);
    var signature = bcoin.ecdsa.sign(hash, this.key).toDER();
    signature = signature.concat(bcoin.protocol.constants.hashType[type]);

    if (bcoin.script.isPubkeyhash(s)) {
      input.script = [ signature, pub ];
      return;
    }

    // Multisig
    input.script = [ [], signature ];
  }, this);

  return inputs.length;
};

Wallet.prototype.addTX = function addTX(tx) {
  this.tx.add(tx);
};

Wallet.prototype.unspent = function unspent() {
  return this.tx.unspent(this);
};

Wallet.prototype.balance = function balance() {
  return this.tx.balance(this);
};
