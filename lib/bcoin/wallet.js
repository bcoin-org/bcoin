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

Wallet.prototype.getPrivateKey = function getPrivateKey() {
  return this.key.getPrivate().toArray();
};

Wallet.prototype.getPublicKey = function getPublicKey() {
  return this.key.getPublic('array');
};

Wallet.prototype.getHash = function getHash() {
  var pub = this.key.getPublic('array');
  return utils.ripesha(pub);
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
    return false;
  if (addr[0] !== 0)
    return false;

  var chk = utils.checksum(addr.slice(0, -4));
  if (utils.readU32(chk, 0) !== utils.readU32(addr, 21))
    return false;

  return addr.slice(1, -4);
};

Wallet.prototype.validateAddress = function validateAddress(addr) {
  var p = Wallet.addr2hash(addr);
  return !!p;
};
Wallet.validateAddress = Wallet.prototype.validateAddress;

Wallet.prototype.own = function own(tx) {
  var outputs = tx.outputs.filter(function(output) {
    if (output.script.length < 5)
      return false;

    var s = output.script.slice(-5);
    return s[0] === 'dup' &&
           s[1] === 'hash160' &&
           utils.isEqual(s[2], this.getHash()) &&
           s[3] === 'eqverify' &&
           s[4] === 'checksig';
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
  var pub = this.key.getPublic('array');

  // Add signature script to each input
  inputs.forEach(function(input, i) {
    var s = input.out.tx.getSubscript(input.out.index);

    var hash = tx.subscriptHash(i, s, type);
    var signature = bcoin.ecdsa.sign(hash, this.key).toDER();

    input.script = [
      signature.concat(bcoin.protocol.constants.hashType[type]),
      pub
    ];
  }, this);

  return inputs.length;
};
