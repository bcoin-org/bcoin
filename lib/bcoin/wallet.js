var assert = require('assert');
var bcoin = require('../bcoin');
var utils = bcoin.utils;

function Wallet() {
  if (!(this instanceof Wallet))
    return new Wallet();

  this.key = bcoin.ecdsa.genKeyPair();
}
module.exports = Wallet;

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
  return tx.outputs.some(function(output) {
    return output.script.length === 5 &&
           output.script[0] === 'dup' &&
           output.script[1] === 'hash160' &&
           utils.toHex(output.script[2]) === utils.toHex(this.getHash()) &&
           output.script[3] === 'eqverify' &&
           output.script[4] === 'checksig';
  }, this);
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
    var copy = input.tx.clone();
    var s = input.out.tx.getSubscript();

    copy.inputs.forEach(function(input, j) {
      input.script = i === j ? s : [];
    });

    var verifyStr = copy.render();
    verifyStr = verifyStr.concat(bcoin.protocol.constants.hashType[type]);
    var hash = utils.dsha256(verifyStr);
    var signature = this.key.sign(hash).toDER();
  }, this);

  return inputs.length;
};
