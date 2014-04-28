var bcoin = require('../bcoin');
var utils = bcoin.utils;

function Wallet() {
  if (!(this instanceof Wallet))
    return new Wallet();

  this.key = bcoin.ecdsa.genKeyPair();
}
module.exports = Wallet;

Wallet.prototype.getAddress = function getAddress() {
  var pub = this.key.getPublic('array');
  var keyHash = utils.ripesha(pub);

  // Add version
  keyHash = [ 0 ].concat(keyHash);

  var addr = keyHash.concat(utils.checksum(keyHash));
  return utils.toBase58(addr);
}

Wallet.prototype.validateAddress = function validateAddress(addr) {
  if (!Array.isArray(addr))
    addr = utils.fromBase58(addr);

  if (addr.length !== 25)
    return false;
  if (addr[0] !== 0)
    return false;
  var chk = utils.checksum(addr.slice(0, -4));
  if (utils.readU32(chk, 0) !== utils.readU32(addr, 21))
    return false;

  return true;
};
Wallet.validateAddress = Wallet.prototype.validateAddress;
