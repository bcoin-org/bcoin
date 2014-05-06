var bcoin = require('../bcoin');
var utils = bcoin.utils;

function Block(data) {
  if (!(this instanceof Block))
    return new Block(data);

  this.type = 'block';
  this.version = data.version;
  this.prevBlock = utils.toHex(data.prevBlock);
  this.merkleRoot = utils.toHex(data.merkleRoot);
  this.ts = data.ts;
  this.bits = data.bits;
  this.nonce = data.nonce;
  this.totalTX = data.totalTX;
  this.hashes = data.hashes.map(function(hash) {
    return utils.toHex(hash);
  });
  this.flags = data.flags;

  this._hash = null;
}
module.exports = Block;

Block.prototype.hash = function hash(enc) {
  // Hash it
  if (!this._hash)
    this._hash = utils.toHex(utils.dsha256(this.abbr()));
  return enc === 'hex' ? this._hash : utils.toArray(this._hash, 'hex');
};

Block.prototype.abbr = function abbr() {
  var res = new Array(80);
  utils.writeU32(res, this.version, 0);
  utils.copy(utils.toArray(this.prevBlock, 'hex'), res, 4);
  utils.copy(utils.toArray(this.merkleRoot, 'hex'), res, 36);
  utils.writeU32(res, this.ts, 68);
  utils.writeU32(res, this.bits, 72);
  utils.writeU32(res, this.nonce, 76);

  return res;
};

Block.prototype.verify = function verify() {
  return utils.testTarget(this.bits, this.hash());
};

Block.prototype.render = function render(framer) {
  return [];
};

Block.prototype.hasMerkle = function hasMerkle(hash) {
  return this.hashes.indexOf(hash) !== -1;
};
