var bcoin = require('../bcoin');
var utils = bcoin.utils;

function Block(data) {
  if (!(this instanceof Block))
    return new Block(data);

  this.type = 'block';
  this.version = data.version;
  this.prevBlock = data.prevBlock;
  this.merkleRoot = data.merkleRoot;
  this.ts = data.ts;
  this.bits = data.bits;
  this.nonce = data.nonce;

  this._hash = null;
  this._hexHash = null;
}
module.exports = Block;

Block.prototype.hash = function hash(enc) {
  // Hash it
  if (!this._hash) {
    this._hash = utils.dsha256(this.abbr());
    this._hexHash = utils.toHex(this._hash);
  }
  return enc === 'hex' ? this._hexHash : this._hash;
};

Block.prototype.abbr = function abbr() {
  var res = new Array(80);
  utils.writeU32(res, this.version, 0);
  utils.copy(this.prevBlock, res, 4);
  utils.copy(this.merkleRoot, res, 36);
  utils.writeU32(res, this.ts, 68);
  utils.writeU32(res, this.bits, 72);
  utils.writeU32(res, this.nonce, 76);

  return res;
};

Block.prototype.verify = function verify() {
  // TODO(indutny): verify nonce
  return true;
};

Block.prototype.render = function render(framer) {
  return [];
};
