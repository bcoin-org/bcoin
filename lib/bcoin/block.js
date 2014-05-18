var bcoin = require('../bcoin');
var utils = bcoin.utils;

function Block(data, subtype) {
  if (!(this instanceof Block))
    return new Block(data, subtype);

  this.type = 'block';
  this.subtype = subtype;
  this.version = data.version;
  this.prevBlock = utils.toHex(data.prevBlock);
  this.merkleRoot = utils.toHex(data.merkleRoot);
  this.ts = data.ts;
  this.bits = data.bits;
  this.nonce = data.nonce;
  this.totalTX = data.totalTX;
  this.hashes = (data.hashes || []).map(function(hash) {
    return utils.toHex(hash);
  });
  this.flags = data.flags || [];

  // List of matched TXs
  this.tx = [];
  this.invalid = false;

  this._hash = null;

  // Verify partial merkle tree and fill `ts` array
  this._verifyMerkle();
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
  return !this.invalid && utils.testTarget(this.bits, this.hash());
};

Block.prototype.render = function render(framer) {
  return [];
};

Block.prototype.hasTX = function hasTX(hash) {
  return this.tx.indexOf(hash) !== -1;
};

Block.prototype._verifyMerkle = function verifyMerkle() {
  var height = 0;

  // Count leafs
  for (var i = this.totalTX; i > 0; i >>= 1)
    height++;
  if (this.totalTX > (1 << (height - 1)))
    height++;

  var tx = [];
  var i = 0;
  var j = 0;
  var hashes = this.hashes;
  var flags = this.flags;

  var root = visit(1);
  if (!root || root !== this.merkleRoot) {
    this.invalid = true;
    return;
  }
  this.tx = tx;
  function visit(depth) {
    if (i === flags.length * 8 || j === hashes.length)
      return null;

    var flag = (flags[i >> 3] >>> (i & 7)) & 1;
    i++;

    if (flag === 0 || depth === height) {
      if (depth === height)
        tx.push(hashes[j]);
      return hashes[j++];
    }

    // Go deeper
    var left = visit(depth + 1);
    if (!left)
      return null;
    var right = visit(depth + 1);
    if (right === left)
      return null;
    if (!right)
      right = left;
    return utils.toHex(utils.dsha256(left + right, 'hex'));
  }
};
