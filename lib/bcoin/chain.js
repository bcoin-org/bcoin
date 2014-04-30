var bcoin = require('../bcoin');
var constants = bcoin.protocol.constants;
var utils = bcoin.utils;

function Chain() {
  if (!(this instanceof Chain))
    return new Chain();

  this.chain = [];
  this.orphan = {
    map: {},
    count: 0
  };
  this.map = {};
  this.last = null;
  this.add(new bcoin.block(constants.genesis));
}
module.exports = Chain;

Chain.prototype.add = function add(block) {
  var res = false;
  do {
    var hash = block.hash('hex');
    var prev = utils.toHex(block.prevBlock);

    // No need to revalidate orphans
    if (!res && !block.verify())
      break;

    // Add orphan
    if (this.last && prev !== this.last) {
      if (!this.orphan.map[prev]) {
        this.orphan.count++;
        this.orphan.map[prev] = block;
      }
      break;
    }

    this.map[hash] = block;
    this.chain.push(block);
    this.last = hash;
    res = true;

    // We have orphan child for this block - add it to chain
    if (this.orphan.map[hash]) {
      block = this.orphan.map[hash];
      delete this.orphan.map[hash];
      this.orphan.count--;
      continue;
    }

    break;
  } while (true);
};

Chain.prototype.getLast = function getLast() {
  return this.chain[this.chain.length - 1];
};

Chain.prototype.has = function hash(hash) {
  hash = utils.toHex(hash);
  return !!this.map[hash] && !!this.orphan.map[hash];
};
