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
  this.bloom = new bcoin.bloom(28 * 1024 * 1024, 33, 0xdeadbeef);
  this.last = null;
  this.add(new bcoin.block(constants.genesis));
}
module.exports = Chain;

Chain.prototype.add = function add(block) {
  var res = false;
  do {
    // No need to revalidate orphans
    if (!res && !block.verify())
      break;

    var rhash = block.hash();
    var prev = utils.toHex(block.prevBlock);

    // Add orphan
    if (this.last && prev !== this.last) {
      if (!this.bloom.test(rhash) && !this.orphan.map[prev]) {
        this.orphan.count++;
        this.orphan.map[prev] = block;
        this.bloom.add(rhash);
      }
      break;
    }

    var hash = block.hash('hex');

    this.bloom.add(rhash);
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

  return res;
};

Chain.prototype.getLast = function getLast() {
  return this.chain[this.chain.length - 1];
};

Chain.prototype.has = function has(hash) {
  hash = utils.toHex(hash);
  return this.bloom.test(hash);
};
