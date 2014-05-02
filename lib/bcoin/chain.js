var bcoin = require('../bcoin');
var constants = bcoin.protocol.constants;
var utils = bcoin.utils;

function Chain(options) {
  if (!(this instanceof Chain))
    return new Chain(options);

  this.options = options || {};
  this.blocks = [];
  this.hashes = [];
  this.ts = [];
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
    var prev = block.prevBlock;

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
    this.blocks.push(block);
    this.hashes.push(hash);
    this.ts.push(block.ts);
    this.last = hash;
    res = true;

    // Compress old blocks
    this._compress();

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

Chain.prototype._compress = function compress() {
  // Store only last 1000 blocks, others will be requested if needed
  if (this.blocks.length < 1000)
    return;

  this.blocks = this.blocks.slice(this.blocks.length - 1000);
};

Chain.prototype.getLast = function getLast() {
  return this.blocks[this.blocks.length - 1];
};

Chain.prototype.has = function has(hash) {
  return this.bloom.test(hash);
};
