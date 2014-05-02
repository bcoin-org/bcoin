var util = require('util');
var EventEmitter = require('events').EventEmitter;

var bcoin = require('../bcoin');
var constants = bcoin.protocol.constants;
var preload = bcoin.protocol.preload;
var utils = bcoin.utils;

function Chain(options) {
  if (!(this instanceof Chain))
    return new Chain(options);

  EventEmitter.call(this);

  this.options = options || {};
  this.blocks = [];
  this.hashes = preload.hashes.slice();
  this.ts = preload.ts.slice();
  this.orphan = {
    map: {},
    count: 0
  };
  this.requests = {};
  this.bloom = new bcoin.bloom(28 * 1024 * 1024, 33, 0xdeadbeef);

  if (this.hashes.length === 0) {
    this.add(new bcoin.block(constants.genesis));
  } else {
    // Add all preloaded hashes to the bloom filter
    for (var i = 0; i < this.hashes.length; i++)
      this.bloom.add(utils.toArray(this.hashes[i], 'hex'));
  }
}
util.inherits(Chain, EventEmitter);
module.exports = Chain;

Chain.prototype.add = function add(block) {
  var res = false;
  do {
    // No need to revalidate orphans
    if (!res && !block.verify())
      break;

    var rhash = block.hash();
    var prev = block.prevBlock;
    var pos = utils.binaryInsert(this.ts, block.ts, function(a, b) {
      return a - b;
    }, true);
    var last = (this.hashes.length && pos > 0) ? this.hashes[pos - 1] : null;

    // Add orphan
    if (last && prev !== last) {
      if (!this.bloom.test(rhash) && !this.orphan.map[prev]) {
        this.orphan.count++;
        this.orphan.map[prev] = block;
        this.bloom.add(rhash);
        this.emit('missing', prev);
      }
      break;
    }

    this.bloom.add(rhash);

    // Sorted insert
    var pos = utils.binaryInsert(this.ts, block.ts, function(a, b) {
      return a - b;
    }, true);

    var hash = block.hash('hex');
    this.ts.splice(pos, 0, block.ts);
    this.hashes.splice(pos, 0, hash);

    // Blocks is a FIFO queue, acting like a cache for the requests
    this.blocks.push(block);

    // Fullfill requests
    if (this.requests[hash]) {
      var req = this.requests[hash];
      delete this.requests[hash];
      req.forEach(function(cb) {
        cb(block);
      });
    }

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
  return {
    hash: this.hashes[this.hashes.length - 1],
    ts: this.ts[this.ts.length - 1]
  };
};

Chain.prototype.has = function has(hash) {
  return this.bloom.test(hash) && !this.requests[utils.toHex(hash)];
};

Chain.prototype.get = function get(hash, cb) {
  if (Array.isArray(hash))
    hash = utils.toHex(hash);

  for (var i = 0; i < this.blocks.length; i++)
    if (this.blocks[i].hash('hex') === hash)
      return cb(this.blocks[i]);

  this.emit('missing', hash);
  if (this.requests[hash])
    this.requests[hash].push(cb);
  else
    this.requests[hash] = [ cb ];
};

Chain.prototype.isFull = function isFull() {
  // < 10m since last block
  return (+new Date / 1000) - this.ts[this.ts.length - 1] < 10 * 60;
};
