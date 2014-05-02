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
  this.fifo = [];
  this.hashes = preload.hashes.slice();
  this.ts = preload.ts.slice();
  this.orphan = {
    map: {},
    count: 0
  };
  this.requests = {
    map: {},
    count: 0
  };
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
  var initial = block;
  do {
    // No need to revalidate orphans
    if (!res && !block.verify())
      break;

    var hash = block.hash('hex');
    var rhash = block.hash();
    var prev = block.prevBlock;

    // Validity period is two hours
    var pos = utils.binaryInsert(this.ts, block.ts - 2 * 3600, function(a, b) {
      return a - b;
    }, true);
    var test = this.bloom.test(rhash) &&
               prev !== initial &&
               !this.orphan.map[prev];

    var match = this.hashes.length === 0;
    for (pos--; !match && 0 <= 0 && pos < this.hashes.length; pos++)
      match = this.hashes[pos] === prev;

    // If last hash at ts matches prev hash or we already know this block -
    // add it to either list or FIFO
    if (!match && !test) {
      // Add orphan
      if (!this.orphan.map[prev]) {
        this.orphan.count++;
        this.orphan.map[prev] = block;
        this.bloom.add(rhash);
        this.emit('missing', prev);
      }
      break;
    }

    // It may be a re-requested block
    if (!this.bloom.test(rhash)) {
      // Sorted insert
      var pos = utils.binaryInsert(this.ts, block.ts, function(a, b) {
        return a - b;
      }, true);

      this.ts.splice(pos, 0, block.ts);
      this.hashes.splice(pos, 0, hash);
      this.bloom.add(rhash);
    }

    // Some old block for caching purposes, should be a FIFO
    if (!this.covers(block.ts)) {
      this.fifo.push(block);

    // A new block
    } else {
      // Insert block into a cache set if it isn't already there
      var pos = utils.binaryInsert(this.blocks, block, function(a, b) {
        return a.ts - b.ts;
      }, true);
      this.blocks.splice(pos, 0, block);
    }

    // Fullfill requests
    if (this.requests.map[hash]) {
      var req = this.requests.map[hash];
      delete this.requests.map[hash];
      this.requests.count--;
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
  // Store only last 1000 blocks and 1000 FIFO
  if (this.blocks.length > 1000)
    this.blocks = this.blocks.slice(-1000);
  if (this.fifo.length > 1000)
    this.fifo = this.fifo.slice(-1000);
};

Chain.prototype.getLast = function getLast() {
  return {
    hash: this.hashes[this.hashes.length - 1],
    ts: this.ts[this.ts.length - 1]
  };
};

Chain.prototype.has = function has(hash, cacheonly) {
  if (!Array.isArray(hash))
    hash = utils.toArray(hash, 'hex');
  if (!cacheonly)
    return this.bloom.test(hash) && !this.requests.map[utils.toHex(hash)];

  for (var i = 0; i < this.blocks.length; i++)
    if (this.blocks[i].hash('hex') === hash)
      return true;
  for (var i = 0; i < this.fifo.length; i++)
    if (this.fifo[i].hash('hex') === hash)
      return true;

  return false;
};

Chain.prototype.get = function get(hash, cb) {
  if (Array.isArray(hash))
    hash = utils.toHex(hash);

  for (var i = 0; i < this.blocks.length; i++)
    if (this.blocks[i].hash('hex') === hash)
      return cb(this.blocks[i]);
  for (var i = 0; i < this.fifo.length; i++)
    if (this.fifo[i].hash('hex') === hash)
      return cb(this.fifo[i]);

  if (this.requests.map[hash]) {
    this.requests.map[hash].push(cb);
    this.requests.count++;
  } else {
    this.requests.map[hash] = [ cb ];
  }
  this.emit('missing', hash);
};

Chain.prototype.isFull = function isFull() {
  // < 10m since last block
  return !this.requests.count &&
         (+new Date / 1000) - this.ts[this.ts.length - 1] < 10 * 60;
};

Chain.prototype.covers = function covers(ts) {
  return this.ts.length && this.ts[0] <= ts;
};

Chain.prototype.hashesFrom = function hashesFrom(ts) {
  var pos = utils.binaryInsert(this.ts, ts, function(a, b) {
    return a - b;
  }, true);
  return this.hashes.slice(pos);
};
