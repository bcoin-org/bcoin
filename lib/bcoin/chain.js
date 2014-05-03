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
  this.block = {
    list: [],

    // Bloom filter for all merkle trees
    merkleBloom: new bcoin.bloom(8 * 1024 * 1024, 16, 0xdeadbeed),

    // Bloom filter for all known blocks
    bloom: new bcoin.bloom(8 * 1024 * 1024, 16, 0xdeadbeef)
  };
  this.orphan = {
    map: {},
    count: 0
  };
  this.index = {
    bloom: new bcoin.bloom(28 * 1024 * 1024, 33, 0xdeadbee0),
    hashes: preload.hashes.slice(),
    ts: preload.ts.slice()
  };
  this.request = {
    map: {},
    count: 0
  };

  if (this.index.hashes.length === 0)
    this.add(new bcoin.block(constants.genesis));

  for (var i = 0; i < this.index.hashes.length; i++)
    this.index.bloom.add(this.index.hashes[i], 'hex');
}
util.inherits(Chain, EventEmitter);
module.exports = Chain;

function compareTs(a, b) {
  return a -b;
}

Chain.prototype.probeIndex = function probeIndex(hash, ts) {
  if (!this.index.bloom.test(hash, 'hex'))
    return false;

  var start = 0;
  var end = this.index.ts.length;
  if (ts) {
    start = utils.binaryInsert(this.index.ts, ts - 2 * 3600, compareTs, true);
    start = Math.max(0, start - 1);
    end = utils.binaryInsert(this.index.ts, ts + 2 * 3600, compareTs, true);
  }

  for (var i = start; i < end; i++)
    if (this.index.hashes[i] === hash)
      return true;

  return false;
};

Chain.prototype.addIndex = function addIndex(hash, ts) {
  if (this.probeIndex(hash, ts))
    return;

  var pos = utils.binaryInsert(this.index.ts, ts, compareTs);
  this.index.hashes.splice(pos, 0, hash);
  this.index.bloom.add(hash, 'hex');
};

Chain.prototype.getRange = function getRange(ts) {
  var start = utils.binaryInsert(this.index.ts, ts - 2 * 3600, compareTs, true);
  var end = utils.binaryInsert(this.index.ts, ts + 2 * 3600, compareTs, true);

  if (start > 0)
    start--;
  if (end > 0)
    end--;

  return { start: this.index.hashes[start], end: this.index.hashes[end] };
};

Chain.prototype.add = function add(block) {
  var res = false;
  var initial = block;
  do {
    // No need to revalidate orphans
    if (!res && !block.verify())
      break;

    var hash = block.hash('hex');
    var prev = block.prevBlock;

    // If the block is already known to be an orphan
    if (this.orphan.map[prev])
      break;

    // If previous block wasn't ever seen - add current to orphans
    if (!this.probeIndex(hash, block.ts) && !this.probeIndex(prev, block.ts)) {
      this.orphan.count++;
      this.orphan.map[prev] = block;

      this.emit('missing', prev, this.getRange(block.ts));
      break;
    }

    // Validated known block at this point - add it to index
    this.addIndex(hash, block.ts);

    // Fullfill request
    if (this.request.map[hash]) {
      var req = this.request.map[hash];
      delete this.request.map[hash];
      this.request.count--;
      req.forEach(function(cb) {
        cb(block);
      });
    }

    // At least one block was added
    res = true;
    this.block.list.push(block);
    this._bloomBlock(block);

    if (!this.orphan.map[hash])
      break;

    // We have orphan child for this block - add it to chain
    block = this.orphan.map[hash];
    delete this.orphan.map[hash];
    this.orphan.count--;
  } while (true);

  // Compress old blocks
  this._compress();

  return res;
};

Chain.prototype._compress = function compress() {
  // Keep at least 1000 blocks and at most 2000
  if (this.block.list.length < 2000)
    return;

  // Bloom filter rebuilt is needed
  this.block.list = this.block.list.slice(-1000);
  this.block.bloom.reset();
  this.block.merkleBloom.reset();

  for (var i = 0; i < this.block.list.length; i++)
    this._bloomBlock(this.block.list[i]);
};

Chain.prototype._bloomBlock = function _bloomBlock(block) {
  this.block.bloom.add(block.hash(), 'hex');
  for (var i = 0; i < block.hashes.length; i++)
    this.block.merkleBloom.add(block.hashes[i], 'hex');
};

Chain.prototype.has = function has(hash) {
  return this.probeIndex(hash) || !!this.orphan.map[hash];
};

Chain.prototype.hasMerkle = function hasMerkle(hash) {
  if (!this.block.merkleBloom.test(hash, 'hex'))
    return false;

  hash = utils.toHex(hash);
  for (var i = 0; i < this.block.list.length; i++)
    if (this.block.list[i].hasMerkle(hash))
      return true;

  return false;
};

Chain.prototype.get = function get(hash, cb) {
  // Cached block found
  if (this.block.bloom.test(hash, 'hex')) {
    for (var i = 0; i < this.block.list.length; i++) {
      if (this.block.list[i].hash('hex') === hash) {
        // NOTE: we return right after the statement - so `i` should be valid
        // at the time of nextTick call
        var self = this;
        process.nextTick(function() {
          cb(self.block.list[i]);
        });
        return;
      }
    }
    assert(false);
  }

  if (this.request.map[hash]) {
    this.request.map[hash].push(cb);
  } else {
    this.request.map[hash] = [ cb ];
    this.request.count++;
    this.emit('missing', hash);
  }
};

Chain.prototype.isFull = function isFull() {
  // < 10m since last block
  return !this.request.count &&
         (+new Date / 1000) - this.index.ts[this.index.ts.length - 1] < 10 * 60;
};

Chain.prototype.covers = function covers(ts) {
  return ts >= this.index.ts[0];
};

Chain.prototype.hashesInRange = function hashesInRange(start, end) {
  var ts = this.index.ts;

  var pos = utils.binaryInsert(ts, start - 2 * 3600, compareTs, true);
  start = Math.max(0, pos - 1);
  var pos = utils.binaryInsert(ts, end + 2 * 3600, compareTs, true);
  end = pos;
  return this.index.hashes.slice(start, end);
};

Chain.prototype.getLast = function getLast() {
  return this.index.hashes[this.index.hashes.length - 1];
};
