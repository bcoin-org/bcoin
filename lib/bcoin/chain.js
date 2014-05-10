var assert = require('assert');
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
  this.prefix = 'bt/chain/';
  this.storage = this.options.storage;
  this.strict = this.options.strict || false;
  this.block = {
    list: [],

    // Bloom filter for all known blocks
    bloom: new bcoin.bloom(8 * 1024 * 1024, 16, 0xdeadbeef)
  };
  this.orphan = {
    map: {},
    count: 0
  };
  this.index = {
    bloom: null,
    hashes: [],
    ts: [],
    heights: []
  };
  this.request = new utils.RequestCache();

  this.fromJSON(preload);

  this.loading = false;
  this._init();
}
util.inherits(Chain, EventEmitter);
module.exports = Chain;

function compareTs(a, b) {
  return a -b;
}

Chain.prototype._init = function _init() {
  if (!this.storage)
    return;

  this.loading = true;
  var self = this;
  var s = this.storage.createReadStream({
    start: this.prefix,
    end: this.prefix + 'z'
  });
  s.on('data', function(data) {
    var hash = data.key.slice(self.prefix.length);
    self._addIndex(hash, data.value.ts, data.value.height);
  });
  s.on('error', function(err) {
    self.emit('error', err);
  });
  s.on('end', function() {
    self.loading = false;
    self.emit('load');
  });
};

Chain.prototype._getRange = function _getRange(hash, ts, futureOnly) {
  var pos = utils.binaryInsert(this.index.ts, ts, compareTs, true);
  var start = Math.min(Math.max(0, pos), this.index.ts.length - 1);

  while (start > 0 && this.index.ts[start] > ts)
    start--;

  var curr = this.index.ts[start];
  var wnd = 2 * 3600;

  if (!futureOnly)
    while (start > 0 && this.index.ts[start] + wnd > curr)
      start--;

  var end = Math.min(Math.max(0, pos), this.index.ts.length - 1);
  while (end < this.index.ts.length - 1 && this.index.ts[end] - wnd < ts)
    end++;

  return { start: start, end: end };
};

Chain.prototype._probeIndex = function _probeIndex(hash, ts) {
  if (!this.index.bloom.test(hash, 'hex'))
    return false;

  var start = 0;
  var end = this.index.ts.length;
  if (ts) {
    var range = this._getRange(hash, ts);
    start = range.start;
    end = range.end;
  }

  for (var i = start; i <= end; i++)
    if (this.index.hashes[i] === hash)
      return { height: this.index.heights[i], ts: this.index.ts[i] };

  return false;
};

Chain.prototype._addIndex = function _addIndex(hash, ts, height) {
  if (this._probeIndex(hash, ts))
    return;

  var pos = utils.binaryInsert(this.index.ts, ts, compareTs, true);

  // Avoid duplicates
  if (this.index.hashes[pos] === hash ||
      this.index.hashes[pos - 1] === hash ||
      this.index.hashes[pos + 1] === hash) {
    return;
  }

  this.index.ts.splice(pos, 0, ts);
  this.index.hashes.splice(pos, 0, hash);
  this.index.heights.splice(pos, 0, height);
  this.index.bloom.add(hash, 'hex');

  if (!this.storage)
    return;

  var self = this;
  var obj = { ts: ts, height: height };
  this.storage.put(this.prefix + hash, obj, function(err) {
    if (err)
      self.emit('error', err);
  });
};

Chain.prototype.add = function add(block) {
  if (this.loading) {
    this.once('load', function() {
      this.add(block);
    });
    return;
  }

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

    var prevProbe = this._probeIndex(prev, block.ts);

    // If previous block wasn't ever seen - add current to orphans
    if (!this._probeIndex(hash, block.ts) && !prevProbe) {
      this.orphan.count++;
      this.orphan.map[prev] = block;

      var range = this._getRange(hash, block.ts, true);
      var hashes = this.index.hashes.slice(range.start, range.end + 1);
      this.emit('missing', prev, hashes, block);
      break;
    }

    // Validated known block at this point - add it to index
    if (prevProbe)
      this._addIndex(hash, block.ts, prevProbe.height + 1);

    // At least one block was added
    res = true;
    this.block.list.push(block);
    this._bloomBlock(block);

    // Fullfill request
    this.request.fullfill(hash, block);

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

  for (var i = 0; i < this.block.list.length; i++)
    this._bloomBlock(this.block.list[i]);
};

Chain.prototype._bloomBlock = function _bloomBlock(block) {
  this.block.bloom.add(block.hash(), 'hex');
};

Chain.prototype.has = function has(hash, noProbe, cb) {
  if (typeof noProbe === 'function') {
    cb = noProbe;
    noProbe = false;
  }
  if (this.loading) {
    this.once('load', function() {
      this.has(hash, cb);
    });
    return;
  }
  cb = utils.asyncify(cb);

  if (this.block.bloom.test(hash, 'hex')) {
    if (this.strict) {
      for (var i = 0; i < this.block.list.length; i++)
        if (this.block.list[i].hash('hex') === hash)
          return cb(true);
    } else {
      return cb(true);
    }
  }

  if (!noProbe && this.index.bloom.test(hash, 'hex')) {
    // XXX find hash
    return true;
  }

  return cb(!!this.orphan.map[hash]);
};

Chain.prototype.get = function get(hash, cb) {
  // Cached block found
  if (this.block.bloom.test(hash, 'hex')) {
    for (var i = 0; i < this.block.list.length; i++) {
      if (this.block.list[i].hash('hex') === hash) {
        // NOTE: we return right after the statement - so `block` should be
        // valid at the time of nextTick call
        var block = this.block.list[i];
        bcoin.utils.nextTick(function() {
          cb(block);
        });
        return;
      }
    }
    assert(false);
  }

  if (this.request.add(hash, cb))
    this.emit('missing', hash, null, null);
};

Chain.prototype.isFull = function isFull() {
  // < 40m since last block
  return !this.request.count &&
         (+new Date / 1000) - this.index.ts[this.index.ts.length - 1] < 40 * 60;
};

Chain.prototype.hashesInRange = function hashesInRange(start, end, cb) {
  if (this.loading) {
    this.once('load', function() {
      this.hashesInRange(start, end, cb);
    });
    return;
  }
  cb = utils.asyncify(cb);
  var ts = this.index.ts;

  start = utils.binaryInsert(ts, start, compareTs, true);
  if (start > 0 && ts[start - 1] >= start)
    start--;
  end = utils.binaryInsert(ts, end, compareTs, true);

  return cb(this.index.hashes.slice(start, end));
};

Chain.prototype.getLast = function getLast(cb) {
  if (this.loading) {
    this.once('load', function() {
      this.getLast(cb);
    });
    return;
  }
  cb = utils.asyncify(cb);
  return cb(this.index.hashes[this.index.hashes.length - 1]);
};

Chain.prototype.toJSON = function toJSON() {
  var keep = 1000;

  // Keep only last 1000 consequent blocks, dilate others at:
  // 7 day range for blocks before 2013
  // 12 hour for blocks before 2014
  // 6 hour for blocks in 2014 and after it
  // (or at maximum 250 block range)
  var last = {
    hashes: this.index.hashes.slice(-keep),
    ts: this.index.ts.slice(-keep),
    heights: this.index.heights.slice(-keep)
  };

  var first = {
    hashes: [],
    ts: [],
    heights: []
  };

  var delta1 = 7 * 24 * 3600;
  var delta2 = 12 * 3600;
  var delta3 = 6 * 3600;

  var lastTs = 0;
  var lastHeight = -1000;
  for (var i = 0; i < this.index.ts.length - keep; i++) {
    var ts = this.index.ts[i];
    var delta = ts < 1356984000 ? delta1 :
                ts < 1388520000 ? delta2 : delta3;
    var hdelta = this.index.heights[i] - lastHeight;
    if (ts - lastTs < delta && hdelta < 250)
      continue;

    lastTs = ts;
    lastHeight = this.index.heights[i];
    first.hashes.push(this.index.hashes[i]);
    first.ts.push(this.index.ts[i]);
    first.heights.push(this.index.heights[i]);
  }

  return {
    v: 1,
    type: 'chain',
    hashes: first.hashes.concat(last.hashes),
    ts: first.ts.concat(last.ts),
    heights: first.heights.concat(last.heights)
  };
};

Chain.prototype.fromJSON = function fromJSON(json) {
  assert.equal(json.v, 1);
  assert.equal(json.type, 'chain');
  this.index.hashes = json.hashes.slice();
  this.index.ts = json.ts.slice();
  this.index.heights = json.heights.slice();
  if (this.index.bloom)
    this.index.bloom.reset();
  else
    this.index.bloom = new bcoin.bloom(28 * 1024 * 1024, 16, 0xdeadbee0);

  if (this.index.hashes.length === 0)
    this.add(new bcoin.block(constants.genesis));

  for (var i = 0; i < this.index.hashes.length; i++) {
    this.index.bloom.add(this.index.hashes[i], 'hex');
  }
};
