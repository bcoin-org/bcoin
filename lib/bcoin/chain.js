/**
 * chain.js - blockchain management for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

var inherits = require('inherits');
var EventEmitter = require('events').EventEmitter;

var bcoin = require('../bcoin');
var constants = bcoin.protocol.constants;
var network = bcoin.protocol.network;
var utils = bcoin.utils;
var assert = utils.assert;

/**
 * Chain
 */

function Chain(options) {
  var preload = network.preload;

  if (!(this instanceof Chain))
    return new Chain(options);

  EventEmitter.call(this);

  this.options = options || {};
  this.prefix = 'bt/chain/';
  this.storage = this.options.storage;
  this.strict = this.options.strict || false;
  this.cacheLimit = this.options.cacheLimit || 2000;

  this.tip = null;

  this.block = {
    list: [],
    // Bloom filter for all known blocks
    bloom: new bcoin.bloom(8 * 1024 * 1024, 16, 0xdeadbeef)
  };

  this.orphan = {
    map: {},
    bmap: {},
    count: 0
  };

  this.index = {
    bloom: null,
    hashes: [],
    ts: [],
    heights: [],
    lastTs: 0
  };

  this.request = new utils.RequestCache();

  this.fromJSON(preload);

  // Last TS after preload, needed for fill percent
  this.index.lastTs = this.index.ts[this.index.ts.length - 1];

  bcoin.chain.global = this;

  this.loading = false;
  this._init();
}

inherits(Chain, EventEmitter);

Chain.codes = {
  okay: 0,
  newOrphan: 1,
  knownOrphan: 2,
  forked: 3,
  invalid: 4,
  badCheckpoint: 4,
  unchanged: 5
};

Chain.messages = {
  0: 'Block was added successfully',
  1: 'Block is a new orphan',
  2: 'Block is a known orphan',
  3: 'Block is a greater fork',
  4: 'Block verification failed',
  5: 'Block does not match checkpoint',
  6: 'Chain is unchanged'
};

Chain.msg = function msg(code) {
  return new Error(Chain.messages[code] || 'Unknown');
};

function compareTs(a, b) {
  return a -b;
}

Chain.prototype._init = function _init() {
  var self = this;
  var s;

  if (!this.storage)
    return;

  utils.nextTick(function() {
    self.emit('debug', 'Chain is loading.');
  });

  this.loading = true;

  s = this.storage.createReadStream({
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
    self.emit('debug', 'Chain successfully loaded.');
  });
};

Chain.prototype._getRange = function _getRange(hash, ts, futureOnly) {
  var pos = utils.binaryInsert(this.index.ts, ts, compareTs, true);
  var start = Math.min(Math.max(0, pos), this.index.ts.length - 1);
  var curr, wnd, end;

  while (start > 0 && this.index.ts[start] > ts)
    start--;

  curr = this.index.ts[start];
  wnd = 2 * 3600;

  if (!futureOnly)
    while (start > 0 && this.index.ts[start] + wnd > curr)
      start--;

  end = Math.min(Math.max(0, pos), this.index.ts.length - 1);
  while (end < this.index.ts.length - 1 && this.index.ts[end] - wnd < ts)
    end++;

  return { start: start, end: end };
};

Chain.prototype._probeIndex = function _probeIndex(hash, ts) {
  if (!this.index.bloom.test(hash, 'hex'))
    return false;

  var start = 0;
  var end = this.index.ts.length;
  var range, i;

  if (ts) {
    range = this._getRange(hash, ts);
    start = range.start;
    end = range.end;
  }

  for (i = start; i <= end; i++)
    if (this.index.hashes[i] === hash)
      return { i: i, height: this.index.heights[i], ts: this.index.ts[i] };

  return false;
};

Chain.prototype._addIndex = function _addIndex(hash, ts, height) {
  var self = this;

  // Already added
  if (this._probeIndex(hash, ts))
    return Chain.codes.unchanged;

  var pos = utils.binaryInsert(this.index.ts, ts, compareTs, true);
  var checkpoint;

  // Duplicate height
  if (this.index.hashes[pos] === hash
      || this.index.hashes[pos - 1] === hash
      || this.index.hashes[pos + 1] === hash) {
    return Chain.codes.unchanged;
  }

  // Fork at checkpoint
  checkpoint = network.checkpoints[height];
  if (checkpoint) {
    this.emit('checkpoint', height, hash, checkpoint);
    if (hash !== checkpoint) {
      this.resetLastCheckpoint(height);
      this.emit('fork', height, hash, checkpoint);
      return Chain.codes.badCheckpoint;
    }
  }

  this.index.ts.splice(pos, 0, ts);
  this.index.hashes.splice(pos, 0, hash);
  this.index.heights.splice(pos, 0, height);
  this.index.bloom.add(hash, 'hex');

  this.tip = this.getTip();
  this.emit('tip', this.tip);

  this._save(hash, {
    ts: ts,
    height: height
  });

  return Chain.codes.okay;
};

Chain.prototype.resetLastCheckpoint = function resetLastCheckpoint(height) {
  var lastHeight = Object.keys(network.checkpoints).sort().indexOf(height) - 1;

  if (lastHeight < 0)
    lastHeight = 0;

  this.resetHeight(lastHeight);
};

Chain.prototype.resetHeight = function resetHeight(height) {
  var self = this;
  var index = this.index.heights.indexOf(height);
  var ahead = this.index.hashes.slice(index + 1);

  assert(index >= 0);

  this.block.list.length = 0;
  this.block.bloom.reset();
  this.orphan.map = {};
  this.orphan.bmap = {};
  this.orphan.count = 0;
  this.index.ts.length = index + 1;
  this.index.hashes.length = index + 1;
  this.index.heights.length = index + 1;
  this.index.bloom.reset();
  this.index.hashes.forEach(function(hash) {
    self.index.bloom.add(hash, 'hex');
  });

  this.index.lastTs = Math.min(
    this.index.lastTs,
    this.index.ts[this.index.ts.length - 1]
  );

  this.tip = this.getTip();
  this.emit('tip', this.tip);

  ahead.forEach(function(hash) {
    self._delete(hash);
  });
};

Chain.prototype.resetTime = function resetTime(ts) {
  var entry = this.byTime(ts);
  if (!entry)
    return;
  return this.resetHeight(entry.height);
};

Chain.prototype._killFork = function _killFork(probe) {
  var self = this;
  var delta = 2 * 3600;
  var upper = probe.ts + delta;
  var lower = probe.ts - delta;
  var index, i, len, hash;

  // Search duplicate heights down
  index = -1;
  for (i = probe.i - 1; i > 0 && this.index.ts[i] > lower; i--) {
    if (probe.height === this.index.heights[i]) {
      index = i;
      break;
    }
  }

  // And up
  if (index === -1) {
    len = this.index.ts.length;
    for (i = probe.i + 1; i < len && this.index.ts[i] < upper; i++) {
      if (probe.height === this.index.heights[i]) {
        index = i;
        break;
      }
    }
  }

  if (index === -1)
    return false;

  hash = this.index.hashes[index];
  this.index.hashes.splice(index, 1);
  this.index.ts.splice(index, 1);
  this.index.heights.splice(index, 1);

  this.tip = this.getTip();
  this.emit('tip', this.tip);

  // Delete both blocks, let's see what others will choose
  this._delete(hash);

  return true;
};

Chain.prototype.add = function add(block) {
  if (this.loading) {
    this.once('load', function() {
      this.add(block);
    });
    return;
  }

  var initial = block;
  var code = Chain.codes.unchanged;
  var hash, prev, prevProbe, range, hashes;

  for (;;) {
    // Only validate the initial block (orphans were already validated)
    if (block === initial && !block.verify()) {
      code = Chain.codes.invalid;
      break;
    }

    hash = block.hash('hex');
    prev = block.prevBlock;

    // If the block is already known to be an orphan
    if (this.orphan.map[prev]) {
      code = Chain.codes.knownOrphan;
      break;
    }

    prevProbe = this._probeIndex(prev, block.ts);

    // Remove forked nodes from storage, if shorter chain is detected
    if (this._killFork(prevProbe)) {
      code = Chain.codes.forked;
      break;
    }

    // If previous block wasn't ever seen - add current to orphans
    if (!this._probeIndex(hash, block.ts) && !prevProbe) {
      this.orphan.count++;
      this.orphan.map[prev] = block;
      this.orphan.bmap[hash] = block;

      range = this._getRange(hash, block.ts, true);
      hashes = this.index.hashes.slice(range.start, range.end + 1);

      this.emit('missing', prev, hashes, block);
      code = Chain.codes.newOrphan;
      break;
    }

    // Validated known block at this point - add it to index
    if (prevProbe)
      code = this._addIndex(hash, block.ts, prevProbe.height + 1);

    // At least one block was added
    this.block.list.push(block);
    this.block.bloom.add(hash, 'hex');

    // Fullfill request
    this.request.fullfill(hash, block);

    if (!this.orphan.map[hash])
      break;

    // We have orphan child for this block - add it to chain
    block = this.orphan.map[hash];
    delete this.orphan.bmap[block.hash('hex')];
    delete this.orphan.map[hash];
    this.orphan.count--;
  }

  // Failsafe for large orphan chains
  if (this.orphan.count > 10000) {
    this.orphan.map = {};
    this.orphan.bmap = {};
    this.orphan.count = 0;
  }

  // No need to have a huge chain
  // if (this.size() > 100000)
  //   this.compact();

  // Compress old blocks
  this._compress();

  return code;
};

Chain.prototype._compress = function compress() {
  var i;

  // Keep at least 1000 blocks and at most 2000 by default
  if (this.block.list.length < this.cacheLimit)
    return;

  // Bloom filter rebuilt is needed
  this.block.list = this.block.list.slice(-(this.cacheLimit / 2 | 0));
  this.block.bloom.reset();

  for (i = 0; i < this.block.list.length; i++)
    this.block.bloom.add(this.block.list[i].hash('hex'), 'hex');
};

Chain.prototype.has = function has(hash, noIndex, cb) {
  var i;

  if (typeof noIndex === 'function') {
    cb = noIndex;
    noIndex = false;
  }

  if (this.loading) {
    this.once('load', function() {
      this.has(hash, noIndex, cb);
    });
    return;
  }

  cb = utils.asyncify(cb);

  if (this.hasCache(hash))
    return cb(true);

  if (this.hasOrphan(hash))
    return cb(true);

  if (!noIndex) {
    if (this.hasBlock(hash))
      return cb(true);
  }

  return cb(false);
};

Chain.prototype.byHash = function byHash(hash) {
  if (Array.isArray(hash))
    hash = utils.toHex(hash);
  else if (hash.hash)
    hash = hash.hash('hex');

  var index = this.index.hashes.indexOf(hash);

  if (index === -1)
    return null;

  return {
    index: index,
    hash: this.index.hashes[index],
    ts: this.index.ts[index],
    height: this.index.heights[index]
  };
};

Chain.prototype.byHeight = function byHeight(height) {
  var index = this.index.heights.indexOf(height);

  if (index === -1)
    return null;

  return {
    index: index,
    hash: this.index.hashes[index],
    ts: this.index.ts[index],
    height: this.index.heights[index]
  };
};

Chain.prototype.byTime = function byTime(ts) {
  for (var i = this.index.ts.length - 1; i >= 0; i--) {
    if (ts >= this.index.ts[i])
      return this.byHeight(this.index.heights[i]);
  }
  return null;
};

Chain.prototype.hasBlock = function hasBlock(hash) {
  if (Array.isArray(hash))
    hash = utils.toHex(hash);
  else if (hash.hash)
    hash = hash.hash('hex');

  // return this.byHash(hash);
  return this.index.bloom.test(hash, 'hex');
};

Chain.prototype.hasOrphan = function hasOrphan(hash) {
  return !!this.getOrphan(hash);
};

Chain.prototype.hasCache = function hasCache(hash) {
  if (Array.isArray(hash))
    hash = utils.toHex(hash);
  else if (hash.hash)
    hash = hash.hash('hex');

  if (!this.block.bloom.test(hash, 'hex'))
    return false;

  if (this.strict)
    return !!this.getCache(hash);

  return true;
};

Chain.prototype.getBlock = function getBlock(hash) {
  if (typeof hash === 'number')
    return this.byHeight(hash);
  return this.byHash(hash);
};

Chain.prototype.getOrphan = function getOrphan(hash) {
  if (Array.isArray(hash))
    hash = utils.toHex(hash);
  else if (hash.hash)
    hash = hash.hash('hex');

  return this.orphan.bmap[hash] || null;
};

Chain.prototype.getCache = function getCache(hash) {
  var i;

  if (Array.isArray(hash))
    hash = utils.toHex(hash);
  else if (hash.hash)
    hash = hash.hash('hex');

  for (i = 0; i < this.block.list.length; i++) {
    if (this.block.list[i].hash('hex') === hash)
      return this.block.list[i];
  }
};

Chain.prototype.getTip = function() {
  var index = this.index.hashes.length - 1;
  return {
    index: index,
    hash: this.index.hashes[index],
    ts: this.index.ts[index],
    height: this.index.heights[index]
  };
};

Chain.prototype.isFull = function isFull() {
  // < 40m since last block
  if (this.request.count)
    return false;

  var delta = utils.now() - this.index.ts[this.index.ts.length - 1];

  return delta < 40 * 60;
};

Chain.prototype.fillPercent = function fillPercent() {
  var total = (utils.now() - 40 * 60) - this.index.ts[0];
  var current = this.index.ts[this.index.ts.length - 1] - this.index.ts[0];
  return Math.max(0, Math.min(current / total, 1));
};

Chain.prototype.hashRange = function hashRange(start, end) {
  var hashes;

  start = this.byTime(start);
  end = this.byTime(end);

  if (!start || !end)
    return [];

  hashes = this.index.hashes.slice(start.index, end.index + 1);

  return hashes;
};

Chain.prototype.hashesInRange = function hashesInRange(start, end, cb) {
  var ts, hashes, heights, zip, i, count;

  if (this.loading) {
    this.once('load', function() {
      this.hashesInRange(start, end, cb);
    });
    return;
  }

  cb = utils.asyncify(cb);
  ts = this.index.ts;

  start = utils.binaryInsert(ts, start, compareTs, true);
  if (start > 0 && ts[start - 1] >= start)
    start--;

  end = utils.binaryInsert(ts, end, compareTs, true);

  // Zip hashes and heights together and sort them by height
  hashes = this.index.hashes.slice(start, end);
  heights = this.index.heights.slice(start, end);
  zip = [];

  for (i = 0; i < hashes.length; i++)
    zip.push({ hash: hashes[i], height: heights[i] });

  zip = zip.sort(function(a, b) {
    return a.height - b.height;
  });

  hashes = zip.map(function(a) {
    return a.hash;
  });

  count = zip[zip.length - 1].height - zip[0].height + 1;

  return cb(hashes, count);
};

Chain.prototype.getStartHeight = function getStartHeight() {
  return 0;
};

Chain.prototype.locatorHashes = function locatorHashes(obj) {
  var start;

  if (obj) {
    if (Array.isArray(obj))
      obj = utils.toHex(obj);
    else if (obj.hash)
      obj = obj.hash('hex');
  }

  // Convert the start to indexes
  if (obj != null) {
    if (typeof obj === 'string') {
      start = this.byHash(obj);
      if (!start)
        return [obj];
    } else if (typeof obj === 'number') {
      start = this.byHeight(obj);
    }

    assert(start);

    if (start)
      start = start.index;
  }

  return bcoin.fullChain.prototype.locatorHashes.call(this, start);
};

Chain.prototype.getOrphanRoot = function getOrphanRoot(hash) {
  return bcoin.fullChain.prototype.getOrphanRoot.call(this, hash);
};

Chain.prototype.getHeight = function getHeight(hash) {
  var entry = this.byHash(hash);

  if (!entry)
    return -1;

  return entry.height;
};

Chain.prototype.getNextBlock = function getNextBlock(hash) {
  var entry = this.byHeight(hash);
  var nextHeight;

  if (!entry)
    return null;

  nextHeight = this.index.heights[entry.index + 1];

  if (nextHeight == null || nextHeight !== entry.height + 1)
    return null;

  return this.index.hashes[entry.index + 1] || null;
};

Chain.prototype.size = function size() {
  return this.index.hashes.length;
};

Chain.prototype.height = function height() {
  return this.getTip().height;
};

Chain.prototype.target = function target(last) {
  assert(false);
};

Chain.prototype.retarget = function retarget(last, firstTs) {
  assert(false);
};

Chain.prototype.compact = function compact(keep) {
  var index = this._compact(keep);
  this.index.hashes = index.hashes;
  this.index.ts = index.ts;
  this.index.heights = index.heights;
  this.index.bloom.reset();
  this.index.hashes.forEach(function(hash) {
    this.index.bloom.add(hash, 'hex');
  }, this);
};

Chain.prototype._compact = function _compact(keep) {
  keep = keep || 1000;

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
  var i, ts, delta, hdelta;

  for (i = 0; i < this.index.ts.length - keep; i++) {
    ts = this.index.ts[i];

    delta = ts < 1356984000
      ? delta1
      : ts < 1388520000 ? delta2 : delta3;

    hdelta = this.index.heights[i] - lastHeight;

    if (ts - lastTs < delta && hdelta < 250)
      continue;

    lastTs = ts;
    lastHeight = this.index.heights[i];
    first.hashes.push(this.index.hashes[i]);
    first.ts.push(this.index.ts[i]);
    first.heights.push(this.index.heights[i]);
  }

  return {
    hashes: first.hashes.concat(last.hashes),
    ts: first.ts.concat(last.ts),
    heights: first.heights.concat(last.heights)
  };
};

Chain.prototype._save = function(hash, obj) {
  var self = this;

  if (!this.storage)
    return;

  this.storage.put(this.prefix + hash, obj, function(err) {
    if (err)
      self.emit('error', err);
  });
};

Chain.prototype._delete = function(hash) {
  var self = this;

  if (!this.storage)
    return;

  this.storage.del(this.prefix + hash, function(err) {
    if (err)
      self.emit('error', err);
  });
};

Chain.prototype.toJSON = function toJSON() {
  var index = this._compact();
  return {
    v: 1,
    type: 'chain',
    network: network.type,
    hashes: index.hashes,
    ts: index.ts,
    heights: index.heights
  };
};

Chain.prototype.fromJSON = function fromJSON(json) {
  var i;

  assert.equal(json.v, 1);
  assert.equal(json.type, 'chain');

  if (json.network)
    assert.equal(json.network, network.type);

  this.index.hashes = json.hashes.slice();
  this.index.ts = json.ts.slice();
  this.index.heights = json.heights.slice();

  if (this.index.bloom)
    this.index.bloom.reset();
  else
    this.index.bloom = new bcoin.bloom(28 * 1024 * 1024, 16, 0xdeadbeef);

  if (this.index.hashes.length === 0)
    this.add(new bcoin.block(network.genesis, 'block'));

  for (i = 0; i < this.index.hashes.length; i++)
    this.index.bloom.add(this.index.hashes[i], 'hex');
};

/**
 * Expose
 */

module.exports = Chain;
