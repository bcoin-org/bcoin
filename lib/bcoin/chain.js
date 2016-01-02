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

  if (this._probeIndex(hash, ts))
    return new Error('Already added.');

  var pos = utils.binaryInsert(this.index.ts, ts, compareTs, true);
  var checkpoint;

  // Avoid duplicates
  if (this.index.hashes[pos] === hash
      || this.index.hashes[pos - 1] === hash
      || this.index.hashes[pos + 1] === hash) {
    return new Error('Duplicate height.');
  }

  checkpoint = network.checkpoints[height];
  if (checkpoint) {
    this.emit('checkpoint', height, hash, checkpoint);
    if (hash !== checkpoint) {
      this.resetLastCheckpoint(height);
      this.emit('fork', height, hash, checkpoint);
      return new Error('Forked chain at checkpoint.');
    }
  }

  this.index.ts.splice(pos, 0, ts);
  this.index.hashes.splice(pos, 0, hash);
  this.index.heights.splice(pos, 0, height);
  this.index.bloom.add(hash, 'hex');

  this._save(hash, {
    ts: ts,
    height: height
  });
};

Chain.prototype.resetLastCheckpoint = function resetLastCheckpoint(height) {
  var lastHeight = Object.keys(network.checkpoints).sort().indexOf(height) - 1;

  if (lastHeight < 0)
    i = 0;

  this.resetHeight(lastHeight);
};

Chain.prototype.resetHeight = function resetHeight(height) {
  var self = this;
  var index = this.index.heights.indexOf(height);

  if (index < 0)
    throw new Error('Cannot reset to height of ' + height);

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
  this.index.lastTs = this.index.ts[this.index.ts.length - 1];
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

  var res = false;
  var err = null;
  var initial = block;
  var hash, prev, prevProbe, range, hashes;

  do {
    // No need to revalidate orphans
    if (!res && !block.verify()) {
      err = new Error('Block verification failed.');
      break;
    }

    hash = block.hash('hex');
    prev = block.prevBlock;

    // If the block is already known to be an orphan
    if (this.orphan.map[prev]) {
      err = new Error('Block is a known orphan.');
      break;
    }

    prevProbe = this._probeIndex(prev, block.ts);

    // Remove forked nodes from storage, if shorter chain is detected
    if (this._killFork(prevProbe)) {
      err = new Error('Fork found.');
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
      break;
    }

    // Validated known block at this point - add it to index
    if (prevProbe) {
      this._addIndex(hash, block.ts, prevProbe.height + 1);
      block.height = prevProbe.height + 1;
    }

    // At least one block was added
    res = true;
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
  } while (true);

  // Compress old blocks
  this._compress();

  return err;
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

Chain.prototype.has = function has(hash, noProbe, cb) {
  var i;

  if (typeof noProbe === 'function') {
    cb = noProbe;
    noProbe = false;
  }

  if (this.loading) {
    this.once('load', function() {
      this.has(hash, noProbe, cb);
    });
    return;
  }

  cb = utils.asyncify(cb);

  if (this.block.bloom.test(hash, 'hex')) {
    if (this.strict) {
      for (i = 0; i < this.block.list.length; i++)
        if (this.block.list[i].hash('hex') === hash)
          return cb(true);
    } else {
      return cb(true);
    }
  }

  if (!noProbe && this.index.bloom.test(hash, 'hex')) {
    // XXX find hash
    return cb(true);
  }

  if (this.hasOrphan(hash))
    return cb(true);

  return cb(false);
};

Chain.prototype.byHeight = function byHeight(height) {
  if (this.loading)
    return null;

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

Chain.prototype.getTip = function() {
  var index = this.index.hashes.length - 1;
  return {
    index: index,
    hash: this.index.hashes[index],
    ts: this.index.ts[index],
    height: this.index.heights[index]
  };
};

Chain.prototype.byHash = function byHash(hash) {
  if (this.loading)
    return null;

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

Chain.prototype.hasBlock = function hasBlock(hash) {
  if (this.loading)
    return false;

  if (Array.isArray(hash))
    hash = utils.toHex(hash);
  else if (hash.hash)
    hash = hash.hash('hex');

  return this.index.bloom.test(hash, 'hex');
};

Chain.prototype.hasOrphan = function hasOrphan(hash) {
  if (this.loading)
    return false;

  if (Array.isArray(hash))
    hash = utils.toHex(hash);
  else if (hash.hash)
    hash = hash.hash('hex');

  return !!this.orphan.bmap[hash];
};

Chain.prototype.get = function get(hash, force, cb) {
  var i, block;

  if (typeof force === 'function') {
    cb = force;
    force = false;
  }

  // Cached block found
  if (!force && this.block.bloom.test(hash, 'hex')) {
    for (i = 0; i < this.block.list.length; i++) {
      if (this.block.list[i].hash('hex') === hash) {
        // NOTE: we return right after the statement - so `block` should be
        // valid at the time of nextTick call
        block = this.block.list[i];
        bcoin.utils.nextTick(function() {
          cb(block);
        });
        return;
      }
    }
    // False positive:
    // assert(false);
  }

  if (!force && this.orphan.bmap[hash])
    return cb(this.orphan.bmap[hash]);

  if (this.request.add(hash, cb))
    this.emit('missing', hash, null, null);
};

Chain.prototype.isFull = function isFull() {
  // < 40m since last block
  if (this.request.count)
    return false;

  var delta = (+new Date() / 1000) - this.index.ts[this.index.ts.length - 1];

  return delta < 40 * 60;
};

Chain.prototype.fillPercent = function fillPercent() {
  var total = (+new Date() / 1000 - 40 * 60) - this.index.lastTs;
  var current = this.index.ts[this.index.ts.length - 1] - this.index.lastTs;
  return Math.max(0, Math.min(current / total, 1));
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

Chain.prototype.getStartHeight = function getStartHeight() {
  return 0;
};

Chain.prototype.locatorHashes = function locatorHashes(start) {
  assert(start == null);

  if (this.index.hashes.length === 1)
    return [this.index.hashes[0]];

  return [
    this.index.hashes[this.index.hashes.length - 1],
    this.index.hashes[0]
  ];
};

Chain.prototype.getOrphanRoot = function getOrphanRoot(hash) {
  assert(false);
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
    v: 1,
    type: 'chain',
    network: network.type,
    hashes: first.hashes.concat(last.hashes),
    ts: first.ts.concat(last.ts),
    heights: first.heights.concat(last.heights)
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
