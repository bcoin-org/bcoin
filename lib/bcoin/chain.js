/**
 * fullchain.js - fullnode blockchain management for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

var inherits = require('inherits');
var EventEmitter = require('events').EventEmitter;

var bcoin = require('../bcoin');
var bn = require('bn.js');
var constants = bcoin.protocol.constants;
var network = bcoin.protocol.network;
var utils = bcoin.utils;
var assert = utils.assert;

/**
 * Chain
 */

function Chain(options) {
  if (!(this instanceof Chain))
    return new Chain(options);

  EventEmitter.call(this);

  this.options = options || {};
  this.prefix = 'bt/chain/';
  this.storage = this.options.storage;
  this.strict = this.options.strict || false;

  this.tip = null;

  this.orphan = {
    map: {},
    bmap: {},
    count: 0,
    size: 0
  };

  this.index = {
    entries: [],
    // Get hash by height
    hashes: [],
    // Get height by hash
    heights: {},
    count: 0,
    lastTs: 0
  };

  this.request = new utils.RequestCache();

  this.fromJSON({
    v: 2,
    type: 'chain',
    network: network.type,
    entries: [
      {
        hash: utils.toHex(network.genesis._hash),
        version: network.genesis.version,
        // prevBlock: utils.toHex(network.genesis.prevBlock),
        ts: network.genesis.ts,
        bits: network.genesis.bits,
        height: 0
      }
    ]
  });

  if (!this.options.fullNode)
    this.fromJSON(network.preload);

  this.tip = this.index.entries[this.index.entries.length - 1];

  // Last TS after preload, needed for fill percent
  this.index.lastTs = this.index.entries[this.index.entries.length - 1].ts;

  Chain.global = this;

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
    data.value.hash = data.key.slice(self.prefix.length);
    self._addIndex(ChainBlock.fromJSON(self, data.value));
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

Chain.prototype._addIndex = function _addIndex(entry) {
  var self = this;

  // Already added
  if (this.index.heights[entry.hash] != null) {
    assert(this.index.heights[entry.hash] === entry.height);
    return Chain.codes.unchanged;
  }

  // Duplicate height
  if (this.index.hashes[entry.height] === entry.hash)
    return Chain.codes.unchanged;

  // Fork at checkpoint
  checkpoint = network.checkpoints[entry.height];
  if (checkpoint) {
    this.emit('checkpoint', entry.height, entry.hash, checkpoint);
    if (hash !== checkpoint) {
      this.emit('fork', entry.height, entry.hash, checkpoint);
      return Chain.codes.badCheckpoint;
    }
  }

  this.index.entries[entry.height] = entry;
  this.index.hashes[entry.height] = entry.hash;
  this.index.heights[entry.hash] = entry.height;
  this.index.count++;

  this.tip = this.index.entries[this.index.entries.length - 1];
  this.emit('tip', this.tip);

  this._save(entry);

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
  var ahead = this.index.entries.slice(height + 1);

  assert(height < this.index.entries.length);

  if (height === this.index.entries.length - 1)
    return;

  this.orphan.map = {};
  this.orphan.bmap = {};
  this.orphan.count = 0;
  this.orphan.size = 0;
  this.index.entries.length = height + 1;
  this.index.heights = this.index.entries.reduce(function(out, entry) {
    if (!self.options.fullNode) {
      if (!entry)
        return out;
    }
    out[entry.hash] = entry.height;
    return out;
  }, {});
  this.index.hashes.length = height + 1;

  if (!this.options.fullNode)
    this.index.count -= this._count(ahead);
  else
    this.index.count = height + 1;

  this.tip = this.index.entries[this.index.entries.length - 1];
  this.emit('tip', this.tip);

  this.index.lastTs = Math.min(
    this.index.lastTs,
    this.index.entries[this.index.entries.length - 1].ts
  );

  ahead.forEach(function(entry) {
    if (!self.options.fullNode) {
      if (!entry)
        return;
    }
    self._delete(entry.hash);
  });
};

Chain.prototype.resetTime = function resetTime(ts) {
  var entry = this.byTime(ts);
  if (!entry)
    return;
  return this.resetHeight(entry.height);
};

Chain.prototype.add = function add(block, peer) {
  if (this.loading) {
    this.once('load', function() {
      this.add(block);
    });
    return;
  }

  var initial = block;
  var code = Chain.codes.unchanged;
  var hash, prev, i, entry;

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

    i = this.index.heights[prev];

    // If previous block wasn't ever seen - add current to orphans
    if (i == null) {
      this.orphan.count++;
      this.orphan.size += block.size();
      this.orphan.map[prev] = block;
      this.orphan.bmap[hash] = block;
      code = Chain.codes.newOrphan;
      break;
    }

    entry = new ChainBlock(this, {
      hash: hash,
      version: block.version,
      // prevBlock: prev,
      ts: block.ts,
      bits: block.bits,
      height: i + 1
    });

    // Add entry if we do not have it (or there is another hash at its height)
    if (this.index.hashes[entry.height] !== hash) {
      assert(this.index.heights[entry.hash] == null);

      // If we have a block at the same height, use chain with higher work
      if (this.index.hashes[entry.height]) {
        if (this.tip.chainwork.cmp(entry.chainwork) < 0) {
          if (!block.postVerify()) {
            throw new Error;
            //code = Chain.codes.invalid;
            //break;
          }
          this.resetHeight(entry.height - 1);
          code = this._addIndex(entry);
          assert(code !== Chain.codes.unchanged);
          if (code !== Chain.codes.okay)
            break;
          code = Chain.codes.forked;
          // Breaking here only works because
          // we deleted the orphan map in resetHeight.
          this.emit('block', block, peer);
          this.emit('entry', entry);
          if (block !== initial)
            this.emit('resolved', entry);
          break;
        }
      }

      // Validated known block at this point - add it to index
      if (!block.postVerify()) {
        throw new Error;
        //code = Chain.codes.invalid;
        //break;
      }
      code = this._addIndex(entry);
      assert(code !== Chain.codes.unchanged);
      if (code !== Chain.codes.okay)
        break;
      this.emit('block', block, peer);
      this.emit('entry', entry);
      if (block !== initial)
        this.emit('resolved', entry);
    }

    // Fullfill request
    this.request.fullfill(hash, block);

    if (!this.orphan.map[hash])
      break;

    // We have orphan child for this block - add it to chain
    block = this.orphan.map[hash];
    delete this.orphan.bmap[block.hash('hex')];
    delete this.orphan.map[hash];
    this.orphan.count--;
    this.orphan.size -= block.size();
  }

  // Failsafe for large orphan chains
  if (this.orphan.size > 20971520) {
    this.orphan.map = {};
    this.orphan.bmap = {};
    this.orphan.count = 0;
    this.orphan.size = 0;
  }

  // No need to have a huge chain
  // if (!this.options.fullNode) {
  //   if (this.size() > 100000)
  //     this.compact();
  // }

  return code;
};

Chain.prototype.has = function has(hash, cb) {
  if (this.loading) {
    this.once('load', function() {
      this.has(hash, noIndex, cb);
    });
    return;
  }

  cb = utils.asyncify(cb);

  return cb(this.hasBlock(hash) || this.hasOrphan(hash));
};

Chain.prototype.byHeight = function byHeight(height) {
  return this.index.entries[height] || null;
};

Chain.prototype.byHash = function byHash(hash) {
  if (Array.isArray(hash))
    hash = utils.toHex(hash);
  else if (hash.hash)
    hash = hash.hash('hex');

  return this.byHeight(this.index.heights[hash]);
};

Chain.prototype.byTime = function byTime(ts) {
  for (var i = this.index.entries.length - 1; i >= 0; i--) {
    if (!this.options.fullNode) {
      if (!this.index.entries[i])
        continue;
    }
    if (ts >= this.index.entries[i].ts)
      return this.index.entries[i];
  }
  return null;
};

Chain.prototype.hasBlock = function hasBlock(hash) {
  return !!this.byHash(hash);
};

Chain.prototype.hasOrphan = function hasOrphan(hash) {
  return !!this.getOrphan(hash);
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

Chain.prototype.getTip = function getTip() {
  return this.index.entries[this.index.entries.length - 1];
};

Chain.prototype.isFull = function isFull() {
  var last = this.index.entries[this.index.entries.length - 1].ts;
  var delta = utils.now() - last;
  return delta < 40 * 60;
};

Chain.prototype.fillPercent = function fillPercent() {
  var total = (utils.now() - 40 * 60) - this.index.lastTs;
  var current = this.getTip().ts - this.index.lastTs;
  return Math.max(0, Math.min(current / total, 1));
};

Chain.prototype.hashRange = function hashRange(start, end) {
  var hashes;

  start = this.byTime(start);
  end = this.byTime(end);

  if (!start || !end)
    return [];

  hashes = this.index.hashes.slice(start.height, end.height + 1);

  if (!this.options.fullNode)
    hashes = this._filter(hashes);

  return hashes;
};

Chain.prototype.getStartHeight = function getStartHeight() {
  return this.index.entries[this.index.entries.length - 1].height;
};

Chain.prototype.locatorHashes = function locatorHashes(start) {
  var chain = this.index.hashes;
  var hashes = [];
  var top = chain.length - 1;
  var step = 1;
  var i;

  if (start) {
    if (Array.isArray(start))
      start = utils.toHex(start);
    else if (start.hash)
      start = start.hash('hex');
  }

  if (typeof start === 'string') {
    top = this.index.heights[start];
    if (top == null) {
      // return [start];
      hashes.push(start);
      top = chain.length - 1;
    }
  } else if (typeof start === 'number') {
    top = start;
  }

  assert(chain[top]);

  i = top;
  for (;;) {
    if (chain[i])
      hashes.push(chain[i]);
    i = i - step;
    if (i <= 0) {
      if (i + step !== 0)
        hashes.push(chain[0]);
      break;
    }
    if (hashes.length >= 10)
      step *= 2;
  }

  return hashes;
};

Chain.prototype.getOrphanRoot = function getOrphanRoot(hash) {
  var self = this;
  var root = hash;

  if (Array.isArray(hash))
    hash = utils.toHex(hash);
  else if (hash.hash)
    hash = hash.hash('hex');

  while (this.orphan.bmap[hash]) {
    root = hash;
    hash = this.orphan.bmap[hash].prevBlock;
  }

  return root;
};

Chain.prototype.getHeight = function getHeight(hash) {
  var entry = this.byHash(hash);
  if (!entry)
    return -1;

  return entry.height;
};

Chain.prototype.getNextBlock = function getNextBlock(hash) {
  var entry = this.byHash(hash);

  if (!entry || !entry.next)
    return null;

  return entry.next.hash;
};

Chain.prototype.size = function size() {
  return this.index.count;
};

Chain.prototype.height = function height() {
  return this.getTip().height;
};

Chain.prototype.target = function target(last, block) {
  var powLimit = utils.toCompact(network.powLimit);
  var interval = network.powTargetTimespan / network.powTargetSpacing | 0;
  var first, ts;

  if (!last)
    last = this.getTip();

  // Do not retarget
  if ((last.height + 1) % interval) {
    if (network.powAllowMinDifficultyBlocks) {
      // Special behavior for testnet:
      ts = block ? (block.ts || block) : utils.now();
      if (ts > last.ts + network.powTargetSpacing * 2)
        return powLimit;

      while (last.prev
        && last.height % interval !== 0
        && last.bits !== powLimit) {
        last = last.prev;
      }

      return last.bits;
    }
    return last.bits;
  }

  // Back 2 weeks
  first = this.byHeight(last.height - (interval - 1));

  if (!first)
    return 0;

  return this.retarget(last, first);
};

Chain.prototype.retarget = function retarget(last, first) {
  var powTargetTimespan = new bn(network.powTargetTimespan);
  var actualTimespan, powLimit, target;

  if (network.powNoRetargeting)
    return last.bits;

  actualTimespan = new bn(last.ts).subn(first.ts);
  if (actualTimespan.cmp(powTargetTimespan.divn(4)) < 0)
    actualTimespan = powTargetTimespan.divn(4);

  if (actualTimespan.cmp(powTargetTimespan.muln(4)) > 0)
    actualTimespan = powTargetTimespan.muln(4);

  powLimit = network.powLimit;
  target = utils.fromCompact(last.bits);
  target.imul(actualTimespan);
  target = target.div(powTargetTimespan);
  if (target.cmp(powLimit) > 0)
    target = powLimit.clone();

  return utils.toCompact(target);
};

Chain.prototype.compact = function compact(keep) {
  var entries = this._compact(keep);
  this.index.entries = {};
  this.index.hashes = [];
  this.index.heights = {};
  this.index.count = 0;
  json.entries.forEach(function(entry) {
    this._addIndex(ChainBlock.fromJSON(this, entry));
  }, this);
};

Chain.prototype._compact = function _compact(keep) {
  var entries = this._filter(this.index.entries);

  if (!keep)
    keep = 1000;

  // Keep only last 1000 consequent blocks, dilate others at:
  // 7 day range for blocks before 2013
  // 12 hour for blocks before 2014
  // 6 hour for blocks in 2014 and after it
  // (or at maximum 250 block range)
  var last = entries.slice(-keep);

  var first = [];

  var delta1 = 7 * 24 * 3600;
  var delta2 = 12 * 3600;
  var delta3 = 6 * 3600;

  var lastTs = 0;
  var lastHeight = -1000;
  var i, ts, delta, hdelta;

  for (i = 0; i < entries.length - keep; i++) {
    ts = entries[i].ts;

    delta = ts < 1356984000
      ? delta1
      : ts < 1388520000 ? delta2 : delta3;

    hdelta = entries[i].height - lastHeight;

    if (ts - lastTs < delta && hdelta < 250)
      continue;

    lastTs = ts;
    lastHeight = entries[i].height;
    first.push(this.index.entries[i]);
  }

  return first.concat(last);
};

Chain.prototype._save = function(hash, obj) {
  var self = this;

  if (!this.storage)
    return;

  this.storage.put(this.prefix + hash, obj.toJSON(), function(err) {
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

Chain.prototype._count = function(obj) {
  for (var i = 0, c = 0; i < obj.length; i++)
    if (obj[i])
      c++;
  return c;
};

Chain.prototype._filter = function(obj) {
  for (var i = 0, a = []; i < obj.length; i++)
    if (obj[i])
      a.push(obj[i]);
  return a;
};

Chain.prototype.toJSON = function toJSON() {
  var entries = this.index.entries;

  if (!this.options.fullNode)
    entries = this._compact();

  return {
    v: 2,
    type: 'chain',
    network: network.type,
    entries: entries.map(function(entry) {
      return entry.toJSON();
    })
  };
};

Chain.prototype.fromJSON = function fromJSON(json) {
  assert.equal(json.v, 2);
  assert.equal(json.type, 'chain');
  assert.equal(json.network, network.type);

  json.entries.forEach(function(entry) {
    this._addIndex(ChainBlock.fromJSON(this, entry));
  }, this);

  assert(this.index.entries.length > 0);
};

/**
 * ChainBlock
 */

function ChainBlock(chain, data) {
  this.chain = chain;
  this.hash = data.hash;
  this.version = data.version;
  // this.prevBlock = data.prevBlock;
  this.ts = data.ts;
  this.bits = data.bits;
  this.height = data.height;
  this.chainwork = this.getChainwork();
}

ChainBlock.prototype.__defineGetter__('prev', function() {
  return this.chain.index.entries[this.height - 1];
});

ChainBlock.prototype.__defineGetter__('next', function() {
  return this.chain.index.entries[this.height + 1];
});

ChainBlock.prototype.__defineGetter__('proof', function() {
  var target = utils.fromCompact(this.bits);
  if (target.isNeg() || target.cmpn(0) === 0)
    return new bn(0);
  // May be faster:
  // return new bn(1).shln(256).div(target.addn(1));
  return new bn(2).pow(new bn(256)).div(target.addn(1));
});

ChainBlock.prototype.getChainwork = function() {
  if (!this.prev)
    return new bn(0);

  return (this.prev ? this.prev.chainwork : new bn(0)).add(this.proof);
};

ChainBlock.prototype.getMedianTime = function() {
  var entry = this;
  var median = [];
  var timeSpan = constants.block.medianTimespan;
  var i;

  for (i = 0; i < timeSpan && entry; i++, entry = entry.prev)
    median.push(entry.ts);

  median = median.sort();

  return median[median.length / 2 | 0];
};

ChainBlock.prototype.isOutdated = function(version) {
  return this.isSuperMajority(version,
    network.block.majorityRejectBlockOutdated);
};

ChainBlock.prototype.needsUpgrade = function(version) {
  return this.isSuperMajority(version,
    network.block.majorityEnforceBlockUpgrade);
};

ChainBlock.prototype.isSuperMajority = function(version, required) {
  var entry = this;
  var found = 0;
  var majorityWindow = network.block.majorityWindow;
  var i;

  for (i = 0; i < majorityWindow && found < required && entry; i++) {
    if (entry.version >= version)
      found++;
    entry = entry.prev;
  }

  return found >= required;
};

ChainBlock.prototype.toJSON = function() {
  // return [
  //   this.hash,
  //   this.version,
  //   // this.prevBlock,
  //   this.ts,
  //   this.bits,
  //   this.height
  // };
  return {
    hash: this.hash,
    version: this.version,
    // prevBlock: this.prevBlock,
    ts: this.ts,
    bits: this.bits,
    height: this.height
  };
};

ChainBlock.fromJSON = function(chain, json) {
  // return new ChainBlock(chain, {
  //   hash: json[0],
  //   version: json[1],
  //   ts: json[2],
  //   bits: json[3],
  //   height: json[4]
  // });
  return new ChainBlock(chain, json);
};

/**
 * Expose
 */

module.exports = Chain;
