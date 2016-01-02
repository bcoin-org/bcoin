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
  this.cacheLimit = this.options.cacheLimit || 2000;

  this.tip = null;

  this.orphan = {
    map: {},
    bmap: {},
    count: 0
  };

  this.index = {
    entries: [],
    // Get hash by height
    hashes: [],
    // Get height by hash
    heights: {},
    lastTs: 0
  };

  this.fromJSON({
    v: 1,
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

  // Last TS after preload, needed for fill percent
  this.index.lastTs = this.index.entries[this.index.entries.length - 1].ts;

  bcoin.chain.global = this;

  this.loading = false;
  this._init();
}

inherits(Chain, EventEmitter);

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

  if (this.index.entries[entry.hash])
    return new Error('Already added.');

  if (this.index.hashes[entry.height] === entry.hash)
    return new Error('Duplicate height.');

  checkpoint = network.checkpoints[entry.height];
  if (checkpoint) {
    this.emit('checkpoint', entry.height, entry.hash, checkpoint);
    if (hash !== checkpoint) {
      this.resetLastCheckpoint(entry.height);
      this.emit('fork', entry.height, entry.hash, checkpoint);
      return new Error('Forked chain at checkpoint.');
    }
  }

  this.index.entries[entry.height] = entry;
  this.index.hashes[entry.height] = entry.hash;
  this.index.heights[entry.hash] = entry.height;

  this._save(entry);
};

Chain.prototype.resetLastCheckpoint = function resetLastCheckpoint(height) {
  var lastHeight = Object.keys(network.checkpoints).sort().indexOf(height) - 1;

  if (lastHeight < 0)
    i = 0;

  this.resetHeight(lastHeight);
};

Chain.prototype.resetHeight = function resetHeight(height) {
  var self = this;
  var forked = this.index.entries.slice(height + 1);

  this.orphan.map = {};
  this.orphan.bmap = {};
  this.orphan.count = 0;
  this.index.entries.length = height + 1;
  this.index.heights = this.index.entries.reduce(function(out, entry) {
    out[entry.hash] = entry.height;
    return out;
  }, {});
  this.index.hashes.length = height + 1;

  this.index.lastTs = this.index.entries[this.index.entries.length - 1].ts;

  forked.forEach(function(entry) {
    self._delete(entry);
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
  var err = null;
  var initial = block;
  var hash, prev, prevProbe, range, i, entry;

  for (;;) {
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

    i = this.index.heights[prev];

    // If previous block wasn't ever seen - add current to orphans
    if (i == null) {
      this.orphan.count++;
      this.orphan.map[prev] = block;
      this.orphan.bmap[hash] = block;
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

    // Already have block
    if (this.index.hashes[entry.height] === hash)
      break;

    assert(this.index.heights[entry.hash] == null);

    // Remove forked nodes from storage, if shorter chain is detected
    if (this.index.hashes[entry.height]) {
      if (!this.tip) {
        this.tip = entry;
      } else if (this.tip.chainwork.cmp(entry.chainwork) < 0) {
        // Found fork
        this.resetHeight(entry.height - 1);
        this.tip = entry;
      }
    }

    // Validated known block at this point - add it to index
    this._addIndex(entry);

    // At least one block was added
    res = true;

    if (!this.orphan.map[hash])
      break;

    // We have orphan child for this block - add it to chain
    block = this.orphan.map[hash];
    delete this.orphan.bmap[block.hash('hex')];
    delete this.orphan.map[hash];
    this.orphan.count--;
  }

  return err;
};

Chain.prototype.has = function has(hash, noProbe, cb) {
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

  assert(!noProbe);

  return cb(this.hasBlock(hash) || this.hasOrphan(hash));
};

Chain.prototype.byHeight = function byHeight(height) {
  if (this.loading)
    return null;

  return this.index.entries[height] || null;
};

Chain.prototype.byHash = function byHash(hash) {
  if (this.loading)
    return null;

  if (Array.isArray(hash))
    hash = utils.toHex(hash);
  else if (hash.hash)
    hash = hash.hash('hex');

  return this.byHeight(this.index.heights[hash]);
};

Chain.prototype.getTip = function getTip() {
  if (this.loading)
    return null;

  return this.index.entries[this.index.entries.length - 1];
};

Chain.prototype.hasBlock = function hasBlock(hash) {
  if (this.loading)
    return false;

  return !!this.byHash(hash);
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
  assert(false);
};

Chain.prototype.isFull = function isFull() {
  var last = this.index.entries[this.index.entries.length - 1].ts;
  var delta = (+new Date() / 1000) - last;
  return delta < 40 * 60;
};

Chain.prototype.fillPercent = function fillPercent() {
  var total = (+new Date() / 1000 - 40 * 60) - this.index.lastTs;
  var current = this.index.entries[this.index.entries.length - 1].ts - this.index.lastTs;
  return Math.max(0, Math.min(current / total, 1));
};

Chain.prototype.hashesInRange = function hashesInRange(start, end, cb) {
  assert(false);
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
  if (this.loading)
    return 0;

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
    // Hash
    if (this.index.heights[start])
      top = this.index.heights[start];
  } else if (typeof start === 'number') {
    // Height
    top = start;
  }

  i = top;
  for (;;) {
    hashes.push(chain[i]);
    i = i - step;
    if (i <= 0) {
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
  return this.index.entries.length;
};

Chain.prototype.height = function height() {
  return this.getTip().height;
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

Chain.prototype.toJSON = function toJSON() {
  var entries = this.index.entries;

  return {
    v: 1,
    type: 'chain',
    network: network.type,
    entries: entries.map(function(entry) {
      return entry.toJSON();
    })
  };
};

Chain.prototype.fromJSON = function fromJSON(json) {
  assert.equal(json.v, 1);
  assert.equal(json.type, 'chain');
  assert.equal(json.network, network.type);

  json.entries.forEach(function(entry) {
    this._addIndex(ChainBlock.fromJSON(this, entry));
  }, this);

  if (this.index.entries.length === 0)
    this.add(new bcoin.block(network.genesis, 'block'));
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

Chain.prototype.target = function target(last) {
  var proofOfWorkLimit = utils.toCompact(network.powLimit);
  var adjustmentInterval = network.powTargetTimespan / network.powTargetSpacing;
  var newBlockTs, heightFirst, first;

  adjustmentInterval |= 0;

  if (!last)
    last = this.getTip();

  // Do not retarget
  if ((last.height + 1) % adjustmentInterval) {
    if (network.powAllowMinDifficultyBlocks) {
      // Special behavior for testnet:
      newBlockTs = Date.now() / 1000 | 0;
      if (newBlockTs > last.ts + network.powTargetSpacing * 2)
        return proofOfWorkLimit;

      while (last.prev
        && last.height % adjustmentInterval !== 0
        && last.bits !== proofOfWorkLimit) {
        last = last.prev;
      }

      return last.bits;
    }
    return last.bits;
  }

  // Back 2 weeks
  heightFirst = last.height - (adjustmentInterval - 1);
  first = this.byHeight(heightFirst);

  if (!first)
    return 0;

  return this.retarget(last, first.ts);
};

Chain.prototype.retarget = function retarget(last, firstTs) {
  var powTargetTimespan = new bn(network.powTargetTimespan);
  var actualTimespan, powLimit, target;

  if (network.powNoRetargeting)
    return last.bits;

  actualTimespan = new bn(last.ts).subn(firstTs);
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
