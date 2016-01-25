/**
 * chain.js - blockchain management for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

var inherits = require('inherits');
var EventEmitter = require('events').EventEmitter;

var bcoin = require('../bcoin');
var bn = require('bn.js');
var fs = require('fs');
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

  if (!options)
    options = {};

  this.options = options;

  if (this.options.debug)
    bcoin.debug = this.options.debug;

  this.db = new ChainDB(this);
  this.heightLookup = {};
  this.request = new utils.RequestCache();
  this.loading = false;
  this.tip = null;

  this.orphan = {
    map: {},
    bmap: {},
    count: 0,
    size: 0
  };

  this._saveEntry(ChainBlock.fromJSON(this, {
    hash: network.genesis.hash,
    version: network.genesis.version,
    prevBlock: network.genesis.prevBlock,
    merkleRoot: network.genesis.merkleRoot,
    ts: network.genesis.ts,
    bits: network.genesis.bits,
    nonce: network.genesis.nonce,
    height: 0
  }), true);

  Chain.global = this;

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
  return Chain.messages[code] || 'Unknown';
};

Chain.prototype._init = function _init() {
  var self = this;

  this.loading = true;

  utils.debug('Chain is loading.');

  utils.nextTick(function() {
    var count = self.db.count();
    var entry;
    var i = 1;

    function done() {
      self.loading = false;
      self.emit('load');

      utils.debug('Chain successfully loaded.');
    }

    (function next() {
      if (i >= count)
        return done();
      self.db.getAsync(i, function(err, entry) {
        if (err)
          throw err;
        self._saveEntry(entry);
        i += 1;
        next();
      });
    })();
  });
};

Chain.prototype._addEntry = function _addEntry(entry) {
  var self = this;
  var existing;

  // Already added
  if (this.heightLookup[entry.hash] != null) {
    assert(this.heightLookup[entry.hash] === entry.height);
    return Chain.codes.unchanged;
  }

  // Duplicate height
  existing = this.db.get(entry.height);
  if (existing && existing.hash === entry.hash)
    return Chain.codes.unchanged;

  // Fork at checkpoint
  checkpoint = network.checkpoints[entry.height];
  if (checkpoint) {
    this.emit('checkpoint', entry.height, entry.hash, checkpoint);
    if (hash !== checkpoint) {
      // Resetting to the last checkpoint _really_ isn't
      // necessary (even bitcoind doesn't do it), but it
      // could be used if you want to be on the overly
      // safe (see: paranoid) side.
      // this.resetLastCheckpoint(entry.height);
      return Chain.codes.badCheckpoint;
    }
  }

  this._saveEntry(entry, true);

  return Chain.codes.okay;
};

Chain.prototype._saveEntry = function _saveEntry(entry, save) {
  if (save)
    this.db.save(entry);

  this.heightLookup[entry.hash] = entry.height;

  if (!this.tip || entry.height > this.tip.height) {
    this.tip = entry;
    this.emit('tip', this.tip);
  }
};

Chain.prototype.resetLastCheckpoint = function resetLastCheckpoint(height) {
  var heights = Object.keys(network.checkpoints).sort();
  var index = heights.indexOf(height) - 1;
  var checkpoint = network.checkpoint[index];

  assert(index >= 0);
  assert(checkpoint);

  // This is the safest way to do it, the other
  // possibility is to simply reset ignore the
  // bad checkpoint block. The likelihood of
  // someone carrying on an entire fork between
  // to checkpoints is absurd, so this is
  // probably _a lot_ of work for nothing.
  this.resetHeight(checkpoint.height);
};

Chain.prototype.resetHeight = function resetHeight(height) {
  var self = this;
  var count = this.db.count();
  var i, existing;

  assert(height < count);

  // Reset the orphan map completely. There may
  // have been some orphans on a forked chain we
  // no longer need.
  this.orphan.map = {};
  this.orphan.bmap = {};
  this.orphan.count = 0;
  this.orphan.size = 0;

  for (i = height + 1; height < count; i++) {
    existing = this.db.get(i);
    assert(existing);
    delete this.heightLookup[existing.hash];
    this.db.remove(i);
  }

  this.tip = this.db.get(height);
  this.emit('tip', this.tip);
};

Chain.prototype.resetTime = function resetTime(ts) {
  var entry = this.byTime(ts);
  if (!entry)
    return;
  return this.resetHeight(entry.height);
};

Chain.prototype.add = function add(block, peer) {
  var initial = block;
  var code = Chain.codes.unchanged;
  var hash, prevHash, prevHeight, entry, tip, existing;
  var total = 0;

  for (;;) {
    hash = block.hash('hex');
    prevHash = block.prevBlock;

    // Find the previous block height/index.
    prevHeight = this.heightLookup[prevHash];

    // Validate the block we want to add.
    // This is only necessary for new
    // blocks coming in, not the resolving
    // orphans.
    if (block === initial && !block.verify()) {
      code = Chain.codes.invalid;
      this.emit('invalid', {
        height: prevHeight + 1,
        hash: hash
      }, peer);
      break;
    }

    // If the block is already known to be
    // an orphan, ignore it.
    if (this.orphan.map[prevHash]) {
      // If the orphan chain forked, simply
      // reset the orphans and find a new peer.
      if (this.orphan.map[prevHash].hash('hex') !== hash) {
        this.orphan.map = {};
        this.orphan.bmap = {};
        this.orphan.count = 0;
        this.orphan.size = 0;
        this.emit('fork', {
          height: -1,
          expected: this.orphan.map[prevHash].hash('hex'),
          received: hash,
          checkpoint: false
        }, peer);
        code = Chain.codes.forked;
        break;
      }
      code = Chain.codes.knownOrphan;
      break;
    }

    // If previous block wasn't ever seen,
    // add it current to orphans and break.
    if (prevHeight == null) {
      this.orphan.count++;
      this.orphan.size += block.size();
      this.orphan.map[prevHash] = block;
      this.orphan.bmap[hash] = block;
      code = Chain.codes.newOrphan;
      total++;
      break;
    }

    // Create a new chain entry.
    entry = new ChainBlock(this, {
      hash: hash,
      version: block.version,
      prevBlock: prevHash,
      merkleRoot: block.merkleRoot,
      ts: block.ts,
      bits: block.bits,
      nonce: block.nonce,
      height: prevHeight + 1
    });

    // Add entry if we do not have it (or if
    // there is another entry at its height)
    existing = this.db.get(entry.height);
    if (!existing || existing.hash !== hash) {
      assert(this.heightLookup[entry.hash] == null);

      // A valid block with an already existing
      // height came in, that spells fork. We
      // don't store by hash so we can't compare
      // chainworks. We reset the chain, find a
      // new peer, and wait to see who wins.
      if (existing) {
        // The tip has more chainwork, it is a
        // higher height than the entry. This is
        // not an alternate tip. Ignore it.
        if (this.tip.chainwork.cmp(entry.chainwork) > 0) {
          code = Chain.codes.unchanged;
          break;
        }
        // Get _our_ tip as opposed to
        // the attempted alternate tip.
        tip = existing;
        // The block has equal chainwork (an
        // alternate tip). Reset the chain, find
        // a new peer, and wait to see who wins.
        this.resetHeight(entry.height - 1);
        this.emit('fork', {
          height: prevHeight + 1,
          expected: tip.hash,
          received: hash,
          checkpoint: false
        }, peer);
        code = Chain.codes.forked;
        break;
      }

      // Do "contextual" verification on our block
      // now that we're certain its previous
      // block is in the chain.
      if (!block.verifyContext()) {
        code = Chain.codes.invalid;
        this.emit('invalid', {
          height: prevHeight + 1,
          hash: hash
        }, peer);
        break;
      }

      // Attempt to add block to the chain index.
      code = this._addEntry(entry);

      // Result should never be `unchanged` since
      // we already verified there were no
      // duplicate heights, etc.
      assert(code !== Chain.codes.unchanged);

      // Block did not match the checkpoint. The
      // chain could be reset to the last sane
      // checkpoint, but it really isn't necessary,
      // so we don't do it. The misbehaving peer has
      // been killed and hopefully we find a peer
      // who isn't trying to fool us.
      if (code === Chain.codes.badCheckpoint) {
        this.emit('fork', {
          height: entry.height,
          expected: network.checkpoints[entry.height],
          received: entry.hash,
          checkpoint: true
        });
        break;
      }

      // Should never happen, but... something
      // went wrong. Ignore this block.
      if (code !== Chain.codes.okay)
        break;

      // Keep track of the number of blocks we
      // added and the number of orphans resolved.
      total++;

      // Emit our block (and potentially resolved
      // orphan) so the programmer can save it.
      this.emit('block', block, peer);
      this.emit('entry', entry);
      if (block !== initial)
        this.emit('resolved', entry);
    }

    // Fullfill request
    this.request.fullfill(hash, block);

    if (!this.orphan.map[hash])
      break;

    // An orphan chain was found, start resolving.
    block = this.orphan.map[hash];
    delete this.orphan.bmap[block.hash('hex')];
    delete this.orphan.map[hash];
    this.orphan.count--;
    this.orphan.size -= block.size();
  }

  // Failsafe for large orphan chains. Do not
  // allow more than 20mb stored in memory.
  if (this.orphan.size > 20971520) {
    this.orphan.map = {};
    this.orphan.bmap = {};
    this.orphan.count = 0;
    this.orphan.size = 0;
  }

  if (code !== Chain.codes.okay) {
    if (!(this.options.multiplePeers && code === Chain.codes.newOrphan))
      utils.debug('Chain Error: %s', Chain.msg(code));
  }

  return total;
};

Chain.prototype.has = function has(hash) {
  if (this.hasBlock(hash))
    return true;

  if (this.hasOrphan(hash))
    return true;

  return false;
};

Chain.prototype.byHeight = function byHeight(height) {
  if (height == null)
    return;
  return this.db.get(height);
};

Chain.prototype.byHash = function byHash(hash) {
  if (utils.isBuffer(hash))
    hash = utils.toHex(hash);
  else if (hash.hash)
    hash = hash.hash('hex');

  return this.byHeight(this.heightLookup[hash]);
};

Chain.prototype.byTime = function byTime(ts) {
  var start = 0;
  var end = this.db.count();
  var pos, delta, entry;

  if (ts >= this.tip.ts)
    return this.tip;

  // Do a binary search for a block
  // mined within an hour of the
  // timestamp.
  while (start < end) {
    pos = (start + end) >> 1;
    entry = this.db.get(pos);
    delta = Math.abs(ts - entry.ts);

    if (delta <= 60 * 60)
      return entry;

    if (ts < entry.ts) {
      end = pos;
    } else {
      start = pos + 1;
    }
  }

  return this.db.get(start);
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
  if (utils.isBuffer(hash))
    hash = utils.toHex(hash);
  else if (hash.hash)
    hash = hash.hash('hex');

  return this.orphan.bmap[hash] || null;
};

Chain.prototype.getTip = function getTip() {
  return this.tip;
};

Chain.prototype.isFull = function isFull() {
  if (!this.tip)
    return false;
  var delta = utils.now() - this.tip.ts;
  return delta < 40 * 60;
};

Chain.prototype.fillPercent = function fillPercent() {
  if (!this.tip)
    return 0;
  return Math.min(1, this.tip.ts / (utils.now() - 40 * 60));
};

Chain.prototype.hashRange = function hashRange(start, end) {
  var hashes;

  start = this.byTime(start);
  end = this.byTime(end);

  if (!start || !end)
    return [];

  for (var i = start.height; i < end.height + 1; i++)
    hashes.push(this.db.get(i).hash);

  return hashes;
};

Chain.prototype.locatorHashes = function locatorHashes(start) {
  var hashes = [];
  var top = this.height();
  var step = 1;
  var i, existing;

  if (start) {
    if (utils.isBuffer(start))
      start = utils.toHex(start);
    else if (start.hash)
      start = start.hash('hex');
  }

  if (typeof start === 'string') {
    top = this.heightLookup[start];
    if (top == null) {
      // We could simply `return [start]` here,
      // but there is no standardized "spacing"
      // for locator hashes. Pretend this hash
      // is our tip. This is useful for getheaders
      // when not using headers-first.
      hashes.push(start);
      top = this.db.count() - 1;
    }
  } else if (typeof start === 'number') {
    top = start;
  }

  assert(this.db.has(top));

  i = top;
  for (;;) {
    existing = this.db.get(i);
    assert(existing);
    hashes.push(existing.hash);
    i = i - step;
    if (i <= 0) {
      if (i + step !== 0)
        hashes.push(network.genesis.hash);
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

  if (utils.isBuffer(hash))
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
  return this.db.count();
};

Chain.prototype.height = function height() {
  if (!this.tip)
    return -1;
  return this.tip.height;
};

Chain.prototype.currentTarget = function currentTarget() {
  if (!this.tip)
    return utils.toCompact(network.powLimit);
  return this.target(this.tip);
};

Chain.prototype.target = function target(last, block) {
  var powLimit = utils.toCompact(network.powLimit);
  var ts, first, i;

  // Genesis
  if (!last)
    return powLimit;

  // Do not retarget
  if ((last.height + 1) % network.powDiffInterval !== 0) {
    if (network.powAllowMinDifficultyBlocks) {
      // Special behavior for testnet:
      ts = block ? (block.ts || block) : utils.now();
      if (ts > last.ts + network.powTargetSpacing * 2)
        return powLimit;

      while (last.prev
        && last.height % network.powDiffInterval !== 0
        && last.bits === powLimit) {
        last = last.prev;
      }

      return last.bits;
    }
    return last.bits;
  }

  // Back 2 weeks
  first = this.db.get(last.height - (network.powDiffInterval - 1));

  assert(first);

  return this.retarget(last, first);
};

Chain.prototype.retarget = function retarget(last, first) {
  var powTargetTimespan = new bn(network.powTargetTimespan);
  var actualTimespan, target;

  if (network.powNoRetargeting)
    return last.bits;

  actualTimespan = new bn(last.ts - first.ts);
  target = utils.fromCompact(last.bits);

  if (actualTimespan.cmp(powTargetTimespan.divn(4)) < 0)
    actualTimespan = powTargetTimespan.divn(4);

  if (actualTimespan.cmp(powTargetTimespan.muln(4)) > 0)
    actualTimespan = powTargetTimespan.muln(4);

  target.imul(actualTimespan);
  target = target.div(powTargetTimespan);

  if (target.cmp(network.powLimit) > 0)
    target = network.powLimit.clone();

  return utils.toCompact(target);
};

Chain.prototype.toJSON = function toJSON() {
  var entries = [];
  var count = this.db.count();
  var i;

  for (i = 0; i < count; i++)
    entries.push(this.db.get(i));

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
    this._saveEntry(ChainBlock.fromJSON(this, entry));
  }, this);
};

/**
 * ChainDB
 */

var BLOCK_SIZE = 112;
// var BLOCK_SIZE = 116;

function ChainDB(chain, options) {
  if (!(this instanceof ChainDB))
    return new ChainDB(chain);

  if (!options)
    options = {};

  this.options = options;
  this.chain = chain;
  this.file = options.file;

  if (!this.file)
    this.file = process.env.HOME + '/bcoin-' + network.type + '.blockchain';

  this._queue = [];
  this._cache = {};
  this._bufferPool = { used: {} };
  this._nullBlock = new Buffer(BLOCK_SIZE);
  this._nullBlock.fill(0);
  this.tip = -1;
  this.size = 0;
  this.fd = null;

  // Need to cache up to the retarget interval
  // if we're going to be checking the damn
  // target all the time.
  if (network.powAllowMinDifficultyBlocks)
    this._cacheWindow = network.powDiffInterval + 1;
  else
    this._cacheWindow = network.block.majorityWindow + 1;

  this._init();
}

ChainDB.prototype._init = function _init() {
  if (+process.env.BCOIN_FRESH === 1) {
    try {
      fs.unlinkSync(this.file);
    } catch (e) {
      ;
    }
  }

  if (!this.exists()) {
    fs.writeFileSync(this.file, new Buffer(0));
    fs.truncateSync(this.file, 0);
  }

  this.size = this.getSize();

  if (this.size % BLOCK_SIZE !== 0) {
    utils.debug('Blockchain is at an odd length. Truncating.');
    fs.truncateSync(this.file, this.size - (this.size % BLOCK_SIZE));
    this.size = this.getSize();
    assert(this.size % BLOCK_SIZE === 0);
  }

  this.fd = fs.openSync(this.file, 'r+');
};

ChainDB.prototype._malloc = function(size) {
  if (!this._bufferPool[size])
    this._bufferPool[size] = new Buffer(size);

  if (this._bufferPool.used[size] === this._bufferPool[size])
    return new Buffer(size);

  this._bufferPool.used[size] = this._bufferPool[size];

  return this._bufferPool[size];
};

ChainDB.prototype._free = function(buf) {
  if (this._bufferPool.used[buf.length] === buf) {
    assert(this._bufferPool[buf.length] === buf);
    delete this._bufferPool.used[buf.length];
  }
};

ChainDB.prototype.exists = function exists() {
  try {
    fs.statSync(this.file);
    return true;
  } catch (e) {
    return false;
  }
};

ChainDB.prototype.getSize = function getSize() {
  try {
    return fs.statSync(this.file).size;
  } catch (e) {
    return 0;
  }
};

ChainDB.prototype.count = function count() {
  var len = this.size / BLOCK_SIZE;
  assert(len % 1 === 0);
  return len;
};

ChainDB.prototype.cache = function cache(entry) {
  if (entry.height > this.tip) {
    this.tip = entry.height;
    delete this._cache[entry.height - this._cacheWindow];
    this._cache[entry.height] = entry;
    assert(Object.keys(this._cache).length <= this._cacheWindow);
  }
};

ChainDB.prototype.get = function get(height) {
  return this.getSync(height);
};

ChainDB.prototype.getSync = function getSync(height) {
  var data, entry;

  if (this._cache[height])
    return this._cache[height];

  if (this._queue[height])
    return this._queue[height];

  if (height < 0 || height == null)
    return;

  if ((height + 1) * BLOCK_SIZE > this.size)
    return;

  data = this._readSync(BLOCK_SIZE, height * BLOCK_SIZE);

  if (!data)
    return;

  // Ignore if it is a null block.
  if (utils.read32(data, 0) === 0)
    return;

  entry = ChainBlock.fromRaw(this.chain, height, data);

  // Cache the past 1001 blocks in memory
  // (necessary for isSuperMajority)
  this.cache(entry);

  return entry;
};

ChainDB.prototype.getAsync = function getAsync(height, callback) {
  var self = this;

  callback = utils.asyncify(callback);

  if (this._cache[height])
    return callback(null, this._cache[height]);

  if (this._queue[height])
    return callback(null, this._queue[height]);

  if (height < 0 || height == null)
    return callback();

  if ((height + 1) * BLOCK_SIZE > this.size)
    return callback();

  return this._readAsync(BLOCK_SIZE, height * BLOCK_SIZE, function(err, data) {
    var entry;

    // We can't ensure the integrity of
    // the chain if we get an error.
    // Just throw.
    if (err)
      throw err;

    if (!data)
      return callback();

    // Ignore if it is a null block.
    if (utils.read32(data, 0) === 0)
      return callback();

    entry = ChainBlock.fromRaw(self.chain, height, data);

    // Cache the past 1001 blocks in memory
    // (necessary for isSuperMajority)
    self.cache(entry);

    return callback(null, entry);
  });
};

ChainDB.prototype.save = function save(entry) {
  return this.saveAsync(entry);
};

ChainDB.prototype.saveSync = function saveSync(entry) {
  var self = this;
  var raw, offset;

  // Cache the past 1001 blocks in memory
  // (necessary for isSuperMajority)
  this.cache(entry);

  raw = entry.toRaw();
  offset = entry.height * BLOCK_SIZE;

  return this._writeSync(raw, offset);
};

ChainDB.prototype.saveAsync = function saveAsync(entry, callback) {
  var self = this;
  var raw, offset;

  callback = utils.asyncify(callback);

  // Cache the past 1001 blocks in memory
  // (necessary for isSuperMajority)
  this.cache(entry);

  // Something is already writing. Cancel it
  // and synchronously write the data after
  // it cancels.
  if (this._queue[entry.height]) {
    this._queue[entry.height] = entry;
    return callback();
  }

  // Speed up writes by doing them asynchronously
  // and keeping the data to be written in memory.
  this._queue[entry.height] = entry;

  // Write asynchronously to the db.
  raw = entry.toRaw();
  offset = entry.height * BLOCK_SIZE;

  return this._writeAsync(raw, offset, function(err, success) {
    // We can't ensure the integrity of
    // the chain if we get an error.
    // Just throw.
    if (err)
      throw err;

    var item = self._queue[entry.height];

    // Something tried to write here but couldn't.
    // Synchronously write it and get it over with.
    try {
      if (item && item !== entry)
        success = self._writeSync(item.toRaw(), offset);
    } catch (e) {
      err = e;
    }

    delete self._queue[entry.height];

    return callback(null, success);
  });
};

ChainDB.prototype.remove = function remove(height) {
  assert(height >= 0);

  // Potential race condition here. Not sure how
  // to handle this.
  if (this._queue[height]) {
    utils.debug('Warning: write job in progress.');
    delete this._queue[height];
  }

  this._writeSync(this._nullBlock, height * BLOCK_SIZE);
  delete this._cache[height];

  // If we deleted several blocks at the end, go back
  // to the last non-null block and truncate the file
  // beyond that point.
  if ((height + 1) * BLOCK_SIZE === this.size) {
    while (this.isNull(height))
      height--;

    if (height < 0)
      height = 0;

    fs.ftruncateSync(this.fd, (height + 1) * BLOCK_SIZE);

    this.size = (height + 1) * BLOCK_SIZE;
    this.tip = height;
  }

  return true;
};

ChainDB.prototype.isNull = function isNull(height) {
  var data = this._readSync(4, height * BLOCK_SIZE);
  if (!data)
    return false;
  return utils.read32(data, 0) === 0;
};

ChainDB.prototype.has = function has(height) {
  var data;

  if (this._queue[height] || this._cache[height])
    return true;

  if (height < 0 || height == null)
    return false;

  if ((height + 1) * BLOCK_SIZE > this.size)
    return false;

  data = this._readSync(4, height * BLOCK_SIZE);

  if (!data)
    return false;

  return utils.read32(data, 0) !== 0;
};

ChainDB.prototype._readSync = function _readSync(size, offset) {
  var index = 0;
  var data, bytes;

  if (offset < 0 || offset == null)
    return;

  data = this._malloc(size);

  try {
    while (bytes = fs.readSync(this.fd, data, index, size, offset)) {
      index += bytes;
      size -= bytes;
      offset += bytes;
      if (index === data.length) {
        this._free(data);
        return data;
      }
    }
  } catch (e) {
    this._free(data);
    throw e;
  }

  this._free(data);

  throw new Error('_readSync() failed.');
};

ChainDB.prototype._readAsync = function _readAsync(size, offset, callback) {
  var self = this;
  var index = 0;
  var data, bytes;

  if (offset < 0 || offset == null)
    return false;

  data = this._malloc(size);

  (function next() {
    fs.read(self.fd, data, index, size, offset, function(err, bytes) {
      if (err) {
        self._free(data);
        return callback(err);
      }

      index += bytes;
      size -= bytes;
      offset += bytes;

      if (index === data.length) {
        self._free(data);
        return callback(null, data);
      }

      next();
    });
  })();
};

ChainDB.prototype._writeSync = function _writeSync(data, offset) {
  var size = data.length;
  var added = Math.max(0, (offset + data.length) - this.size);
  var index = 0;
  var bytes;

  if (offset < 0 || offset == null)
    return false;

  try {
    while (bytes = fs.writeSync(this.fd, data, index, size, offset)) {
      index += bytes;
      size -= bytes;
      offset += bytes;
      if (index === data.length) {
        this.size += added;
        return true;
      }
    }
  } catch (e) {
    throw e;
  }

  throw new Error('_writeSync() failed.');
};

ChainDB.prototype._writeAsync = function _writeAsync(data, offset, callback) {
  var self = this;
  var added = Math.max(0, (offset + data.length) - this.size);
  var size = data.length;
  var index = 0;

  if (offset < 0 || offset == null)
    return false;

  self.size += added;

  (function next() {
    fs.write(self.fd, data, index, size, offset, function(err, bytes) {
      if (err) {
        self.size -= (added - index);
        return callback(err);
      }

      index += bytes;
      size -= bytes;
      offset += bytes;

      if (index === data.length)
        return callback(null, true);

      next();
    });
  })();
};

/**
 * ChainBlock
 */

function ChainBlock(chain, data) {
  this.chain = chain;
  this.hash = data.hash;
  this.version = data.version;
  this.prevBlock = data.prevBlock;
  this.merkleRoot = data.merkleRoot;
  this.ts = data.ts;
  this.bits = data.bits;
  this.nonce = data.nonce;
  this.height = data.height;
  this.chainwork = data.chainwork || this.getChainwork();
}

ChainBlock.prototype.__defineGetter__('prev', function() {
  return this.chain.db.get(this.height - 1);
});

ChainBlock.prototype.__defineGetter__('next', function() {
  return this.chain.db.get(this.height + 1);
});

ChainBlock.prototype.getProof = function getProof() {
  var target = utils.fromCompact(this.bits);
  if (target.isNeg() || target.cmpn(0) === 0)
    return new bn(0);
  return new bn(1).ushln(256).div(target.addn(1));
};

ChainBlock.prototype.getChainwork = function() {
  return (this.prev ? this.prev.chainwork : new bn(0)).add(this.getProof());
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
  return this.isSuperMajority(version, network.block.majorityRejectOutdated);
};

ChainBlock.prototype.isUpgraded = function(version) {
  return this.isSuperMajority(version, network.block.majorityEnforceUpgrade);
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
  return {
    hash: this.hash,
    version: this.version,
    prevBlock: this.prevBlock,
    merkleRoot: this.merkleRoot,
    ts: this.ts,
    bits: this.bits,
    nonce: this.nonce,
    height: this.height
  };
};

ChainBlock.fromJSON = function(chain, json) {
  return new ChainBlock(chain, json);
};

ChainBlock.prototype.toRaw = function toRaw() {
  var res = new Buffer(BLOCK_SIZE);

  utils.writeU32(res, this.version, 0);
  utils.copy(utils.toArray(this.prevBlock, 'hex'), res, 4);
  utils.copy(utils.toArray(this.merkleRoot, 'hex'), res, 36);
  utils.writeU32(res, this.ts, 68);
  utils.writeU32(res, this.bits, 72);
  utils.writeU32(res, this.nonce, 76);
  utils.copy(this.chainwork.toArray('be', 32), res, 80);
  // utils.copy(utils.checksum(res.slice(0, 112)), res, 112);

  return res;
};

ChainBlock.fromRaw = function fromRaw(chain, height, p) {
  // if (!utils.isEqual(utils.checksum(p.slice(0, 112)), p.slice(112, 116)))
  //   throw new Error('Bad checksum');
  return new ChainBlock(chain, {
    height: height,
    hash: utils.toHex(utils.dsha256(p.slice(0, 80))),
    version: utils.read32(p, 0),
    prevBlock: utils.toHex(p.slice(4, 36)),
    merkleRoot: utils.toHex(p.slice(36, 68)),
    ts: utils.readU32(p, 68),
    bits: utils.readU32(p, 72),
    nonce: utils.readU32(p, 76),
    chainwork: new bn(p.slice(80, 112), 'be')
  });
};

/**
 * Expose
 */

module.exports = Chain;
