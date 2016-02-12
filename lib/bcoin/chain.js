/**
 * chain.js - blockchain management for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

var inherits = require('inherits');
var EventEmitter = require('events').EventEmitter;
var request = require('request');

var bcoin = require('../bcoin');
var bn = require('bn.js');
var constants = bcoin.protocol.constants;
var network = bcoin.protocol.network;
var utils = bcoin.utils;
var assert = utils.assert;
var fs = bcoin.fs;

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

  this.db = new bcoin.chaindb(this);
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

  this._saveEntry(bcoin.chainblock.fromJSON(this, {
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

  this._preload(function(err, start) {
    if (err) {
      utils.debug('Preloading chain failed.');
      utils.debug('Reason: %s', err.message);
    }
    utils.nextTick(function() {
      var count = self.db.count();
      var i = start || 1;
      var lastEntry;

      utils.debug('Starting chain load at height: %s', i);

      function done(height) {
        if (height != null) {
          utils.debug(
            'Blockchain is corrupt after height %d. Resetting.',
            height);
          self.resetHeight(height);
        } else {
          utils.debug('Chain successfully loaded.');
        }
        self.loading = false;
        self.emit('load');
      }

      (function next() {
        if (i >= count)
          return done();

        self.db.getAsync(i, function(err, entry) {
          if (err)
            throw err;

          // Do some paranoid checks.
          if (lastEntry && entry.prevBlock !== lastEntry.hash)
            return done(Math.max(0, i - 2));

          lastEntry = entry;
          self._saveEntry(entry);
          i += 1;
          next();
        });
      })();
    });
  });
};

// Stream headers from electrum.org for quickly
// preloading the chain. Electrum.org stores
// headers in the standard block header format,
// but they do not store chainwork, so we have
// to calculate it ourselves.
Chain.prototype._preload = function _preload(callback) {
  var self = this;
  var url = 'https://headers.electrum.org/blockchain_headers';
  var chainHeight, buf, height, stream;

  if (!this.options.preload)
    return callback();

  if (network.type !== 'main')
    return callback(new Error('Electrum.org only offers `main` headers.'));

  utils.debug('Loading %s', url);

  stream = request.get(url);
  chainHeight = this.db.count() - 1;
  height = 0;
  buf = {
    data: [],
    size: 0
  };

  stream.on('response', function(res) {
    if (res.statusCode >= 400) {
      stream.destroy();
      return callback(new Error('Bad response code: ' + res.statusCode));
    }
  });

  stream.on('error', function(err) {
    var start = Math.max(0, height - 2);
    self.resetHeight(start);
    return callback(err, start + 1);
  });

  stream.on('data', function(data) {
    var blocks = [];
    var need = 80 - buf.size;
    var i, lastEntry;

    while (data.length >= need) {
      buf.data.push(data.slice(0, need));
      blocks.push(Buffer.concat(buf.data));
      buf.data.length = 0;
      buf.size = 0;
      data = data.slice(need);
      need = 80 - buf.size;
    }

    if (data.length > 0) {
      assert(data.length < 80);
      buf.data.push(data);
      buf.size += data.length;
    }

    if (blocks.length === 0)
      return;

    blocks.forEach(function(data) {
      var entry = bcoin.chainblock.fromRaw(self, height, data);
      var block = bcoin.block(entry, 'headers');
      var start;

      // Do some paranoid checks.
      if (lastEntry && entry.prevBlock !== lastEntry.hash) {
        start = Math.max(0, height - 2);
        stream.destroy();
        self.resetHeight(start);
        return callback(new Error('Corrupt headers.'), start + 1);
      }

      // Verify the block headers. We don't want to
      // trust an external centralized source completely.
      // For very paranoid but slower validation:
      // if (!block.verify() || !block.verifyContext()) {
      if (!block.verify()) {
        start = Math.max(0, height - 2);
        stream.destroy();
        self.resetHeight(start);
        return callback(new Error('Bad headers.'), start + 1);
      }

      lastEntry = entry;

      delete entry.chainwork;
      entry.chainwork = entry.getChainwork();

      // Skip the genesis block in case
      // it ends up being corrupt.
      if (height === 0) {
        height++;
        return;
      }

      // Don't write blocks we already have
      // (bad for calculating chainwork).
      // self._saveEntry(entry, height > chainHeight);

      self._saveEntry(entry, true);

      height++;

      if ((height + 1) % 50000 === 0)
        utils.debug('Received %d headers from electrum.org.', height + 1);
    });
  });

  stream.on('end', function() {
    return callback(null, height + 1);
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

  for (i = height + 1; i < count; i++) {
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
      this.orphan.size += block.getSize();
      this.orphan.map[prevHash] = block;
      this.orphan.bmap[hash] = block;
      code = Chain.codes.newOrphan;
      total++;
      break;
    }

    // Create a new chain entry.
    entry = new bcoin.chainblock(this, {
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

      // Update the block height
      block.height = entry.height;
      block.txs.forEach(function(tx) {
        tx.height = entry.height;
      });

      // Keep track of the number of blocks we
      // added and the number of orphans resolved.
      total++;

      // Emit our block (and potentially resolved
      // orphan) so the programmer can save it.
      this.emit('block', block, peer);
      this.emit('entry', entry);
      if (block !== initial)
        this.emit('resolved', block, peer);

      // Fullfill request
      this.request.fullfill(hash, block);
    }

    if (!this.orphan.map[hash])
      break;

    // An orphan chain was found, start resolving.
    block = this.orphan.map[hash];
    delete this.orphan.bmap[block.hash('hex')];
    delete this.orphan.map[hash];
    this.orphan.count--;
    this.orphan.size -= block.getSize();
  }

  // Failsafe for large orphan chains. Do not
  // allow more than 20mb stored in memory.
  if (this.orphan.size > 20971520) {
    Object.keys(this.orphan.bmap).forEach(function(hash) {
      this.emit('unresolved', this.orphan.bmap[hash], peer);
    }, this);
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

Chain.prototype.isFull = function isFull() {
  var delta;

  if (!this.tip)
    return false;

  delta = utils.now() - this.tip.ts;

  return delta < 40 * 60;
};

Chain.prototype.fillPercent = function fillPercent() {
  if (!this.tip)
    return 0;
  return Math.min(1, this.tip.ts / (utils.now() - 40 * 60));
};

Chain.prototype.hashRange = function hashRange(start, end) {
  var hashes = [];
  var i;

  start = this.byTime(start);
  end = this.byTime(end);

  if (!start || !end)
    return hashes;

  for (i = start.height; i < end.height + 1; i++)
    hashes.push(this.db.get(i).hash);

  return hashes;
};

Chain.prototype.getLocator = function getLocator(start) {
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
  var root;

  if (utils.isBuffer(hash))
    hash = utils.toHex(hash);
  else if (hash.hash)
    hash = hash.hash('hex');

  root = hash;

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
  var next;

  if (!entry)
    return null;

  next = entry.next;

  if (!next)
    return;

  return next.hash;
};

Chain.prototype.getSize = function getSize() {
  return this.db.count();
};

// Legacy
Chain.prototype.size = Chain.prototype.getSize;

Chain.prototype.height = function height() {
  if (!this.tip)
    return -1;
  return this.tip.height;
};

Chain.prototype.getCurrentTarget = function getCurrentTarget() {
  if (!this.tip)
    return utils.toCompact(network.powLimit);
  return this.getTarget(this.tip);
};

// Legacy
Chain.prototype.currentTarget = Chain.prototype.getCurrentTarget;

Chain.prototype.getTarget = function getTarget(last, block) {
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

// Legacy
Chain.prototype.target = Chain.prototype.getTarget;

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
    this._saveEntry(bcoin.chainblock.fromJSON(this, entry));
  }, this);
};

/**
 * Expose
 */

module.exports = Chain;
