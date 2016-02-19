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
  this.height = -1;
  this.mempool = options.mempool;
  this.blockdb = options.blockdb;
  this.locked = false;
  this.pending = [];
  this.pendingBlocks = {};
  this.pendingSize = 0;
  this.total = 0;
  this.orphanLimit = options.orphanLimit || 20 * 1024 * 1024;
  this.pendingLimit = options.pendingLimit || 20 * 1024 * 1024;
  this.invalid = {};
  this.bestHeight = -1;

  this.orphan = {
    map: {},
    bmap: {},
    count: 0,
    size: 0
  };

  Chain.global = this;

  this._init();
}

inherits(Chain, EventEmitter);

Chain.prototype._init = function _init() {
  var self = this;

  // Hook into events for debugging
  this.on('block', function(block, entry, peer) {
    var host = peer ? peer.host : 'unknown';
    // utils.debug('Block %s (%d) added to chain (%s)',
    //   utils.revHex(entry.hash), entry.height, host);
  });

  this.on('resolved', function(block, entry, peer) {
    var host = peer ? peer.host : 'unknown';
    utils.debug('Orphan %s (%d) was resolved (%s)',
      utils.revHex(entry.hash), entry.height, host);
  });

  this.on('checkpoint', function(block, data, peer) {
    var host = peer ? peer.host : 'unknown';
    utils.debug('Hit checkpoint block %s (%d) (%s)',
      utils.revHex(data.checkpoint), data.height, host);
  });

  this.on('fork', function(block, data, peer) {
    var host = peer ? peer.host : 'unknown';
    utils.debug(
      'Fork at height %d: expected=%s received=%s checkpoint=%s peer=%s',
      data.height,
      utils.revHex(data.expected),
      utils.revHex(data.received),
      data.checkpoint,
      host
    );
    if (data.checkpoint)
      utils.debug('WARNING: Block failed a checkpoint.');
  });

  this.on('invalid', function(block, data, peer) {
    var host = peer ? peer.host : 'unknown';
    utils.debug(
      'Invalid block at height %d: hash=%s peer=%s',
      data.height,
      utils.revHex(data.hash),
      host
    );
    if (data.chain) {
      utils.debug(
        'Peer is sending an invalid continuation chain (%s)',
        host);
    } else if (data.seen) {
      utils.debug('Peer is sending an invalid chain (%s)', host);
    }
  });

  this.on('exists', function(block, data, peer) {
    var host = peer ? peer.host : 'unknown';
    utils.debug('Already have block %s (%s)',
      data.height, host);
  });

  this.on('orphan', function(block, data, peer) {
    var host = peer ? peer.host : 'unknown';
    utils.debug('Handled orphan %s (%s)', utils.revHex(data.hash), host);
  });

  this.on('purge', function(count, size, peer) {
    utils.debug('Warning: %d (%dmb) orphans cleared!', coin, utils.mb(size));
  });

  // Update the mempool.
  this.on('add block', function(block) {
    if (self.mempool)
      self.mempool.addBlock(block);
  });

  this.on('remove block', function(block) {
    if (self.mempool)
      self.mempool.removeBlock(block);
  });

  this.loading = true;

  utils.debug('Chain is loading.');

  this._ensureGenesis(function(err) {
    if (err)
      throw err;

    self._preload(function(err, start) {
      var count = self.db.count();
      var i = start || 1;
      var lastEntry;

      if (err) {
        utils.debug('Preloading chain failed.');
        utils.debug('Reason: %s', err.message);
      }

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

        self.syncHeight(function(err) {
          if (err)
            throw err;
          self.loading = false;
          self.emit('load');
        });
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

          if (i % 10000 === 0)
            utils.debug('Loaded %d blocks.', i);

          lastEntry = entry;
          self._saveEntry(entry);
          i += 1;
          next();
        });
      })();
    });
  });
};

Chain.prototype._ensureGenesis = function _ensureGenesis(callback) {
  var self = this;

  callback = utils.asyncify(callback);

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

  if (!this.blockdb)
    return callback();

  self.blockdb.hasBlock(network.genesis.hash, function(err, result) {
    var genesis;

    if (err)
      return callback(err);

    if (result)
      return callback();

    utils.debug('BlockDB does not have genesis block. Adding.');

    genesis = bcoin.block.fromRaw(network.genesisBlock, 'hex');
    genesis.height = 0;

    self.blockdb.saveBlock(genesis, function(err) {
      if (err)
        return callback(err);

      return callback();
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

Chain.prototype._saveBlock = function _saveBlock(block, callback) {
  var self = this;

  if (!this.blockdb)
    return utils.nextTick(callback);

  this.blockdb.saveBlock(block, callback);
};

Chain.prototype._removeBlock = function _removeBlock(tip, callback) {
  var self = this;

  if (!this.blockdb)
    return utils.nextTick(callback);

  this.blockdb.removeBlock(tip, callback);
};

Chain.prototype._verifyContext = function _verifyContext(block, prev, callback) {
  var self = this;
  var flags;

  flags = this._verify(block, prev);

  if (flags === false)
    return callback(null, false);

  this._checkDuplicates(block, prev, function(err, result) {
    if (err)
      return callback(err);

    if (!result)
      return callback(null, false);

    self._checkInputs(block, prev, flags, function(err, result) {
      if (err)
        return callback(err);

      if (!result)
        return callback(null, false);

      return callback(null, true);
    });
  });
};

Chain.prototype._verify = function _verify(block, prev) {
  var flags = constants.flags.MANDATORY_VERIFY_FLAGS;
  var sigops = 0;
  var height, ts, i, tx, cb, coinbaseHeight, medianTime, locktimeMedian;

  // Skip the genesis block
  if (block.isGenesis())
    return flags;

  // Ensure it's not an orphan
  if (!prev) {
    utils.debug('Block has no previous entry: %s', block.rhash);
    return false;
  }

  height = prev.height + 1;
  medianTime = prev.getMedianTime();

  // Ensure the timestamp is correct
  if (block.ts <= medianTime) {
    utils.debug('Block time is lower than median: %s', block.rhash);
    return false;
  }

  // Ensure the miner's target is equal to what we expect
  if (block.bits !== this.getTarget(prev, block)) {
    utils.debug('Block is using wrong target: %s', block.rhash);
    return false;
  }

  // Only allow version 2 blocks (coinbase height)
  // once the majority of blocks are using it.
  if (block.version < 2 && prev.isOutdated(2)) {
    utils.debug('Block is outdated (v2): %s', block.rhash);
    return false;
  }

  // Only allow version 3 blocks (sig validation)
  // once the majority of blocks are using it.
  if (block.version < 3 && prev.isOutdated(3)) {
    utils.debug('Block is outdated (v3): %s', block.rhash);
    return false;
  }

  // Only allow version 4 blocks (checklocktimeverify)
  // once the majority of blocks are using it.
  if (block.version < 4 && prev.isOutdated(4)) {
    utils.debug('Block is outdated (v4): %s', block.rhash);
    return false;
  }

  // Only allow version 8 blocks (locktime median past)
  // once the majority of blocks are using it.
  // if (block.version < 8 && prev.isOutdated(8)) {
  //   utils.debug('Block is outdated (v8): %s', block.rhash);
  //   return false;
  // }

  // Make sure the height contained in the coinbase is correct.
  if (block.version >= 2 && prev.isUpgraded(2))
    coinbaseHeight = true;

  // Signature validation is now enforced (bip66)
  if (block.version >= 3 && prev.isUpgraded(3))
    flags |= constants.flags.VERIFY_DERSIG;

  // CHECKLOCKTIMEVERIFY is now usable (bip65)
  if (block.version >= 4 && prev.isUpgraded(4))
    flags |= constants.flags.VERIFY_CHECKLOCKTIMEVERIFY;

  // Use nLockTime median past (bip113)
  // https://github.com/btcdrak/bips/blob/d4c9a236ecb947866c61aefb868b284498489c2b/bip-0113.mediawiki
  // Support version bits:
  // https://gist.github.com/sipa/bf69659f43e763540550
  // http://lists.linuxfoundation.org/pipermail/bitcoin-dev/2015-August/010396.html
  // if (block.version >= 8 && prev.isUpgraded(8))
  //   locktimeMedian = true;

  // Can't verify any further when merkleblock or headers.
  if (block.subtype !== 'block')
    return flags;

  // Make sure the height contained in the coinbase is correct.
  if (coinbaseHeight) {
    if (block.getCoinbaseHeight() !== height) {
      utils.debug('Block has bad coinbase height: %s', block.rhash);
      return false;
    }
  }

  // Get timestamp for tx.isFinal().
  ts = locktimeMedian ? medianTime : block.ts;

  // Check all transactions
  for (i = 0; i < block.txs.length; i++) {
    tx = block.txs[i];

    // Transactions must be finalized with
    // regards to nSequence and nLockTime.
    if (!tx.isFinal(height, ts)) {
      utils.debug('TX is not final: %s (%s)', block.rhash, i);
      return false;
    }

    // Check for block sigops limits
    // Start counting P2SH sigops once block
    // timestamps reach March 31st, 2012.
    if (block.ts >= constants.block.bip16time)
      sigops += tx.getSigops(true);
    else
      sigops += tx.getSigops();

    if (sigops > constants.script.maxBlockSigops) {
      utils.debug('Block has too many sigops: %s', block.rhash);
      return false;
    }
  }

  return flags;
};

Chain.prototype._checkDuplicates = function _checkDuplicates(block, prev, callback) {
  var self = this;
  var height = prev.height + 1;
  var pending = block.txs.length;
  var called;

  if (!this.blockdb || block.subtype !== 'block')
    return callback(null, true);

  if (block.isGenesis())
    return callback(null, true);

  assert(pending);

  function done(err, result) {
    if (called)
      return;
    called = true;
    callback(err, result);
  }

  // Check all transactions
  block.txs.forEach(function(tx) {
    var hash = tx.hash('hex');

    // BIP30 - Ensure there are no duplicate txids
    self.blockdb.hasTX(hash, function(err, result) {
      if (called)
        return;

      if (err)
        return done(err);

      // Blocks 91842 and 91880 created duplicate
      // txids by using the same exact output script
      // and extraNonce.
      if (result) {
        utils.debug('Block is overwriting txids: %s', block.rhash);
        if (!(network.type === 'main' && (height === 91842 || height === 91880)))
          return done(null, false);
      }

      if (!--pending)
        return done(null, true);
    });
  });
};

Chain.prototype._checkInputs = function _checkInputs(block, prev, flags, callback) {
  var self = this;
  var height = prev.height + 1;

  if (!this.blockdb || block.subtype !== 'block')
    return callback(null, true);

  if (block.isGenesis())
    return callback(null, true);

  // If we are an ancestor of a checkpoint, we can
  // skip the input verification.
  // if (height < network.checkpoints.lastHeight && !network.checkpoints[height])
  //   return callback(null, true);

  this._fillBlock(block, function(err) {
    var i, j, input, hash;

    if (err)
      return callback(err);

    // Check all transactions
    for (i = 0; i < block.txs.length; i++) {
      tx = block.txs[i];
      hash = tx.hash('hex');

      for (j = 0; j < tx.inputs.length; j++) {
        input = tx.inputs[j];

        // Coinbases do not have prevouts
        if (tx.isCoinbase())
          continue;

        // Ensure tx is not double spending an output
        if (!input.output) {
          utils.debug('Block is using spent inputs: %s (tx: %s, output: %s)',
            block.rhash, tx.rhash,
            input.prevout.rhash + '/' + input.prevout.index);
          throw new Error('Spent inputs: '
            + utils._inspect(input, false)
            + JSON.stringify(input, null, 2));
          return callback(null, false);
        }

        // Verify the scripts
        if (!tx.verify(j, true, flags)) {
          utils.debug('Block has invalid inputs: %s (%s/%d)',
            block.rhash, tx.rhash, j);
          utils.debug('Signature Hash: %s', utils.toHex(tx.signatureHash(j, input.output.script, 'all')));
          utils.debug(input);
          utils.debug('raw: %s', utils.toHex(input.output.script._raw || []));
          utils.debug('encoded: %s', utils.toHex(bcoin.script.encode(input.output.script)));
          throw new Error('Bad inputs: '
            + utils._inspect(input, false)
            + JSON.stringify(input, null, 2)
            + '\n'
            + utils.toHex(tx.signatureHash(j, input.output.script, 'all')));
          return callback(null, false);
        }
      }
    }

    return callback(null, true);
  });
};

Chain.prototype._fillBlock = function _fillBlock(block, callback) {
  var self = this;

  return this.blockdb.fillCoins(block.txs, function(err) {
    var coins, i, tx, hash, j, input, id;

    if (err)
      return callback(err);

    coins = {};

    for (i = 0; i < block.txs.length; i++) {
      tx = block.txs[i];
      hash = tx.hash('hex');

      for (j = 0; j < tx.inputs.length; j++) {
        input = tx.inputs[j];
        id = input.prevout.hash + '/' + input.prevout.index;
        if (!input.output && coins[id]) {
          input.output = coins[id];
          delete coins[id];
        }
      }

      for (j = 0; j < tx.outputs.length; j++)
        coins[hash + '/' + j] = bcoin.coin(tx, j);
    }

    return callback();
  });
};

Chain.prototype._addEntry = function _addEntry(entry, block, callback) {
  var self = this;
  var existing;

  callback = utils.asyncify(callback);

  // Already added
  if (this.heightLookup[entry.hash] != null) {
    assert(this.heightLookup[entry.hash] === entry.height);
    return callback(null, false);
  }

  // Duplicate height (do a sync call here since this is cached)
  existing = this.db.get(entry.height);
  if (existing && existing.hash === entry.hash)
    return callback(null, false);

  this._saveBlock(block, function(err) {
    if (err)
      return callback(err);

    self._saveEntry(entry, true, function(err) {
      if (err)
        return callback(err);

      return callback(null, true);
    });
  });
};

Chain.prototype._saveEntry = function _saveEntry(entry, save, callback) {
  this.heightLookup[entry.hash] = entry.height;

  if (!this.tip || entry.height > this.tip.height) {
    this.tip = entry;
    this.height = this.tip.height;
    this.emit('tip', this.tip);
  }

  if (save)
    this.db.save(entry, callback);
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

  assert(height <= count - 1);
  assert(this.tip);

  if (height === count - 1)
    return;

  for (i = height + 1; i < count; i++) {
    existing = this.db.get(i);
    assert(existing);
    // this.db.remove(i);
    this.db.drop(i);
    delete this.heightLookup[existing.hash];
  }

  this.db.truncate(height);

  // Reset the orphan map completely. There may
  // have been some orphans on a forked chain we
  // no longer need.
  this.emit('purge', this.orphan.count, this.orphan.size);
  this.orphan.map = {};
  this.orphan.bmap = {};
  this.orphan.count = 0;
  this.orphan.size = 0;

  this.tip = this.db.get(height);
  assert(this.tip);
  this.height = this.tip.height;
  this.emit('tip', this.tip);
};

Chain.prototype.resetHeightAsync = function resetHeightAsync(height, callback) {
  var self = this;
  var count = this.db.count();
  var i, lock;

  assert(height <= count - 1);
  assert(this.tip);

  if (height === count - 1)
    return utils.nextTick(callback);

  lock = this.locked;
  this.locked = true;

  i = height + 1;

  function next() {
    if (i === count)
      return self.db.truncateAsync(height, done);

    self.db.getAsync(i, function(err, existing) {
      if (err)
        return done(err);

      assert(existing);

      delete self.heightLookup[existing.hash];
      self.db.drop(i);
      i++;
      next();
    });
  }

  function done(err) {
    self.locked = lock;

    if (err)
      return callback(err);

    // Reset the orphan map completely. There may
    // have been some orphans on a forked chain we
    // no longer need.
    self.emit('purge', self.orphan.count, self.orphan.size);
    self.orphan.map = {};
    self.orphan.bmap = {};
    self.orphan.count = 0;
    self.orphan.size = 0;

    self.tip = self.db.get(height);
    assert(self.tip);
    self.height = self.tip.height;
    self.emit('tip', self.tip);

    return callback();
  }
};

Chain.prototype.revertHeight = function revertHeight(height, callback) {
  var self = this;
  var chainHeight;
  var lock = this.locked;

  assert(!this.locked);

  callback = utils.asyncify(callback);

  this.locked = true;

  function done(err, result) {
    self.locked = lock;
    callback(err, result);
  }

  chainHeight = this.db.count() - 1;

  if (chainHeight < 0)
    return done(new Error('Bad chain height.'));

  if (!this.blockdb) {
    if (height > chainHeight)
      return done(new Error('Cannot reset height.'));
    this.resetHeight(height);
    return done();
  }

  this.blockdb.getHeight(function(err, blockHeight) {
    if (err)
      return done(err);

    if (blockHeight < 0)
      return done(new Error('Bad block height.'));

    if (chainHeight !== blockHeight)
      return done(new Error('ChainDB and BlockDB are out of sync.'));

    if (height === chainHeight)
      return done();

    if (height > chainHeight)
      return done(new Error('Cannot reset height.'));

    self.blockdb.resetHeight(height, function(err) {
      if (err)
        return done(err);

      self.resetHeight(height);

      return done();
    }, function(block) {
      self.emit('remove block', block);
    });
  });
};

Chain.prototype._revertLast = function _revertLast(existing, callback) {
  var self = this;
  return this._removeBlock(existing.hash, function(err, existingBlock) {
    if (err)
      return callback(err);

    self.resetHeight(existing.height - 1);

    if (existingBlock)
      self.emit('remove block', existingBlock);

    return callback();
  });
};

Chain.prototype.syncHeight = function syncHeight(callback) {
  var self = this;
  var chainHeight;
  var lock = this.locked;

  callback = utils.asyncify(callback);

  assert(!this.locked);

  this.locked = true;

  function done(err, result) {
    self.locked = lock;
    callback(err, result);
  }

  chainHeight = this.db.count() - 1;

  if (chainHeight < 0)
    return done(new Error('Bad chain height.'));

  if (!this.blockdb)
    return done();

  this.blockdb.getHeight(function(err, blockHeight) {
    if (err)
      return done(err);

    if (blockHeight < 0)
      return done(new Error('Bad block height.'));

    if (blockHeight === chainHeight)
      return done();

    utils.debug('ChainDB and BlockDB are out of sync.');

    if (blockHeight < chainHeight) {
      utils.debug('BlockDB is higher than ChainDB. Syncing...');
      self.resetHeight(blockHeight);
      return done();
    }

    if (blockHeight > chainHeight) {
      utils.debug('ChainDB is higher than BlockDB. Syncing...');
      self.blockdb.resetHeight(chainHeight, function(err) {
        if (err)
          return done(err);

        return done();
      }, function(block) {
        self.emit('remove block', block);
      });
    }
  });
};

Chain.prototype.resetTime = function resetTime(ts) {
  var entry = this.byTime(ts);
  if (!entry)
    return;
  return this.resetHeight(entry.height);
};

Chain.prototype.add = function add(initial, peer, callback) {
  var self = this;
  var host = peer ? peer.host : 'unknown';
  var total = 0;

  assert(!this.loading);

  if (this.locked) {
    this.pending.push([initial, peer, callback]);
    this.pendingBlocks[initial.hash('hex')] = true;
    this.pendingSize += initial.getSize();
    if (this.pendingSize > this.pendingLimit) {
      utils.debug('Warning: %dmb of pending blocks.',
        utils.mb(this.pendingSize));
    }
    return;
  }

  this.locked = true;

  (function next(block) {
    var hash = block.hash('hex');
    var prevHash = block.prevBlock;
    var prevHeight, entry, existing, checkpoint, prev, orphan;

    // Special case for genesis block.
    if (block.isGenesis())
      return done();

    // Do not revalidate known invalid blocks.
    if (self.invalid[hash] || self.invalid[prevHash]) {
      self.emit('invalid', block, {
        height: -1,
        hash: hash,
        seen: true,
        chain: self.invalid[prevHash]
      }, peer);
      return done();
    }

    // Find the previous block height/index.
    prevHeight = self.heightLookup[prevHash];

    // Validate the block we want to add.
    // This is only necessary for new
    // blocks coming in, not the resolving
    // orphans.
    if (block === initial && !block.verify()) {
      self.invalid[hash] = true;
      self.emit('invalid', block, {
        height: prevHeight + 1,
        hash: hash,
        seen: false,
        chain: false
      }, peer);
      return done();
    }

    // If the block is already known to be
    // an orphan, ignore it.
    orphan = self.orphan.map[prevHash];
    if (orphan) {
      // If the orphan chain forked, simply
      // reset the orphans and find a new peer.
      if (orphan.hash('hex') !== hash) {
        self.emit('purge', self.orphan.count, self.orphan.size, peer);
        self.orphan.map = {};
        self.orphan.bmap = {};
        self.orphan.count = 0;
        self.orphan.size = 0;
        self.emit('fork', block, {
          height: -1,
          expected: orphan.hash('hex'),
          received: hash,
          checkpoint: false
        }, peer);
        return done();
      }
      self.emit('orphan', block, {
        height: -1,
        hash: hash,
        seen: true
      }, peer);
      return done();
    }

    // Update the best height based on the coinbase.
    // We do this even for orphans (peers will send
    // us their highest block during the initial
    // getblocks sync, making it an orphan).
    if (block.getCoinbaseHeight() > self.bestHeight)
      self.bestHeight = block.getCoinbaseHeight();

    // If previous block wasn't ever seen,
    // add it current to orphans and break.
    if (prevHeight == null) {
      self.orphan.count++;
      self.orphan.size += block.getSize();
      self.orphan.map[prevHash] = block;
      self.orphan.bmap[hash] = block;
      self.emit('orphan', block, {
        height: -1,
        hash: hash,
        seen: false
      }, peer);
      return done();
    }

    // Create a new chain entry.
    entry = new bcoin.chainblock(self, {
      hash: hash,
      version: block.version,
      prevBlock: prevHash,
      merkleRoot: block.merkleRoot,
      ts: block.ts,
      bits: block.bits,
      nonce: block.nonce,
      height: prevHeight + 1
    });

    // Fork at checkpoint
    // Block did not match the checkpoint. The
    // chain could be reset to the last sane
    // checkpoint, but it really isn't necessary,
    // so we don't do it. The misbehaving peer has
    // been killed and hopefully we find a peer
    // who isn't trying to fool us.
    checkpoint = network.checkpoints[entry.height];
    if (checkpoint) {
      self.emit('checkpoint', block, {
        height: entry.height,
        hash: entry.hash,
        checkpoint: checkpoint
      }, peer);
      if (entry.hash !== checkpoint) {
        // Resetting to the last checkpoint _really_ isn't
        // necessary (even bitcoind doesn't do it), but it
        // could be used if you want to be on the overly
        // safe (see: paranoid) side.
        // this.resetLastCheckpoint(entry.height);
        self.emit('fork', block, {
          height: entry.height,
          expected: network.checkpoints[entry.height],
          received: entry.hash,
          checkpoint: true
        }, peer);
        return done();
      }
    }

    // See if the entry already exists.
    existing = self.db.get(entry.height);

    // Entry already exists.
    if (existing) {
      // We already have this block. Do regular
      // orphan resolution (won't do anything).
      // NOTE: Wrap this in a nextTick to avoid
      // a stack overflow if there are a lot of
      // existing blocks.
      if (existing.hash === hash) {
        self.emit('exists', block, {
          height: entry.height,
          hash: entry.hash
        }, peer);
        return utils.nextTick(handleOrphans);
      }

      // A valid block with an already existing
      // height came in, that spells fork. We
      // don't store by hash so we can't compare
      // chainworks. We reset the chain, find a
      // new peer, and wait to see who wins.
      assert(self.heightLookup[entry.hash] == null);

      // The tip has more chainwork, it is a
      // higher height than the entry. This is
      // not an alternate tip. Ignore it.
      if (self.tip.chainwork.cmp(entry.chainwork) > 0)
        return done();

      // The block has equal chainwork (an
      // alternate tip). Reset the chain, find
      // a new peer, and wait to see who wins.
      // return self.revertHeight(existing.height - 1, function(err) {
      return self._revertLast(existing, function(err, existingBlock) {
        if (err)
          return done(err);

        self.emit('fork', block, {
          height: existing.height,
          expected: existing.hash,
          received: entry.hash,
          checkpoint: false
        }, peer);

        return done();
      });
    }

    // Add entry if we do not have it.
    assert(self.heightLookup[entry.hash] == null);

    // Lookup previous entry.
    prev = self.db.get(prevHeight);
    assert(prev);

    // Do "contextual" verification on our block
    // now that we're certain its previous
    // block is in the chain.
    self._verifyContext(block, prev, function(err, verified) {
      if (err)
        return done(err);

      if (!verified) {
        self.invalid[entry.hash] = true;
        self.emit('invalid', block, {
          height: entry.height,
          hash: entry.hash,
          seen: false,
          chain: false
        }, peer);
        return done();
      }

      // Update the block height
      block.height = entry.height;
      block.txs.forEach(function(tx) {
        tx.height = entry.height;
      });

      // Attempt to add block to the chain index.
      self._addEntry(entry, block, function(err, success) {
        if (err)
          return done(err);

        // Result should never be `unchanged` since
        // we already verified there were no
        // duplicate heights, etc.
        assert(success === true);

        // Keep track of the number of blocks we
        // added and the number of orphans resolved.
        total++;

        // Emit our block (and potentially resolved
        // orphan) so the programmer can save it.
        self.emit('block', block, entry, peer);
        if (block !== initial)
          self.emit('resolved', block, entry, peer);

        self.emit('add block', block);

        // Fullfill request
        self.request.fullfill(hash, block);

        handleOrphans();
      });
    });

    function handleOrphans() {
      if (!self.orphan.map[hash])
        return done();

      // An orphan chain was found, start resolving.
      block = self.orphan.map[hash];
      delete self.orphan.bmap[block.hash('hex')];
      delete self.orphan.map[hash];
      self.orphan.count--;
      self.orphan.size -= block.getSize();

      next(block);
    }
  })(initial);

  function done(err) {
    var item;

    // Failsafe for large orphan chains. Do not
    // allow more than 20mb stored in memory.
    if (self.orphan.size > self.orphanLimit) {
      self.emit('purge', self.orphan.count, self.orphan.size, peer);
      Object.keys(self.orphan.bmap).forEach(function(hash) {
        self.emit('unresolved', self.orphan.bmap[hash], peer);
      });
      self.orphan.map = {};
      self.orphan.bmap = {};
      self.orphan.count = 0;
      self.orphan.size = 0;
    }

    // We intentionally did not asyncify the
    // callback so if it calls chain.add, it
    // still gets added to the queue. The
    // chain.add below needs to be in a nextTick
    // so we don't cause a stack overflow if
    // these end up being all sync chain.adds.
    utils.nextTick(function() {
      if (err)
        callback(err);
      else
        callback(null, total);

      self.total += total;
      self.locked = false;

      // Start resolving the queue
      // (I love asynchronous IO).
      if (self.pending.length === 0) {
        self.emit('flush');
        return;
      }

      item = self.pending.shift();
      delete self.pendingBlocks[item[0].hash('hex')];
      self.pendingSize -= item[0].getSize();

      self.add(item[0], item[1], item[2]);
    });
  }
};

Chain.prototype.has = function has(hash) {
  if (this.hasBlock(hash))
    return true;

  if (this.hasOrphan(hash))
    return true;

  if (this.hasPending(hash))
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

Chain.prototype.hasPending = function hasPending(hash) {
  if (utils.isBuffer(hash))
    hash = utils.toHex(hash);
  else if (hash.hash)
    hash = hash.hash('hex');

  return !!this.pendingBlocks[hash];
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
  var top = this.height;
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

Chain.prototype.getLocatorAsync = function getLocatorAsync(start, callback) {
  var self = this;
  var hashes = [];
  var top = this.height;
  var step = 1;
  var i, called;

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

  function done(err) {
    if (called)
      return;

    called = true;

    if (err)
      return callback(err);

    return callback(null, hashes);
  }

  this.db.hasAsync(top, function(err, has) {
    var pending;

    if (err)
      return done(err);

    if (!has)
      return done(new Error('Potential reset.'));

    i = top;
    for (;;) {
      hashes.push(i);
      i = i - step;
      if (i <= 0) {
        if (i + step !== 0)
          hashes.push(0);
        break;
      }
      if (hashes.length >= 10)
        step *= 2;
    }

    pending = hashes.length;

    hashes.forEach(function(height, i) {
      if (typeof height === 'string') {
        if (!--pending)
          done();
        return;
      }

      self.db.getAsync(height, function(err, existing) {
        if (err)
          return done(err);

        if (!existing)
          return done(new Error('Potential reset.'));

        hashes[i] = existing.hash;

        if (!--pending)
          done();
      });
    });
  });
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
