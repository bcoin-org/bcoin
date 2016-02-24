/**
 * chain.js - blockchain management for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

var EventEmitter = require('events').EventEmitter;

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
  this.request = new utils.RequestCache();
  this.loading = false;
  this.mempool = options.mempool;
  this.blockdb = options.blockdb;
  this.busy = false;
  this.jobs = [];
  this.pending = [];
  this.pendingBlocks = {};
  this.pendingSize = 0;
  this.total = 0;
  this.orphanLimit = options.orphanLimit || 10 * 1024 * 1024;
  this.pendingLimit = options.pendingLimit || 10 * 1024 * 1024;
  this.invalid = {};
  this.bestHeight = -1;
  this.lastUpdate = utils.now();
  this.blockDelta = 0;

  this.orphan = {
    map: {},
    bmap: {},
    count: 0,
    size: 0
  };

  Chain.global = this;

  this._init();
}

utils.inherits(Chain, EventEmitter);

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
    utils.debug('Warning: %d (%dmb) orphans cleared!', count, utils.mb(size));
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
      if (err) {
        utils.debug('Preloading chain failed.');
        utils.debug('Reason: %s', err.message);
      }

      self.db.load(start || 0, function(err) {
        if (err)
          throw err;

        self.syncHeight(function(err) {
          if (err)
            throw err;

          self.loading = false;
          self.emit('load');
        });
      });
    });
  });
};

Chain.prototype.__defineGetter__('tip', function() {
  return this.db.tip;
});

Chain.prototype.__defineGetter__('height', function() {
  return this.db.height;
});

// Maybe do this:
// Chain.prototype._lock = function _lock(func, args, callback, force) {
// And return wrapped callback with an unlock call in it

Chain.prototype._lock = function _lock(func, args, force) {
  var self = this;
  var block, called;

  if (force) {
    assert(this.busy);
    return function unlock() {
      assert(!called);
      called = true;
    };
  }

  if (this.busy) {
    if (func === Chain.prototype.add) {
      block = args[0];
      this.pending.push(block);
      this.pendingBlocks[block.hash('hex')] = true;
      this.pendingSize += block.getSize();
      if (this.pendingSize > this.pendingLimit) {
        this.purgePending();
        return;
      }
    }
    this.jobs.push([func, args]);
    return;
  }

  this.busy = true;

  return function unlock() {
    var item, block;

    assert(!called);
    called = true;

    self.busy = false;

    if (func === Chain.prototype.add) {
      if (self.pending.length === 0)
        self.emit('flush');
    }

    if (self.jobs.length === 0)
      return;

    item = self.jobs.shift();

    if (item[0] === Chain.prototype.add) {
      block = item[1][0];
      assert(block === self.pending.shift());
      delete self.pendingBlocks[block.hash('hex')];
      self.pendingSize -= block.getSize();
    }

    item[0].apply(self, item[1]);
  };
};

Chain.prototype._ensureGenesis = function _ensureGenesis(callback) {
  var self = this;

  callback = utils.asyncify(callback);

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
  var request;

  if (!this.options.preload)
    return callback();

  if (network.type !== 'main')
    return callback(new Error('Electrum.org only offers `main` headers.'));

  try {
    request = require('request');
  } catch (e) {
    return callback(e);
  }

  utils.debug('Loading %s', url);

  stream = request.get(url);
  chainHeight = this.db.getSize() - 1;
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
    self.resetHeightAsync(start, function(e) {
      if (e)
        throw e;
      return callback(err, start + 1);
    });
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
        self.resetHeightAsync(start, function(e) {
          if (e)
            throw e;
          return callback(new Error('Corrupt headers.'), start + 1);
        });
      }

      // Verify the block headers. We don't want to
      // trust an external centralized source completely.
      if (!block.verify()) {
        start = Math.max(0, height - 2);
        stream.destroy();
        self.resetHeightAsync(start, function(e) {
          if (e)
            throw e;
          return callback(new Error('Bad headers.'), start + 1);
        });
      }

      lastEntry = entry;

      delete entry.chainwork;
      entry.chainwork = entry.getChainwork();

      // Make sure the genesis block is correct.
      if (height === 0 && entry.hash !== network.genesis.hash) {
        stream.destroy();
        return callback(new Error('Bad genesis block.'), 0);
      }

      // Filthy hack to avoid writing
      // redundant blocks to disk!
      if (height <= chainHeight) {
        self.db._cache(entry);
        self.db._populate(entry);
      } else {
        self.db.saveAsync(entry);
      }

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

  // For some reason bitcoind has p2sh in the
  // mandatory flags by default, when in reality
  // it wasn't activated until march 30th 2012.
  // The first p2sh output and redeem script
  // appeared on march 7th 2012, only it did
  // not have a signature. See:
  // https://blockchain.info/tx/6a26d2ecb67f27d1fa5524763b49029d7106e91e3cc05743073461a719776192
  // https://blockchain.info/tx/9c08a4d78931342b37fd5f72900fb9983087e6f46c4a097d8a1f52c74e28eaf6
  if (block.ts < constants.block.bip16time)
    flags &= ~constants.flags.VERIFY_P2SH;

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
  if (block.type !== 'block')
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
  }

  return flags;
};

Chain.prototype._checkDuplicates = function _checkDuplicates(block, prev, callback) {
  var self = this;
  var height = prev.height + 1;

  if (!this.blockdb || block.type !== 'block')
    return callback(null, true);

  if (block.isGenesis())
    return callback(null, true);

  // Check all transactions
  utils.every(block.txs, function(tx, next) {
    var hash = tx.hash('hex');

    // BIP30 - Ensure there are no duplicate txids
    self.blockdb.hasTX(hash, function(err, result) {
      if (err)
        return next(err);

      // Blocks 91842 and 91880 created duplicate
      // txids by using the same exact output script
      // and extraNonce.
      if (result) {
        utils.debug('Block is overwriting txids: %s', block.rhash);
        if (!(network.type === 'main' && (height === 91842 || height === 91880)))
          return next(null, false);
      }

      next(null, true);
    });
  }, callback);
};

Chain.prototype._checkInputs = function _checkInputs(block, prev, flags, callback) {
  var self = this;
  var height = prev.height + 1;
  var scriptCheck = true;

  if (!this.blockdb || block.type !== 'block')
    return callback(null, true);

  if (block.isGenesis())
    return callback(null, true);

  // If we are an ancestor of a checkpoint, we can
  // skip the input verification.
  if (this.options.useCheckpoints) {
    if (height < network.checkpoints.lastHeight && !network.checkpoints[height])
      scriptCheck = false;
  }

  this._fillBlock(block, function(err) {
    var i, j, input, hash;
    var sigops = 0;

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
            utils.revHex(input.prevout.hash) + '/' + input.prevout.index);
          if (height < network.checkpoints.lastHeight)
            throw new Error('BUG: Spent inputs in historical data!');
          return callback(null, false);
        }

        if (!scriptCheck)
          continue;

        // Verify the scripts
        if (!tx.verify(j, true, flags)) {
          utils.debug('Block has invalid inputs: %s (%s/%d)',
            block.rhash, tx.rhash, j);
          utils.debug(input);
          utils.debug('Signature Hash: %s',
            utils.toHex(tx.signatureHash(j, input.output.script, 'all')));
          utils.debug('Raw Script: %s',
            utils.toHex(input.output.script._raw || []));
          utils.debug('Reserialized Script: %s',
            utils.toHex(bcoin.script.encode(input.output.script)));
          if (height < network.checkpoints.lastHeight)
            throw new Error('BUG: Bad inputs in historical data!');
          return callback(null, false);
        }
      }

      if (!scriptCheck)
        continue;

      // Check for block sigops limits
      // Start counting P2SH sigops once block
      // timestamps reach March 31st, 2012.
      if (block.ts >= constants.block.bip16time)
        sigops += tx.getSigops(true);
      else
        sigops += tx.getSigops();

      if (sigops > constants.script.maxBlockSigops) {
        utils.debug('Block has too many sigops: %s', block.rhash);
        return callback(null, false);
      }
    }

    return callback(null, true);
  });
};

Chain.prototype._checkReward = function _checkReward(block) {
  var claimed, actual;

  claimed = block.txs[0].getOutputValue();
  actual = bcoin.block.reward(block.height);

  for (i = 1; i < block.txs.length; i++)
    actual.iadd(block.txs[i].getFee());

  if (claimed.cmp(actual) > 0)
    return false;

  return true;
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
  var existing, now;

  callback = utils.asyncify(callback);

  // Already added
  if (this.db.has(entry.height)) {
    assert(this.db.getHeight(entry.hash) === entry.height);
    return callback(null, false);
  }

  // Duplicate height (do a sync call here since this is cached)
  existing = this.db.getSync(entry.height);
  if (existing && existing.hash === entry.hash)
    return callback(null, false);

  now = utils.now();
  this.blockDelta = now - this.lastUpdate;
  this.lastUpdate = now;

  this._saveBlock(block, function(err) {
    if (err)
      return callback(err);

    self.db.saveAsync(entry, function(err) {
      if (err)
        return callback(err);

      return callback(null, true);
    });
  });
};

Chain.prototype.resetHeight = function resetHeight(height, force) {
  var self = this;

  if (height === this.db.getSize() - 1)
    return;

  this.db.resetHeightSync(height, function(entry) {
    self.emit('remove entry', entry);
  });

  // Reset the orphan map completely. There may
  // have been some orphans on a forked chain we
  // no longer need.
  this.purgeOrphans();
  this.purgePending();
};

Chain.prototype.resetHeightAsync = function resetHeightAsync(height, callback, force) {
  var self = this;

  var unlock = this._lock(resetHeightAsync, [height, callback], force);
  if (!unlock)
    return;

  function done(err, result) {
    unlock();
    if (callback)
      callback(err, result);
  }

  if (height === this.db.getSize() - 1)
    return utils.nextTick(done);

  this.db.resetHeightAsync(height, function(err) {
    if (err)
      return done(err);

    // Reset the orphan map completely. There may
    // have been some orphans on a forked chain we
    // no longer need.
    self.purgeOrphans();
    self.purgePending();

    return done();
  }, function(entry) {
    self.emit('remove entry', entry);
  });
};

Chain.prototype.revertHeight = function revertHeight(height, callback, force) {
  var self = this;
  var chainHeight;

  var unlock = this._lock(revertHeight, [height, callback], force);
  if (!unlock)
    return;

  callback = utils.asyncify(callback);

  function done(err, result) {
    unlock();
    callback(err, result);
  }

  chainHeight = this.db.getSize() - 1;

  if (chainHeight < 0)
    return done(new Error('Bad chain height.'));

  if (chainHeight < height)
    return done(new Error('Cannot reset height.'));

  if (chainHeight === height)
    return done();

  this.resetHeightAsync(height, function(err) {
    if (err)
      return done(err);

    if (!self.blockdb)
      return done();

    self.blockdb.getHeight(function(err, blockHeight) {
      if (err)
        return done(err);

      if (blockHeight < 0)
        return done(new Error('Bad block height.'));

      if (blockHeight < height)
        return done(new Error('Cannot reset height.'));

      if (blockHeight === height)
        return done();

      self.blockdb.resetHeight(height, function(err) {
        if (err)
          return done(err);

        return done();
      }, function(block) {
        self.emit('remove block', block);
      });
    });
  }, true);
};

Chain.prototype._revertLast = function _revertLast(existing, callback, force) {
  var self = this;

  var unlock = this._lock(_revertLast, [existing, callback], force);
  if (!unlock)
    return;

  function done(err, result) {
    unlock();
    callback(err, result);
  }

  this.resetHeightAsync(existing.height - 1, function(err) {
    if (err)
      return done(err);

    self._removeBlock(existing.hash, function(err, existingBlock) {
      if (err)
        return done(err);

      if (existingBlock)
        self.emit('remove block', existingBlock);

      return done();
    });
  }, true);
};

Chain.prototype.syncHeight = function syncHeight(callback, force) {
  var self = this;
  var chainHeight;

  var unlock = this._lock(syncHeight, [callback], force);
  if (!unlock)
    return;

  callback = utils.asyncify(callback);

  function done(err, result) {
    unlock();
    callback(err, result);
  }

  chainHeight = this.db.getSize() - 1;

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
      utils.debug('ChainDB is higher than BlockDB. Syncing...');
      return self.resetHeightAsync(blockHeight, done, true);
    }

    if (blockHeight > chainHeight) {
      utils.debug('BlockDB is higher than ChainDB. Syncing...');
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

Chain.prototype.resetTimeAsync = function resetTimeAsync(ts, callback, force) {
  var self = this;

  var unlock = this._lock(resetTimeAsync, [ts, callback], force);
  if (!unlock)
    return;

  this.byTimeAsync(ts, function(err, entry) {
    if (err) {
      unlock();
      if (callback)
        callback(err);
      return;
    }

    if (!entry) {
      unlock();
      if (callback)
        callback();
      return;
    }

    self.resetHeightAsync(entry.height, function(err) {
      unlock();
      if (callback)
        callback(err);
    }, true);
  }, true);
};

Chain.prototype.onFlush = function onFlush(callback) {
  if (this.pending.length === 0)
    return callback();

  this.once('flush', callback);
};

Chain.prototype.add = function add(initial, peer, callback, force) {
  var self = this;
  var total = 0;

  assert(!this.loading);

  var unlock = this._lock(add, [initial, peer, callback], force);
  if (!unlock)
    return;

  (function next(block) {
    var hash = block.hash('hex');
    var prevHash = block.prevBlock;
    var prevHeight, height, entry, checkpoint, prev, orphan;

    // Find the previous block height/index.
    prevHeight = self.db.getHeight(prevHash);
    height = prevHeight === -1 ? -1 : prevHeight + 1;

    // We already have this block.
    if (self.db.has(hash) || self.hasPending(hash)) {
      self.emit('exists', block, {
        height: height,
        hash: hash
      }, peer);
      return done();
    }

    // Do not revalidate known invalid blocks.
    if (self.invalid[hash] || self.invalid[prevHash]) {
      self.emit('invalid', block, {
        height: height,
        hash: hash,
        seen: !!self.invalid[hash],
        chain: !!self.invalid[prevHash]
      }, peer);
      self.invalid[hash] = true;
      return done();
    }

    // Validate the block we want to add.
    // This is only necessary for new
    // blocks coming in, not the resolving
    // orphans.
    if (block === initial && !block.verify()) {
      self.invalid[hash] = true;
      self.emit('invalid', block, {
        height: height,
        hash: hash,
        seen: false,
        chain: false
      }, peer);
      return done();
    }

    // Special case for genesis block.
    if (block.isGenesis())
      return done();

    // If the block is already known to be
    // an orphan, ignore it.
    orphan = self.orphan.map[prevHash];
    if (orphan) {
      // If the orphan chain forked, simply
      // reset the orphans and find a new peer.
      if (orphan.hash !== hash) {
        self.purgeOrphans();
        self.purgePending();

        self.emit('fork', block, {
          height: -1,
          expected: orphan.hash,
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
    if (prevHeight === -1) {
      self.emit('orphan', block, {
        height: -1,
        hash: hash,
        seen: false
      }, peer);
      block = {
        data: block._raw,
        type: block.type,
        hash: block.hash('hex'),
        prevBlock: block.prevBlock,
        coinbaseHeight: block.getCoinbaseHeight()
      };
      self.orphan.count++;
      self.orphan.size += block.data.length;
      self.orphan.map[prevHash] = block;
      self.orphan.bmap[hash] = block;
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

    // Verify the checkpoint.
    checkpoint = network.checkpoints[entry.height];
    if (checkpoint) {
      self.emit('checkpoint', block, {
        height: entry.height,
        hash: entry.hash,
        checkpoint: checkpoint
      }, peer);

      // Block did not match the checkpoint. The
      // chain could be reset to the last sane
      // checkpoint, but it really isn't necessary,
      // so we don't do it. The misbehaving peer has
      // been killed and hopefully we find a peer
      // who isn't trying to fool us.
      if (entry.hash !== checkpoint) {
        self.purgeOrphans();
        self.purgePending();

        self.emit('fork', block, {
          height: entry.height,
          expected: checkpoint,
          received: entry.hash,
          checkpoint: true
        }, peer);

        return done();
      }
    }

    // Lookup previous entry.
    // We can do this synchronously:
    // This will be cached in 99.9% of cases.
    if (!self.db.isCached(prevHeight))
      utils.debug('Warning: height %d is not cached.', prevHeight);

    try {
      prev = self.db.getSync(prevHeight);
    } catch (e) {
      return done(e);
    }

    assert(prev);

    // Do "contextual" verification on our block
    // now that we're certain its previous
    // block is in the chain.
    self._verifyContext(block, prev, function(err, verified) {
      var existing;

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

      // Real fork resolution would just be this.
      // if (entry.chainwork.cmp(self.tip.chainwork) > 0)
      //   return self.setBestChain(entry);
      // return done();

      // See if the height already exists (fork).
      // Do this synchronously: This will
      // be cached in 99.9% of cases.
      if (self.db.has(entry.height)) {
        if (!self.db.isCached(entry.height))
          utils.debug('Warning: height %d is not cached.', entry.height);

        try {
          existing = self.db.getSync(entry.height);
        } catch (e) {
          return done(e);
        }

        // Shouldn't be the same by this point.
        assert(existing.hash !== entry.hash);

        // A valid block with an already existing
        // height came in, that spells fork. We
        // don't store by hash so we can't compare
        // chainworks. We reset the chain, find a
        // new peer, and wait to see who wins.
        assert(self.db.getHeight(entry.hash) === -1);

        // The tip has more chainwork, it is a
        // higher height than the entry. This is
        // not an alternate tip. Ignore it.
        if (existing.chainwork.cmp(entry.chainwork) > 0)
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
        }, true);
      }

      // Add entry if we do not have it.
      assert(self.db.getHeight(entry.hash) === -1);

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

        // Fulfill request
        self.request.fulfill(hash, block);

        handleOrphans();
      });
    });

    function handleOrphans() {
      if (!self.orphan.map[hash])
        return done();

      // An orphan chain was found, start resolving.
      block = self.orphan.map[hash];
      delete self.orphan.bmap[block.hash];
      delete self.orphan.map[hash];
      self.orphan.count--;
      self.orphan.size -= block.data.length;

      if (block.type === 'block')
        block = bcoin.block.fromRaw(block.data);
      else if (block.type === 'merkleblock')
        block = bcoin.merkleblock.fromRaw(block.data);
      else if (block.type === 'headers')
        block = bcoin.headers.fromRaw(block.data);

      next(block);
    }
  })(initial);

  function done(err) {
    var item;

    // Failsafe for large orphan chains. Do not
    // allow more than 20mb stored in memory.
    if (self.orphan.size > self.orphanLimit)
      self.pruneOrphans(peer);

    // Keep track of total blocks handled.
    self.total += total;

    // We intentionally did not asyncify the
    // callback so if it calls chain.add, it
    // still gets added to the queue. The
    // chain.add below needs to be in a nextTick
    // so we don't cause a stack overflow if
    // these end up being all sync chain.adds.
    utils.nextTick(function() {
      unlock();
      if (err)
        callback(err);
      else
        callback(null, total);
    });
  }
};

Chain.prototype.purgeOrphans = function purgeOrphans() {
  this.emit('purge', this.orphan.count, this.orphan.size);
  this.orphan.map = {};
  this.orphan.bmap = {};
  this.orphan.count = 0;
  this.orphan.size = 0;
};

Chain.prototype.pruneOrphans = function pruneOrphans(peer) {
  var self = this;
  var best, last;

  best = Object.keys(this.orphan.map).reduce(function(best, prevBlock, i) {
    var orphan = self.orphan.map[prevBlock];
    var height = orphan.coinbaseHeight;

    last = orphan;

    if (!best || height > best.coinbaseHeight)
      return orphan;

    return best;
  }, null);

  // Save the best for last... or the
  // last for the best in this case.
  if (!best || best.coinbaseHeight <= 0)
    best = last;

  this.emit('purge',
    this.orphan.count - (best ? 1 : 0),
    this.orphan.size - (best ? best.data.length : 0));

  Object.keys(this.orphan.bmap).forEach(function(hash) {
    var orphan = self.orphan.bmap[hash];
    if (orphan !== best)
      self.emit('unresolved', orphan, peer);
  });

  this.orphan.map = {};
  this.orphan.bmap = {};
  this.orphan.count = 0;
  this.orphan.size = 0;

  if (!best)
    return;

  this.orphan.map[best.prevBlock] = best;
  this.orphan.bmap[best.hash('hex')] = best;
  this.orphan.count++;
  this.orphan.size += best.data.length;
};

Chain.prototype.purgePending = function purgePending() {
  var self = this;

  utils.debug('Warning: %dmb of pending blocks. Purging.',
    utils.mb(this.pendingSize));

  this.pending.forEach(function(block) {
    delete self.pendingBlocks[block.hash('hex')];
  });

  this.pending.length = 0;
  this.pendingSize = 0;

  this.jobs = this.jobs.filter(function(item) {
    return item[0] !== Chain.prototype.add;
  });
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

Chain.prototype.byTime = function byTime(ts) {
  var start = 0;
  var end = this.height + 1;
  var pos, delta, entry;

  if (ts >= this.tip.ts)
    return this.tip;

  // Do a binary search for a block
  // mined within an hour of the
  // timestamp.
  while (start < end) {
    pos = (start + end) >> 1;
    entry = this.db.getSync(pos);
    delta = Math.abs(ts - entry.ts);

    if (delta <= 60 * 60)
      return entry;

    if (ts < entry.ts) {
      end = pos;
    } else {
      start = pos + 1;
    }
  }

  return this.db.getSync(start);
};

Chain.prototype.byTimeAsync = function byTimeAsync(ts, callback, force) {
  var self = this;
  var start = 0;
  var end = this.height + 1;
  var pos, delta;

  var unlock = this._lock(byTimeAsync, [ts, callback], force);
  if (!unlock)
    return;

  callback = utils.asyncify(callback);

  function done(err, result) {
    if (err) {
      unlock();
      return callback(err);
    }

    if (result) {
      unlock();
      return callback(null, result);
    }

    self.db.getAsync(start, function(err, entry) {
      unlock();
      callback(err, entry);
    });
  }

  if (ts >= this.tip.ts)
    return done(null, this.tip);

  // Do a binary search for a block
  // mined within an hour of the
  // timestamp.
  (function next() {
    if (start >= end)
      return done();

    pos = (start + end) >> 1;

    self.db.getAsync(pos, function(err, entry) {
      if (err)
        return done(err);

      delta = Math.abs(ts - entry.ts);

      if (delta <= 60 * 60)
        return done(null, entry);

      if (ts < entry.ts) {
        end = pos;
      } else {
        start = pos + 1;
      }

      next();
    });
  })();
};

Chain.prototype.hasBlock = function hasBlock(hash) {
  if (typeof hash === 'number')
    return this.db.has(hash);

  if (Buffer.isBuffer(hash))
    hash = utils.toHex(hash);
  else if (hash.hash)
    hash = hash.hash('hex');

  return this.db.has(hash);
};

Chain.prototype.hasOrphan = function hasOrphan(hash) {
  return !!this.getOrphan(hash);
};

Chain.prototype.hasPending = function hasPending(hash) {
  if (Buffer.isBuffer(hash))
    hash = utils.toHex(hash);
  else if (hash.hash)
    hash = hash.hash('hex');

  return !!this.pendingBlocks[hash];
};

Chain.prototype.getEntry = function getEntry(hash) {
  if (typeof hash === 'number')
    return this.db.getSync(hash);

  if (Buffer.isBuffer(hash))
    hash = utils.toHex(hash);
  else if (hash.hash)
    hash = hash.hash('hex');

  return this.db.getSync(hash);
};

Chain.prototype.getEntryAsync = function getEntryAsync(hash, callback) {
  if (typeof hash === 'number')
    return this.db.getAsync(hash, callback);

  if (Buffer.isBuffer(hash))
    hash = utils.toHex(hash);
  else if (hash.hash)
    hash = hash.hash('hex');

  return this.db.getAsync(hash, callback);
};

Chain.prototype.getOrphan = function getOrphan(hash) {
  if (Buffer.isBuffer(hash))
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

Chain.prototype.isInitial = function isInitial() {
  if (!this.tip)
    return true;

  // Should mimic the original IsInitialBlockDownload() function
  return this.blockDelta < 10 && this.tip.ts < utils.now() - 24 * 60 * 60;
};

Chain.prototype.getProgress = function getProgress() {
  if (!this.tip)
    return 0;
  return Math.min(1, this.tip.ts / (utils.now() - 40 * 60));
};

Chain.prototype.getHashRange = function getHashRange(start, end) {
  var hashes = [];
  var i;

  start = this.byTime(start);
  end = this.byTime(end);

  if (!start || !end)
    return hashes;

  for (i = start.height; i < end.height + 1; i++)
    hashes.push(this.db.getSync(i).hash);

  return hashes;
};

Chain.prototype.getHashRangeAsync = function getHashRangeAsync(start, end, callback, force) {
  var self = this;

  var unlock = this._lock(getHashRangeAsync, [start, end, callback], force);
  if (!unlock)
    return;

  function done(err, result) {
    unlock();
    callback(err, result);
  }

  this.byTimeAsync(start, function(err, start) {
    if (err)
      return done(err);

    self.byTimeAsync(end, function(err, end) {
      var hashes, i;

      if (err)
        return done(err);

      hashes = [];

      if (!start || !end)
        return done(null, hashes);

      utils.forRange(start.height, end.height + 1, function(i, next) {
        self.db.getAsync(i, function(err, entry) {
          if (err)
            return next(err);

          if (!entry)
            return next(new Error('No entry for hash range.'));

          hashes[i - start.height] = entry.hash;

          next();
        });
      }, function(err) {
        if (err)
          return done(err);
        return done(null, hashes);
      });
    }, true);
  }, true);
};

Chain.prototype.getLocator = function getLocator(start) {
  var hashes = [];
  var top = this.height;
  var step = 1;
  var i, existing;

  if (start) {
    if (Buffer.isBuffer(start))
      start = utils.toHex(start);
    else if (start.hash)
      start = start.hash('hex');
  }

  if (typeof start === 'string') {
    top = this.db.getHeight(start);
    if (top === -1) {
      // We could simply `return [start]` here,
      // but there is no standardized "spacing"
      // for locator hashes. Pretend this hash
      // is our tip. This is useful for getheaders
      // when not using headers-first.
      hashes.push(start);
      top = this.height;
    }
  } else if (typeof start === 'number') {
    top = start;
  }

  assert(this.db.has(top));

  i = top;
  for (;;) {
    existing = this.db.getSync(i);
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

Chain.prototype.getLocatorAsync = function getLocatorAsync(start, callback, force) {
  var self = this;
  var hashes = [];
  var top = this.height;
  var step = 1;
  var i;

  var unlock = this._lock(getLocatorAsync, [start, callback], force);
  if (!unlock)
    return;

  if (start) {
    if (Buffer.isBuffer(start))
      start = utils.toHex(start);
    else if (start.hash)
      start = start.hash('hex');
  }

  if (typeof start === 'string') {
    top = this.db.getHeight(start);
    if (top === -1) {
      // We could simply `return [start]` here,
      // but there is no standardized "spacing"
      // for locator hashes. Pretend this hash
      // is our tip. This is useful for getheaders
      // when not using headers-first.
      hashes.push(start);
      top = this.height;
    }
  } else if (typeof start === 'number') {
    top = start;
  }

  assert(this.db.has(top));

  callback = utils.asyncify(callback);

  i = top;
  for (;;) {
    hashes.push(i);
    i = i - step;
    if (i <= 0) {
      if (i + step !== 0)
        hashes.push(network.genesis.hash);
      break;
    }
    if (hashes.length >= 10)
      step *= 2;
  }

  utils.forEach(hashes, function(height, next, i) {
    if (typeof height === 'string')
      return next();

    self.db.getAsync(height, function(err, existing) {
      if (err)
        return next(err);

      assert(existing);

      hashes[i] = existing.hash;

      next();
    });
  }, function(err) {
    unlock();
    if (err)
      return callback(err);
    return callback(null, hashes);
  });
};

Chain.prototype.getOrphanRoot = function getOrphanRoot(hash) {
  var self = this;
  var root;

  if (Buffer.isBuffer(hash))
    hash = utils.toHex(hash);
  else if (hash.hash)
    hash = hash.hash('hex');

  assert(hash);

  while (this.orphan.bmap[hash]) {
    root = hash;
    hash = this.orphan.bmap[hash].prevBlock;
  }

  if (!root)
    return;

  return {
    root: root,
    soil: this.orphan.bmap[root].prevBlock
  };
};

Chain.prototype.getHeight = function getHeight(hash) {
  return this.db.getHeight(hash);
};

Chain.prototype.getSize = function getSize() {
  return this.db.getSize();
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
  // NOTE: This is cached.
  first = this.db.getSync(last.height - (network.powDiffInterval - 1));

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

/**
 * Expose
 */

module.exports = Chain;
