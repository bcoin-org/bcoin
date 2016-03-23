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
var utils = require('./utils');
var assert = utils.assert;
var BufferReader = require('./reader');

/**
 * Chain
 */

function Chain(node, options) {
  if (!(this instanceof Chain))
    return new Chain(node, options);

  EventEmitter.call(this);

  if (!options)
    options = {};

  this.options = options;

  this.node = node;
  this.loaded = false;
  this.mempool = node.mempool;
  this.db = new bcoin.chaindb(this, options);
  this.total = 0;
  this.orphanLimit = options.orphanLimit || (20 << 20);
  this.pendingLimit = options.pendingLimit || (20 << 20);
  this.locker = new bcoin.locker(this, this.add, this.pendingLimit);
  this.invalid = {};
  this.bestHeight = -1;
  this.lastUpdate = utils.now();
  this.tip = null;
  this.height = -1;

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
    // var host = peer ? peer.host : 'unknown';
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

  this.db.on('add entry', function(entry) {
    self.emit('add entry', entry);
  });

  this.db.on('remove entry', function(entry) {
    self.emit('remove entry', entry);
  });

  this.db.on('add block', function(block) {
    self.emit('add block', block);
  });

  this.db.on('remove block', function(block) {
    self.emit('remove block', block);
  });

  utils.debug('Chain is loading.');

  self._preload(function(err, start) {
    if (err) {
      utils.debug('Preloading chain failed.');
      utils.debug('Reason: %s', err.message);
    }

    self.db.open(function(err) {
      if (err)
        return self.emit('error', err);

      self.db.getTip(function(err, tip) {
        if (err)
          return self.emit('error', err);

        assert(tip);

        self.tip = tip;
        self.height = tip.height;

        self.loaded = true;
        self.emit('open');
      });
    });
  });
};

Chain.prototype.open = function open(callback) {
  if (this.loaded)
    return utils.nextTick(callback);

  this.once('open', callback);
};

Chain.prototype._lock = function _lock(func, args, force) {
  return this.locker.lock(func, args, force);
};

// Stream headers from electrum.org for quickly
// preloading the chain. Electrum.org stores
// headers in the standard block header format,
// but they do not store chainwork, so we have
// to calculate it ourselves.
Chain.prototype._preload = function _preload(callback) {
  var self = this;
  var url = 'https://headers.electrum.org/blockchain_headers';
  var buf, height, stream;
  var request = require('./http/request');

  if (!this.options.preload)
    return callback();

  if (!this.options.spv)
    return callback();

  if (network.type !== 'main')
    return callback(new Error('Electrum.org only offers `main` headers.'));

  utils.debug('Loading %s', url);

  function parseHeader(buf) {
    var p = new BufferReader(buf);
    var hash = utils.dsha256(buf.slice(0, 80));

    return {
      hash: utils.toHex(hash),
      version: p.read32(),
      prevBlock: p.readHash('hex'),
      merkleRoot: p.readHash('hex'),
      ts: p.readU32(),
      bits: p.readU32(),
      nonce: p.readU32()
    };
  }

  this.db.getChainHeight(function(err, chainHeight) {
    if (err)
      return callback(err);

    stream = request({ method: 'GET', uri: url });
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
      self.reset(start, function(e) {
        if (e)
          throw e;
        return callback(err, start + 1);
      });
    });

    stream.on('data', function(data) {
      var blocks = [];
      var need = 80 - buf.size;
      var lastEntry;

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
        var block, entry, start;

        data = parseHeader(data);
        data.height = height;

        // Make sure the genesis block is correct.
        if (data.height === 0 && data.hash !== network.genesis.hash) {
          stream.destroy();
          return callback(new Error('Bad genesis block.'), 0);
        }

        // Do some paranoid checks.
        if (lastEntry && data.prevBlock !== lastEntry.hash) {
          start = Math.max(0, height - 2);
          stream.destroy();
          return self.reset(start, function(err) {
            if (err)
              throw err;
            return callback(new Error('Corrupt headers.'), start + 1);
          });
        }

        // Create headers object for validation.
        block = new bcoin.headers(data);

        // Verify the block headers. We don't want to
        // trust an external centralized source completely.
        if (!block.verifyHeaders()) {
          start = Math.max(0, height - 2);
          stream.destroy();
          return self.reset(start, function(err) {
            if (err)
              throw err;
            return callback(new Error('Bad headers.'), start + 1);
          });
        }

        // Create a chain entry.
        entry = new bcoin.chainblock(self, data, lastEntry);

        // Filthy hack to avoid writing
        // redundant blocks to disk!
        if (entry.height <= chainHeight) {
          self.db.addCache(entry);
          // self.db.bloom(entry.hash, 'hex');
        } else {
          self.db.save(entry);
        }

        if ((height + 1) % 50000 === 0)
          utils.debug('Received %d headers from electrum.org.', height + 1);

        lastEntry = entry;
        height++;
      });
    });

    stream.on('end', function() {
      return callback(null, height + 1);
    });
  });
};

Chain.prototype._verifyContext = function _verifyContext(block, prev, peer, callback) {
  var self = this;

  this._verify(block, prev, peer, function(err, flags) {
    if (err)
      return callback(err);

    if (flags === false)
      return callback(null, false);

    self._checkDuplicates(block, prev, peer, function(err, result) {
      if (err)
        return callback(err);

      if (!result)
        return callback(null, false);

      self._checkInputs(block, prev, flags, peer, function(err, result) {
        if (err)
          return callback(err);

        if (!result)
          return callback(null, false);

        return callback(null, true);
      });
    });
  });
};

Chain.prototype._verify = function _verify(block, prev, peer, callback) {
  var self = this;
  var flags = constants.flags.MANDATORY_VERIFY_FLAGS;
  var height, ts, i, tx, coinbaseHeight;
  var medianTime, locktimeMedian, segwit;
  var ret = {};

  function done(err, result) {
    prev.free();
    callback(err, result);
  }

  if (!block.verify(ret)) {
    self.emit('verify-error', block, ret.reason, ret.score, peer);
    return done(null, false);
  }

  // Skip the genesis block
  if (block.isGenesis())
    return done(null, flags);

  // Ensure it's not an orphan
  if (!prev) {
    utils.debug('Block has no previous entry: %s', block.rhash);
    return done(null, false);
  }

  prev.ensureAncestors(function(err) {
    if (err)
      return callback(err);

    height = prev.height + 1;
    medianTime = prev.getMedianTime();

    // Ensure the timestamp is correct
    if (block.ts <= medianTime) {
      utils.debug('Block time is lower than median: %s', block.rhash);
      self.emit('verify-error', block, 'time-too-old', 0, peer);
      return done(null, false);
    }

    if (block.bits !== self.getTarget(prev, block)) {
      utils.debug('Block is using wrong target: %s', block.rhash);
      self.emit('verify-error', block, 'bad-diffbits', 100, peer);
      return done(null, false);
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
      self.emit('verify-error', block, 'bad-version', 0, peer);
      return done(null, false);
    }

    // Only allow version 3 blocks (sig validation)
    // once the majority of blocks are using it.
    if (block.version < 3 && prev.isOutdated(3)) {
      utils.debug('Block is outdated (v3): %s', block.rhash);
      self.emit('verify-error', block, 'bad-version', 0, peer);
      return done(null, false);
    }

    // Only allow version 4 blocks (checklocktimeverify)
    // once the majority of blocks are using it.
    if (block.version < 4 && prev.isOutdated(4)) {
      utils.debug('Block is outdated (v4): %s', block.rhash);
      self.emit('verify-error', block, 'bad-version', 0, peer);
      return done(null, false);
    }

    // Only allow version 5 blocks (segwit)
    // once the majority of blocks are using it.
    if (network.segwitHeight !== -1 && height >= network.segwitHeight) {
      if (block.version < 5 && prev.isOutdated(5)) {
        utils.debug('Block is outdated (v5): %s', block.rhash);
        self.emit('verify-error', block, 'bad-version', 0, peer);
        return done(null, false);
      }
    }

    // Only allow version 8 blocks (locktime median past)
    // once the majority of blocks are using it.
    // if (block.version < 8 && prev.isOutdated(8)) {
    //   utils.debug('Block is outdated (v8): %s', block.rhash);
    //   return false);
    // }

    // Make sure the height contained in the coinbase is correct.
    if (network.block.bip34height !== -1 && height >= network.block.bip34height) {
      if (block.version >= 2 && prev.isUpgraded(2))
        coinbaseHeight = true;
    }

    // Signature validation is now enforced (bip66)
    if (block.version >= 3 && prev.isUpgraded(3))
      flags |= constants.flags.VERIFY_DERSIG;

    // CHECKLOCKTIMEVERIFY is now usable (bip65)
    if (block.version >= 4 && prev.isUpgraded(4))
      flags |= constants.flags.VERIFY_CHECKLOCKTIMEVERIFY;

    // Segregrated witness is now usable (the-bip-that-really-needs-to-be-rewritten)
    if (network.segwitHeight !== -1 && height >= network.segwitHeight) {
      if (block.version >= 5 && prev.isUpgraded(5)) {
        flags |= constants.flags.VERIFY_WITNESS;
        segwit = true;
      }
    }

    // Can't verify any further when merkleblock or headers.
    if (block.type !== 'block')
      return done(null, flags);

    // Make sure the height contained in the coinbase is correct.
    if (coinbaseHeight) {
      if (block.getCoinbaseHeight() !== height) {
        utils.debug('Block has bad coinbase height: %s', block.rhash);
        self.emit('verify-error', block, 'bad-cb-height', 100, peer);
        return done(null, false);
      }
    }

    if (block.version >= 5 && segwit) {
      if (block.commitmentHash !== block.getCommitmentHash()) {
        utils.debug('Block failed witnessroot test: %s', block.rhash);
        self.emit('verify-error', block, 'bad-blk-wit-length', 100, peer);
        return done(null, false);
      }
    } else {
      if (block.hasWitness()) {
        utils.debug('Unexpected witness data found: %s', block.rhash);
        self.emit('verify-error', block, 'unexpected-witness', 100, peer);
        return done(null, false);
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
        self.emit('verify-error', block, 'bad-txns-nonfinal', 10, peer);
        return done(null, false);
      }
    }

    return done(null, flags);
  });
};

Chain.prototype._checkDuplicates = function _checkDuplicates(block, prev, peer, callback) {
  var self = this;
  var height = prev.height + 1;

  if (this.options.spv || block.type !== 'block')
    return callback(null, true);

  if (block.isGenesis())
    return callback(null, true);

  // Check all transactions
  utils.everySerial(block.txs, function(tx, next) {
    var hash = tx.hash('hex');

    // BIP30 - Ensure there are no duplicate txids
    self.db.isUnspentTX(hash, function(err, result) {
      if (err)
        return next(err);

      // Blocks 91842 and 91880 created duplicate
      // txids by using the same exact output script
      // and extraNonce.
      if (result) {
        utils.debug('Block is overwriting txids: %s', block.rhash);
        if (!(network.type === 'main' && (height === 91842 || height === 91880))) {
          self.emit('verify-error', block, 'bad-txns-BIP30', 100, peer);
          return next(null, false);
        }
      }

      next(null, true);
    });
  }, callback);
};

Chain.prototype._checkInputs = function _checkInputs(block, prev, flags, peer, callback) {
  var height = prev.height + 1;
  var scriptCheck = true;

  if (this.options.spv || block.type !== 'block')
    return callback(null, true);

  if (block.isGenesis())
    return callback(null, true);

  // If we are an ancestor of a checkpoint, we can
  // skip the input verification.
  if (this.options.useCheckpoints) {
    if (height < network.checkpoints.lastHeight && !network.checkpoints[height])
      scriptCheck = false;
  }

  this.db.fillBlock(block, function(err) {
    var i, j, input, tx, hash;
    var sigops = 0;

    if (err)
      return callback(err);

    // Check all transactions
    for (i = 0; i < block.txs.length; i++) {
      tx = block.txs[i];
      hash = tx.hash('hex');

      // Check for block sigops limits
      // Start counting P2SH sigops once block
      // timestamps reach March 31st, 2012.
      if (block.ts >= constants.block.bip16time)
        sigops += tx.getSigops(true);
      else
        sigops += tx.getSigops();

      if (sigops > constants.script.maxBlockSigops) {
        utils.debug('Block has too many sigops: %s', block.rhash);
        self.emit('verify-error', block, 'bad-blk-sigops', 100, peer);
        return callback(null, false);
      }

      // Coinbases do not have prevouts
      if (tx.isCoinbase())
        continue;

      if (tx.getOutputValue().cmp(tx.getInputValue()) > 0) {
        utils.debug('TX is spending funds it does not have: %s', tx.rhash);
        return false;
      }

      for (j = 0; j < tx.inputs.length; j++) {
        input = tx.inputs[j];

        // Ensure tx is not double spending an output
        if (!input.output) {
          utils.debug('Block is using spent inputs: %s (tx: %s, output: %s)',
            block.rhash, tx.rhash,
            utils.revHex(input.prevout.hash) + '/' + input.prevout.index);
          if (height < network.checkpoints.lastHeight)
            throw new Error('BUG: Spent inputs in historical data!');
          self.emit('verify-error', block, 'bad-txns-inputs-missingorspent', 100, peer);
          return callback(null, false);
        }

        if (!scriptCheck)
          continue;

        // Disable. Use workers and verifyAsync for now.
        continue;

        // Verify the scripts
        if (!tx.verify(j, true, flags)) {
          utils.debug('Block has invalid inputs: %s (%s/%d)',
            block.rhash, tx.rhash, j);
          utils.debug(input);
          utils.debug('Signature Hash v0: %s',
            utils.toHex(tx.signatureHash(j, input.output.script, 'all', 0)));
          utils.debug('Signature Hash v1: %s',
            utils.toHex(tx.signatureHash(j, input.output.script, 'all', 1)));
          utils.debug('Raw Script: %s',
            utils.toHex(input.output.script.encode()));
          utils.debug('Reserialized Script: %s',
            utils.toHex(input.output.script.clone().encode()));
          if (height < network.checkpoints.lastHeight)
            throw new Error('BUG: Bad inputs in historical data!');
          return callback(null, false);
        }
      }
    }

    // Disable. Use workers and verifyAsync for now.
    // return callback(null, true);

    if (!scriptCheck)
      return callback(null, true);

    // Verify all txs in parallel.
    utils.every(block.txs, function(tx, next) {
      tx.verifyAsync(null, true, flags, next);
    }, callback);
  });
};

Chain.prototype._checkReward = function _checkReward(block) {
  var i, claimed, actual;

  claimed = block.txs[0].getOutputValue();
  actual = bcoin.block.reward(block.height);

  for (i = 1; i < block.txs.length; i++)
    actual.iadd(block.txs[i].getFee());

  if (claimed.cmp(actual) > 0) {
    self.emit('verify-error', block, 'bad-cb-amount', 100, peer);
    return false;
  }

  return true;
};

Chain.prototype.getHeight = function getHeight(hash) {
  if (Buffer.isBuffer(hash))
    hash = utils.toHex(hash);
  else if (hash.hash)
    hash = hash.hash('hex');

  if (this.db.hasCache(hash))
    return this.db.getCache(hash).height;

  return -1;
};

Chain.prototype._findFork = function _findFork(fork, longer, callback) {
  (function find() {
    if (fork.hash === longer.hash)
      return callback(null, fork);

    (function next() {
      if (longer.height <= fork.height)
        return done();

      longer.getPrevious(function(err, entry) {
        if (err)
          return callback(err);

        if (!entry)
          return callback(new Error('No previous entry for new tip.'));

        longer = entry;

        next();
      });
    })();

    function done() {
      if (fork.hash === longer.hash)
        return callback(null, fork);

      fork.getPrevious(function(err, entry) {
        if (err)
          return callback(err);

        if (!entry)
          return callback(new Error('No previous entry for old tip.'));

        fork = entry;

        find();
      });
    }
  })();
};

Chain.prototype._reorganize = function _reorganize(entry, block, callback) {
  var self = this;

  return this._findFork(this.tip, entry, function(err, fork) {
    if (err)
      return callback(err);

    assert(fork);

    // Disconnect blocks/txs.
    function disconnect(callback) {
      var entries = [];

      (function collect(entry) {
        entry.getPrevious(function(err, entry) {
          if (err)
            return callback(err);

          assert(entry);

          entries.push(entry);

          if (entry.hash === fork.hash)
            return finish();

          collect(entry);
        });
      })(self.tip);

      function finish() {
        assert(entries.length > 0);

        utils.forEachSerial(entries, function(entry, next) {
          self.db.disconnect(entry, next);
        }, callback);
      }
    }

    // Connect blocks/txs.
    function connect(callback) {
      var entries = [];

      (function collect(entry) {
        entry.getPrevious(function(err, entry) {
          if (err)
            return callback(err);

          assert(entry);

          entries.push(entry);

          if (entry.hash === fork.hash)
            return finish();

          collect(entry);
        });
      })(entry);

      function finish() {
        entries = entries.slice().reverse();
        assert(entries.length > 0);

        utils.forEachSerial(entries, function(entry, next) {
          self.db.connect(entry, next);
        }, callback);
      }
    }

    return disconnect(function(err) {
      if (err)
        return callback(err);

      return connect(function(err) {
        if (err)
          return callback(err);

        self.emit('fork', block, {
          height: fork.height,
          expected: self.tip.hash,
          received: entry.hash,
          checkpoint: false
        });

        return callback();
      });
    });
  });
};

Chain.prototype._setBestChain = function _setBestChain(entry, block, callback) {
  var self = this;

  callback = utils.asyncify(callback);

  this.lastUpdate = utils.now();

  // Start fsyncing writes once we're no
  // longer dealing with historical data.
  if (this.isFull())
    this.db.fsync = true;

  if (!this.tip) {
    if (entry.hash !== network.genesis.hash)
      return callback(new Error('Bad genesis block.'));

    done();
  } else if (entry.prevBlock === this.tip.hash) {
    done();
  } else {
    self._reorganize(entry, block, done);
  }

  function done(err) {
    if (err)
      return callback(err);

    self.db.save(entry, block, function(err) {
      if (err)
        return callback(err);

      self.tip = entry;
      self.height = entry.height;

      return callback();
    });
  }
};

Chain.prototype.reset = function reset(height, callback, force) {
  var self = this;

  var unlock = this._lock(reset, [height, callback], force);
  if (!unlock)
    return;

  callback = utils.ensure(callback);

  this.db.reset(height, function(err, result) {
    if (err) {
      unlock();
      return callback(err);
    }

    // Reset the orphan map completely. There may
    // have been some orphans on a forked chain we
    // no longer need.
    self.purgeOrphans();
    self.purgePending();

    unlock();
    callback(null, result);
  });
};

Chain.prototype.resetTime = function resetTime(ts, callback, force) {
  var self = this;

  var unlock = this._lock(resetTime, [ts, callback], force);
  if (!unlock)
    return;

  callback = utils.ensure(callback);

  this.byTime(ts, function(err, entry) {
    if (err) {
      unlock();
      callback(err);
      return;
    }

    if (!entry) {
      unlock();
      callback();
      return;
    }

    self.reset(entry.height, function(err) {
      unlock();
      callback(err);
    }, true);
  }, true);
};

Chain.prototype.onFlush = function onFlush(callback) {
  return this.locker.onFlush(callback);
};

Chain.prototype.add = function add(initial, peer, callback, force) {
  var self = this;
  var total = 0;
  var ret = {};

  assert(this.loaded);

  var unlock = this._lock(add, [initial, peer, callback], force);
  if (!unlock)
    return;

  (function next(block) {
    var hash = block.hash('hex');
    var prevHash = block.prevBlock;
    var height, checkpoint, orphan;

    // We already have this block.
    self.db.has(hash, function(err, existing) {
      if (err)
        return done(err);

      if (existing || self.hasPending(hash)) {
        self.emit('exists', block, {
          height: -1,
          hash: hash
        }, peer);
        return done();
      }

      // Find the previous block height/index.
      self.db.get(prevHash, function(err, prev) {
        if (err)
          return done(err);

        height = !prev ? -1 : prev.height + 1;

        // Do not revalidate known invalid blocks.
        if (self.invalid[hash] || self.invalid[prevHash]) {
          self.emit('invalid', block, {
            height: height,
            hash: hash,
            seen: !!self.invalid[hash],
            chain: !!self.invalid[prevHash]
          }, peer);
          self.invalid[hash] = true;
          self.emit('verify-error', block, 'duplicate', 0, peer);
          return done();
        }

        // Validate the block we want to add.
        // This is only necessary for new
        // blocks coming in, not the resolving
        // orphans.
        if (block === initial && !block.verify(ret)) {
          self.invalid[hash] = true;
          self.emit('invalid', block, {
            height: height,
            hash: hash,
            seen: false,
            chain: false
          }, peer);
          self.emit('verify-error', block, ret.reason, ret.score, peer);
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
          // reset the orphans.
          if (orphan.hash('hex') !== hash) {
            self.purgeOrphans();
            self.purgePending();

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

          if (self.options.headers)
            self.emit('verify-error', block, 'bad-prevblk', 0, peer);

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
        if (!prev) {
          self.orphan.count++;
          self.orphan.size += block.getSize();
          self.orphan.map[prevHash] = block;
          self.orphan.bmap[hash] = block;
          self.emit('orphan', block, {
            height: -1,
            hash: hash,
            seen: false
          }, peer);
          if (self.options.headers)
            self.emit('verify-error', block, 'bad-prevblk', 0, peer);
          return done();
        }

        // Verify the checkpoint.
        checkpoint = network.checkpoints[height];
        if (checkpoint) {
          self.emit('checkpoint', block, {
            height: height,
            hash: hash,
            checkpoint: checkpoint
          }, peer);

          // Block did not match the checkpoint. The
          // chain could be reset to the last sane
          // checkpoint, but it really isn't necessary,
          // so we don't do it. The misbehaving peer has
          // been killed and hopefully we find a peer
          // who isn't trying to fool us.
          if (hash !== checkpoint) {
            self.purgeOrphans();
            self.purgePending();

            self.emit('fork', block, {
              height: height,
              expected: checkpoint,
              received: hash,
              checkpoint: true
            }, peer);

            self.emit('verify-error', block, 'checkpoint mismatch', 100, peer);

            return done();
          }
        }

        assert(prev);

        // Explanation: we try to keep as much data
        // off the javascript heap as possible. Blocks
        // in the future may be 8mb or 20mb, who knows.
        // In fullnode-mode we store the blocks in
        // "compact" form (the headers plus the raw
        // Buffer object) until they're ready to be
        // fully validated here. They are deserialized,
        // validated, and emitted. Hopefully the deserialized
        // blocks get cleaned up by the GC quickly.
        if (block.type === 'compactblock') {
          try {
            block = block.toBlock();
          } catch (e) {
            // Ugly hack to handle
            // the error properly.
            peer.parser.emit('error', e);
            return done(e);
          }
        }

        // Update the block height early
        // Some things in verifyContext may
        // need access to height on txs.
        block.height = height;
        block.txs.forEach(function(tx) {
          tx.height = height;
        });

        // Do "contextual" verification on our block
        // now that we're certain its previous
        // block is in the chain.
        self._verifyContext(block, prev, peer, function(err, verified) {
          var entry;

          // Couldn't verify block.
          // Revert the height.
          if (err || !verified) {
            block.height = -1;
            block.txs.forEach(function(tx) {
              tx.height = -1;
            });
          }

          if (err)
            return done(err);

          if (!verified) {
            self.invalid[hash] = true;
            self.emit('invalid', block, {
              height: height,
              hash: hash,
              seen: false,
              chain: false
            }, peer);
            return done();
          }

          // Create a new chain entry.
          entry = new bcoin.chainblock(self, {
            hash: hash,
            version: block.version,
            prevBlock: block.prevBlock,
            merkleRoot: block.merkleRoot,
            ts: block.ts,
            bits: block.bits,
            nonce: block.nonce,
            height: height
          }, prev);

          // Set main chain only if chainwork is higher.
          if (entry.chainwork.cmp(self.tip.chainwork) <= 0)
            return done();

          // Attempt to add block to the chain index.
          self._setBestChain(entry, block, function(err) {
            if (err)
              return done(err);

            // Keep track of the number of blocks we
            // added and the number of orphans resolved.
            total++;

            // Emit our block (and potentially resolved
            // orphan) so the programmer can save it.
            self.emit('block', block, entry, peer);
            if (block.hash('hex') !== initial.hash('hex'))
              self.emit('resolved', block, entry, peer);

            // No orphan chain.
            if (!self.orphan.map[hash])
              return done();

            // An orphan chain was found, start resolving.
            block = self.orphan.map[hash];
            delete self.orphan.bmap[block.hash('hex')];
            delete self.orphan.map[hash];
            self.orphan.count--;
            self.orphan.size -= block.getSize();

            next(block);
          });
        });
      });
    });
  })(initial);

  function done(err) {
    // Failsafe for large orphan chains. Do not
    // allow more than 20mb stored in memory.
    if (self.orphan.size > self.orphanLimit)
      self.pruneOrphans(peer);

    // Keep track of total blocks handled.
    self.total += total;

    // Take heap snapshot for debugging.
    if (self.total % 20 === 0)
      bcoin.profiler.snapshot();

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

  best = Object.keys(this.orphan.map).reduce(function(best, prevBlock) {
    var orphan = self.orphan.map[prevBlock];
    var height = orphan.getCoinbaseHeight();

    last = orphan;

    if (!best || height > best.getCoinbaseHeight())
      return orphan;

    return best;
  }, null);

  // Save the best for last... or the
  // last for the best in this case.
  if (!best || best.getCoinbaseHeight() <= 0)
    best = last;

  this.emit('purge',
    this.orphan.count - (best ? 1 : 0),
    this.orphan.size - (best ? best.getSize() : 0));

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
  this.orphan.size += best.getSize();
};

Chain.prototype.purgePending = function purgePending() {
  return this.locker.purgePending();
};

Chain.prototype.has = function has(hash, callback) {
  if (this.hasOrphan(hash))
    return callback(null, true);

  if (this.hasPending(hash))
    return callback(null, true);

  return this.hasBlock(hash, callback);
};

Chain.prototype.byTime = function byTime(ts, callback, force) {
  var self = this;
  var start = 0;
  var end = this.height;
  var pos, delta;

  var unlock = this._lock(byTime, [ts, callback], force);
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

    self.db.get(start, function(err, entry) {
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

    pos = (start + end) >>> 1;

    self.db.get(pos, function(err, entry) {
      if (err)
        return done(err);

      delta = Math.abs(ts - entry.ts);

      if (delta <= 60 * 60)
        return done(null, entry);

      if (ts < entry.ts)
        end = pos - 1;
      else
        start = pos + 1;

      next();
    });
  })();
};

Chain.prototype.hasBlock = function hasBlock(hash, callback) {
  if (typeof hash === 'number')
    return this.db.has(hash, callback);

  if (Buffer.isBuffer(hash))
    hash = utils.toHex(hash);
  else if (hash.hash)
    hash = hash.hash('hex');

  return this.db.has(hash, callback);
};

Chain.prototype.hasOrphan = function hasOrphan(hash) {
  return !!this.getOrphan(hash);
};

Chain.prototype.hasPending = function hasPending(hash) {
  if (Buffer.isBuffer(hash))
    hash = utils.toHex(hash);
  else if (hash.hash)
    hash = hash.hash('hex');

  return this.locker.hasPending(hash);
};

Chain.prototype.getEntry = function getEntry(hash, callback) {
  if (typeof hash === 'number')
    return this.db.get(hash, callback);

  if (Buffer.isBuffer(hash))
    hash = utils.toHex(hash);
  else if (hash.hash)
    hash = hash.hash('hex');

  return this.db.get(hash, callback);
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

  return delta < 4 * 60 * 60;
};

Chain.prototype.isInitial = function isInitial() {
  var now, delta;

  if (!this.tip)
    return true;

  now = utils.now();
  delta = now - this.lastUpdate;

  // Should mimic the original IsInitialBlockDownload() function
  return delta < 10 && this.tip.ts < now - 24 * 60 * 60;
};

Chain.prototype.getProgress = function getProgress() {
  if (!this.tip)
    return 0;
  return Math.min(1, this.tip.ts / (utils.now() - 40 * 60));
};

Chain.prototype.getHashRange = function getHashRange(start, end, callback, force) {
  var self = this;

  var unlock = this._lock(getHashRange, [start, end, callback], force);
  if (!unlock)
    return;

  function done(err, result) {
    unlock();
    callback(err, result);
  }

  this.byTime(start, function(err, start) {
    if (err)
      return done(err);

    self.byTime(end, function(err, end) {
      var hashes;

      if (err)
        return done(err);

      hashes = [];

      if (!start || !end)
        return done(null, hashes);

      utils.forRange(start.height, end.height + 1, function(i, next) {
        self.db.get(i, function(err, entry) {
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

Chain.prototype.getLocator = function getLocator(start, callback, force) {
  var self = this;
  var hashes = [];
  var top = this.height;
  var step = 1;
  var i;

  var unlock = this._lock(getLocator, [start, callback], force);
  if (!unlock)
    return;

  if (start) {
    if (Buffer.isBuffer(start))
      start = utils.toHex(start);
    else if (start.hash)
      start = start.hash('hex');
  }

  function getTop(callback) {
    if (typeof start === 'string') {
      return self.db.getHeight(start, function(err, top) {
        if (err)
          return callback(err);

        if (top === -1) {
          // We could simply `return [start]` here,
          // but there is no standardized "spacing"
          // for locator hashes. Pretend this hash
          // is our tip. This is useful for getheaders
          // when not using headers-first.
          hashes.push(start);
          top = self.height;
        }

        return callback(null, top);
      });
    } else if (typeof start === 'number') {
      top = start;
    }
    return callback(null, top);
  }

  return getTop(function(err, top) {
    if (err) {
      unlock();
      return callback(err);
    }

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

      self.db.get(height, function(err, existing) {
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
  });
};

Chain.prototype.getOrphanRoot = function getOrphanRoot(hash) {
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

Chain.prototype.getCurrentTarget = function getCurrentTarget(callback) {
  if (!this.tip)
    return callback(null, utils.toCompact(network.powLimit));
  return this.getTargetAsync(this.tip, null, callback);
};

Chain.prototype.getTargetAsync = function getTarget(last, block, callback) {
  var self = this;
  var powLimit = utils.toCompact(network.powLimit);
  var i = 0;
  var ts;

  callback = utils.asyncify(callback);

  // Genesis
  if (!last)
    return callback(null, powLimit);

  // Do not retarget
  if ((last.height + 1) % network.powDiffInterval !== 0) {
    if (network.powAllowMinDifficultyBlocks) {
      // Special behavior for testnet:
      ts = block ? (block.ts || block) : utils.now();
      if (ts > last.ts + network.powTargetSpacing * 2)
        return callback(null, powLimit);

      (function next(err, last) {
        if (err)
          return callback(err);

        assert(last);

        if (last.height > 0
          && last.height % network.powDiffInterval !== 0
          && last.bits === powLimit) {
          return last.getPrevious(next);
        }

        return callback(null, last.bits);
      })(null, last);

      return;
    }
    return callback(null, last.bits);
  }

  (function next(err, first) {
    if (err)
      return callback(err);

    i++;
    assert(first);

    if (i >= network.powDiffInterval)
      return callback(null, self.retarget(last, first));

    first.getPrevious(next);
  })(null, last);
};

Chain.prototype.getTarget = function getTarget(last, block) {
  var powLimit = utils.toCompact(network.powLimit);
  var ts, first, i, prev;

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

      i = 1;
      prev = last.ancestors;
      while (prev[i]
        && last.height % network.powDiffInterval !== 0
        && last.bits === powLimit) {
        last = prev[i++];
      }

      return last.bits;
    }
    return last.bits;
  }

  // Back 2 weeks
  first = last.ancestors[network.powDiffInterval - 1];

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

// https://github.com/bitcoin/bitcoin/pull/7648/files
Chain.prototype.getState = function getState(prev, block, id, callback) {
  var self = this;
  var period = network.minerConfirmationWindow;
  var threshold = network.ruleChangeActivationThreshold;
  var deployment = network.deployments[id];
  var timeStart, timeTimeout, compute, height;

  if (!deployment)
    return callback(null, constants.thresholdStates.FAILED);

  timeStart = deployment.startTime;
  timeTimeout = deployment.timeout;
  compute = [];

  if (block && block.isGenesis())
    return callback(null, constants.thresholdStates.DEFINED);

  if (((prev.height + 1) % period) !== 0) {
    height = prev.height - ((prev.height + 1) % period);
    return prev.getAncestorByHeight(height, function(err, ancestor) {
      if (err)
        return callback(err);
      if (!ancestor)
        return callback(null, constants.thresholdStates.DEFINED);
      return self.getState(ancestor, block, callback);
    });
  }

  function condition(entry) {
    var bits = entry.version & constants.versionbits.TOP_MASK;
    var topBits = constants.versionbits.TOP_BITS;
    var mask = 1 << deployment.bit;
    return bits === topBits && (entry.version & mask) !== 0;
  }

  (function walk(err, entry) {
    if (err)
      return callback(err);

    if (!entry)
      return walkForward(constants.thresholdStates.DEFINED);

    return entry.getMedianTimeAsync(function(err, medianTime) {
      if (err)
        return walk(err);

      if (medianTime < timeStart)
        return walkForward(constants.thresholdStates.DEFINED);

      compute.push(entry);

      height = entry.height - period;

      return entry.getAncestorByHeight(height, walk);
    });
  })(null, prev);

  function walkForward(state) {
    var entry;

    if (compute.length === 0)
      return callback(null, state);

    entry = compute.pop();

    switch (state) {
      case constants.thresholdStates.DEFINED:
        return entry.getMedianTimeAsync(function(err, medianTime) {
          if (err)
            return callback(err);

          if (medianTime >= timeTimeout)
            return walkForward(constants.thresholdStates.FAILED);

          if (medianTime >= timeStart)
            return walkForward(constants.thresholdStates.STARTED);

          return walkForward(state);
        });
      case constants.thresholdStates.STARTED:
        return entry.getMedianTimeAsync(function(err, medianTime) {
          if (err)
            return callback(err);

          if (medianTime >= timeTimeout)
            return walkForward(constants.thresholdStates.FAILED);

          var count = 0;
          var i = 0;

          (function next(err, entry) {
            if (err)
              return callback(err);

            if (!entry)
              return doneCounting();

            if (i++ >= period)
              return doneCounting();

            if (condition(entry))
              count++;

            return entry.getPrevious(next);
          })(null, entry);

          function doneCounting(err) {
            if (err)
              return callback(err);

            if (count >= threshold)
              return walkForward(constants.thresholdStates.LOCKED_IN);

            return walkForward(state);
          }
        });
      case constants.thresholdStates.LOCKED_IN:
        return walkForward(constants.thresholdStates.ACTIVE);
      case constants.thresholdStates.FAILED:
      case constants.thresholdStates.ACTIVE:
        return walkForward(state);
    }

    assert(false, 'Bad state.');
  }
};

Chain.prototype.computeBlockVersion = function computeBlockVersion(prev, callback) {
  var self = this;
  var version = 0;

  utils.forEachSerial(Object.keys(network.deployments), function(id, next) {
    var deployment = network.deployments[id];
    self.getState(prev, null, id, function(err, state) {
      if (err)
        return next(err);

      if (state === constants.thresholdStates.LOCKED_IN
          || state === constants.thresholdStates.STARTED) {
        version |= (1 << deployment.bit);
      }

      next();
    });
  }, function(err) {
    if (err)
      return callback(err);

    if (version === 0)
      return callback(null, constants.versionbits.LAST_OLD_BLOCK_VERSION);

    version |= constants.versionbits.TOP_BITS;

    return callback(null, version);
  });
};

/**
 * Expose
 */

module.exports = Chain;
