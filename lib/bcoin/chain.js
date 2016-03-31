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
var VerifyError = utils.VerifyError;

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
  this.segwitActive = null;

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

  function getHost() {
    var peer;

    if (!self.node || !self.node.pool)
      return;

    peer = self.node.pool.peers.load;

    if (!peer)
      return 'unknown';

    return peer.host;
  }

  // Hook into events for debugging
  this.on('block', function(block, entry) {
    if (self.height < 400000)
      return;

    utils.debug('Block %s (%d) added to chain (%s)',
      utils.revHex(entry.hash), entry.height, getHost());
  });

  this.on('competitor', function(block, entry) {
    utils.debug('Heads up: Competing chain at height %d:'
      + ' tip-height=%d competitor-height=%d'
      + ' tip-hash=%s competitor-hash=%s'
      + ' tip-chainwork=%s competitor-chainwork=%s'
      + ' chainwork-diff=%s (%s)',
      entry.height,
      utils.revHex(self.tip.hash),
      utils.revHex(entry.hash),
      self.tip.height,
      entry.height,
      self.tip.chainwork.toString(),
      entry.chainwork.toString(),
      self.tip.chainwork.sub(entry.chainwork).toString(),
      getHost());
  });

  this.on('resolved', function(block, entry) {
    utils.debug('Orphan %s (%d) was resolved (%s)',
      utils.revHex(entry.hash), entry.height, getHost());
  });

  this.on('checkpoint', function(block, data) {
    utils.debug('Hit checkpoint block %s (%d) (%s)',
      utils.revHex(data.checkpoint), data.height, getHost());
  });

  this.on('fork', function(block, data) {
    utils.debug(
      'Fork at height %d: expected=%s received=%s checkpoint=%s',
      data.height,
      utils.revHex(data.expected),
      utils.revHex(data.received),
      data.checkpoint,
      getHost()
    );
    if (data.checkpoint)
      utils.debug('WARNING: Block failed a checkpoint.');
  });

  this.on('invalid', function(block, data) {
    utils.debug(
      'Invalid block at height %d: hash=%s',
      data.height,
      utils.revHex(data.hash),
      getHost()
    );
    if (data.chain) {
      utils.debug(
        'Peer is sending an invalid continuation chain (%s)',
        getHost());
    } else if (data.seen) {
      utils.debug('Peer is sending an invalid chain (%s)', getHost());
    }
  });

  this.on('exists', function(block, data) {
    utils.debug('Already have block %s (%s)',
      data.height, getHost());
  });

  this.on('orphan', function(block, data) {
    utils.debug('Handled orphan %s (%s)', utils.revHex(data.hash), getHost());
  });

  this.on('purge', function(count, size) {
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

        if (self.bestHeight === -1)
          network.height = tip.height;

        self.isSegwitActive(function(err, result) {
          if (err)
            return self.emit('error', err);

          if (result)
            utils.debug('Segwit is active.');

          self.loaded = true;
          self.emit('open');
          self.emit('tip', tip);

          if (self.isFull())
            self.emit('full');
        });
      });
    });
  });
};

Chain.prototype.open = function open(callback) {
  if (this.loaded)
    return utils.nextTick(callback);

  this.once('open', callback);
};

Chain.prototype.close =
Chain.prototype.destroy = function destroy(callback) {
  this.db.close(utils.ensure(callback));
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
      version: p.readU32(), // Technically signed
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

        if (entry.height <= chainHeight)
          self.db.addCache(entry);
        else
          self.db.save(entry, null, true);

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

Chain.prototype._verifyContext = function _verifyContext(block, prev, callback) {
  var self = this;

  this._verify(block, prev, function(err, flags) {
    if (err)
      return callback(err);

    self._checkDuplicates(block, prev, function(err, result) {
      if (err)
        return callback(err);

      self._checkInputs(block, prev, flags, function(err) {
        if (err)
          return callback(err);

        return callback();
      });
    });
  });
};

Chain.prototype._verify = function _verify(block, prev, callback) {
  var self = this;
  var flags = constants.flags.MANDATORY_VERIFY_FLAGS;
  var lockFlags = constants.flags.MANDATORY_LOCKTIME_FLAGS;
  var height, ts, i, tx, coinbaseHeight;
  var medianTime, segwit;
  var ret = {};

  function done(err, result) {
    prev.free();
    callback(err, result);
  }

  if (!block.verify(ret))
    return done(new VerifyError(block, 'invalid', ret.reason, ret.score));

  // Skip the genesis block
  if (block.isGenesis())
    return done(null, flags);

  // Ensure it's not an orphan
  if (!prev)
    return done(new VerifyError(block, 'invalid', 'bad-prevblk', 0));

  prev.ensureAncestors(function(err) {
    if (err)
      return done(err);

    height = prev.height + 1;
    medianTime = prev.getMedianTime();

    // Ensure the timestamp is correct
    if (block.ts <= medianTime)
      return done(new VerifyError(block, 'invalid', 'time-too-old', 0));

    if (block.bits !== self.getTarget(prev, block))
      return done(new VerifyError(block, 'invalid', 'bad-diffbits', 100));

    // For some reason bitcoind has p2sh in the
    // mandatory flags by default, when in reality
    // it wasn't activated until march 30th 2012.
    // The first p2sh output and redeem script
    // appeared on march 7th 2012, only it did
    // not have a signature. See:
    // 6a26d2ecb67f27d1fa5524763b49029d7106e91e3cc05743073461a719776192
    // 9c08a4d78931342b37fd5f72900fb9983087e6f46c4a097d8a1f52c74e28eaf6
    if (block.ts < constants.block.bip16time)
      flags &= ~constants.flags.VERIFY_P2SH;

    // Only allow version 2 blocks (coinbase height)
    // once the majority of blocks are using it.
    if (block.version < 2 && prev.isOutdated(2))
      return done(new VerifyError(block, 'obsolete', 'bad-version', 0));

    // Only allow version 3 blocks (sig validation)
    // once the majority of blocks are using it.
    if (block.version < 3 && prev.isOutdated(3))
      return done(new VerifyError(block, 'obsolete', 'bad-version', 0));

    // Only allow version 4 blocks (checklocktimeverify)
    // once the majority of blocks are using it.
    if (block.version < 4 && prev.isOutdated(4))
      return done(new VerifyError(block, 'obsolete', 'bad-version', 0));

    // Only allow version 5 blocks (segwit)
    // once the majority of blocks are using it.
    if (network.segwitHeight !== -1 && height >= network.segwitHeight) {
      if (block.version < 5 && prev.isOutdated(5))
        return done(new VerifyError(block, 'obsolete', 'bad-version', 0));
    }

    // Only allow version 8 blocks (locktime median past)
    // once the majority of blocks are using it.
    // if (block.version < 8 && prev.isOutdated(8))
    //   return done(new VerifyError(block, 'obsolete', 'bad-version', 0));

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

    // Segregrated witness is now usable
    if (network.segwitHeight !== -1 && height >= network.segwitHeight) {
      if (block.version >= 5 && prev.isUpgraded(5)) {
        flags |= constants.flags.VERIFY_WITNESS;
        segwit = true;
        self.segwitActive = true;
      } else if (block.version >= 5) {
        self.segwitActive = false;
      }
    }

    // Locktime median time past is now enforced.
    // if (block.version >= 8 && prev.isUpgraded(8))
    //   lockFlags |= constants.flags.MEDIAN_TIME_PAST;

    if (network.type === 'segnet4') {
      self.getState(prev, 'witness', function(err, state) {
        if (err)
          return callback(err);

        if (state === constants.thresholdStates.ACTIVE) {
          flags |= constants.flags.VERIFY_WITNESS;
          segwit = true;
          self.segwitActive = true;
        } else {
          self.segwitActive = false;
        }

        return finish();
      });
    } else {
      finish();
    }

    function finish() {
      // Can't verify any further when merkleblock or headers.
      if (block.type !== 'block')
        return done(null, flags);

      // Make sure the height contained in the coinbase is correct.
      if (coinbaseHeight) {
        if (block.getCoinbaseHeight() !== height)
          return done(new VerifyError(block, 'invalid', 'bad-cb-height', 100));
      }

      if (block.version >= 5 && segwit) {
        if (block.commitmentHash !== block.getCommitmentHash()) {
          return done(new VerifyError(block,
            'invalid',
            'bad-blk-wit-length',
            100));
        }
      } else {
        if (block.hasWitness()) {
          return done(new VerifyError(block,
            'invalid',
            'unexpected-witness',
            100));
        }
      }

      // Get timestamp for tx.isFinal().
      ts = (lockFlags & constants.flags.MEDIAN_TIME_PAST)
        ? medianTime
        : block.ts;

      // Check all transactions
      for (i = 0; i < block.txs.length; i++) {
        tx = block.txs[i];

        // Transactions must be finalized with
        // regards to nSequence and nLockTime.
        if (!tx.isFinal(height, ts)) {
          return done(new VerifyError(block,
            'invalid',
            'bad-txns-nonfinal',
            10));
        }
      }

      return done(null, flags);
    }
  });
};

Chain.prototype._checkDuplicates = function _checkDuplicates(block, prev, callback) {
  var self = this;
  var height = prev.height + 1;

  if (this.options.spv || block.type !== 'block')
    return callback();

  if (block.isGenesis())
    return callback();

  // Check all transactions
  utils.forEachSerial(block.txs, function(tx, next) {
    var hash = tx.hash('hex');

    // BIP30 - Ensure there are no duplicate txids
    self.db.isUnspentTX(hash, function(err, result) {
      if (err)
        return next(err);

      if (result) {
        // Blocks 91842 and 91880 created duplicate
        // txids by using the same exact output script
        // and extraNonce.
        if (network.type === 'main') {
          if (height === 91842 || height === 91880)
            return next();
        }
        return next(new VerifyError(block, 'invalid', 'bad-txns-BIP30', 100));
      }

      next();
    });
  }, callback);
};

Chain.prototype._checkInputs = function _checkInputs(block, prev, flags, callback) {
  var self = this;
  var height = prev.height + 1;
  var scriptCheck = true;
  var historical = false;

  if (this.options.spv || block.type !== 'block')
    return callback();

  if (block.isGenesis())
    return callback();

  // If we are an ancestor of a checkpoint, we can
  // skip the input verification.
  if (height <= network.checkpoints.lastHeight) {
    if (this.options.useCheckpoints)
      scriptCheck = false;
    historical = true;
  }

  this.db.fillBlock(block, function(err) {
    var ret = {};
    var sigops = 0;
    var i, j, input, tx, hash;

    if (err)
      return callback(err);

    if (!self._checkReward(block))
      return callback(new VerifyError(block, 'invalid', 'bad-cb-amount', 100));

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

      if (sigops > constants.block.maxSigops) {
        return callback(new VerifyError(block,
          'invalid',
          'bad-blk-sigops',
          100));
      }

      // Coinbases do not have prevouts
      if (tx.isCoinbase())
        continue;

      if (!tx.checkInputs(height, ret)) {
        return callback(new VerifyError(block,
          'invalid',
          ret.reason,
          ret.score));
      }

      for (j = 0; j < tx.inputs.length; j++) {
        input = tx.inputs[j];

        // Ensure tx is not double spending an output
        if (!input.coin) {
          assert(!historical, 'BUG: Spent inputs in historical data!');
          return callback(new VerifyError(block,
            'invalid',
            'bad-txns-inputs-missingorspent',
            100));
        }

        if (self.options.verifySync !== true)
          continue;

        if (!scriptCheck)
          continue;

        // Verify the scripts
        if (!tx.verify(j, true, flags)) {
          assert(!historical, 'BUG: Invalid inputs in historical data!');
          return callback(new VerifyError(block,
            'invalid',
            'mandatory-script-verify-flag-failed',
            100));
        }
      }
    }

    if (self.options.verifySync === true)
      return callback();

    if (!scriptCheck)
      return callback();

    // Verify all txs in parallel.
    utils.every(block.txs, function(tx, next) {
      tx.verifyAsync(null, true, flags, next);
    }, function(err, verified) {
      if (err)
        return callback(err);

      if (!verified) {
        assert(!historical, 'BUG: Invalid inputs in historical data!');
        return callback(new VerifyError(block,
          'invalid',
          'mandatory-script-verify-flag-failed',
          100));
      }

      return callback();
    });
  });
};

Chain.prototype._checkReward = function _checkReward(block) {
  var i, claimed, actual;

  claimed = block.txs[0].getOutputValue();
  actual = bcoin.block.reward(block.height);

  for (i = 1; i < block.txs.length; i++)
    actual.iadd(block.txs[i].getFee());

  return claimed.cmp(actual) <= 0;
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

  function done(err) {
    if (err)
      return callback(err);

    // Save block and connect inputs.
    self.db.save(entry, block, true, function(err) {
      if (err)
        return callback(err);

      self.tip = entry;
      self.height = entry.height;

      if (self.bestHeight === -1)
        network.height = entry.height;

      self.emit('tip', entry);

      // Return true (added to the main chain)
      return callback(null, true);
    });
  }

  // Update the timestamp to
  // maintain a time delta of blocks.
  this.lastUpdate = utils.now();

  // We don't have a genesis block yet.
  if (!this.tip) {
    if (entry.hash !== network.genesis.hash)
      return utils.asyncify(callback)(new Error('Bad genesis block.'));

    return done();
  }

  // The block is on a side chain if the
  // chainwork is less than or equal to
  // our tip's. Add the block but do _not_
  // connect the inputs.
  if (entry.chainwork.cmp(this.tip.chainwork) <= 0) {
    return this.db.save(entry, block, false, function(err) {
      if (err)
        return callback(err);

      // Return false (added to side chain)
      return callback(null, false);
    });
  }

  // Everything is in order.
  if (entry.prevBlock === this.tip.hash)
    return done();

  // A higher fork has arrived.
  // Time to reorganize the chain.
  utils.debug('WARNING: Reorganizing chain.');
  return this._reorganize(entry, block, done);
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

Chain.prototype.add = function add(block, callback, force) {
  var self = this;
  var total = 0;
  var ret = {};

  assert(this.loaded);

  var unlock = this._lock(add, [block, callback], force);
  if (!unlock)
    return;

  (function next(block, initial) {
    var hash = block.hash('hex');
    var prevHash = block.prevBlock;
    var height, checkpoint, orphan;

    // Do not revalidate known invalid blocks.
    if (self.invalid[hash] || self.invalid[prevHash]) {
      self.emit('invalid', block, {
        height: block.getCoinbaseHeight(),
        hash: hash,
        seen: !!self.invalid[hash],
        chain: !!self.invalid[prevHash]
      });
      self.invalid[hash] = true;
      return done(new VerifyError(block, 'duplicate', 'duplicate', 100));
    }

    // Do we already have this block?
    if (self.hasPending(hash)) {
      self.emit('exists', block, {
        height: block.getCoinbaseHeight(),
        hash: hash
      });
      return done(new VerifyError(block, 'duplicate', 'duplicate', 0));
    }

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
          height: block.getCoinbaseHeight(),
          expected: orphan.hash('hex'),
          received: hash,
          checkpoint: false
        });

        return done(new VerifyError(block, 'duplicate', 'duplicate', 0));
      }

      self.emit('orphan', block, {
        height: block.getCoinbaseHeight(),
        hash: hash,
        seen: true
      });

      return done(new VerifyError(block, 'invalid', 'bad-prevblk', 0));
    }

    // Special case for genesis block.
    if (block.isGenesis())
      return done();

    // Validate the block we want to add.
    // This is only necessary for new
    // blocks coming in, not the resolving
    // orphans.
    if (initial && !block.verify(ret)) {
      self.invalid[hash] = true;
      self.emit('invalid', block, {
        height: block.getCoinbaseHeight(),
        hash: hash,
        seen: false,
        chain: false
      });
      return done(new VerifyError(block, 'invalid', ret.reason, ret.score));
    }

    self.db.has(hash, function(err, existing) {
      if (err)
        return done(err);

      // Do we already have this block?
      if (existing) {
        self.emit('exists', block, {
          height: block.getCoinbaseHeight(),
          hash: hash
        });
        return done(new VerifyError(block, 'duplicate', 'duplicate', 0));
      }

      // Find the previous block height/index.
      self.db.get(prevHash, function(err, prev) {
        if (err)
          return done(err);

        height = !prev ? -1 : prev.height + 1;

        // Update the best height based on the coinbase.
        // We do this even for orphans (peers will send
        // us their highest block during the initial
        // getblocks sync, making it an orphan).
        if (block.getCoinbaseHeight() > self.bestHeight) {
          self.bestHeight = block.getCoinbaseHeight();
          network.height = self.bestHeight;
        }

        // If previous block wasn't ever seen,
        // add it current to orphans and break.
        if (!prev) {
          self.orphan.count++;
          self.orphan.size += block.getSize();
          self.orphan.map[prevHash] = block;
          self.orphan.bmap[hash] = block;
          self.emit('orphan', block, {
            height: block.getCoinbaseHeight(),
            hash: hash,
            seen: false
          });
          return done(new VerifyError(block, 'invalid', 'bad-prevblk', 0));
        }

        // Verify the checkpoint.
        checkpoint = network.checkpoints[height];
        if (checkpoint) {
          self.emit('checkpoint', block, {
            height: height,
            hash: hash,
            checkpoint: checkpoint
          });

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
            });

            return done(new VerifyError(block,
              'checkpoint',
              'checkpoint mismatch',
              100));
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
            return done(new VerifyError(block,
              'malformed',
              'error parsing message',
              100));
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
        self._verifyContext(block, prev, function(err) {
          var entry;

          if (err) {
            // Couldn't verify block.
            // Revert the height.
            block.height = -1;
            block.txs.forEach(function(tx) {
              tx.height = -1;
            });

            if (err.type === 'VerifyError') {
              self.invalid[hash] = true;
              self.emit('invalid', block, {
                height: height,
                hash: hash,
                seen: false,
                chain: false
              });
            }

            return done(err);
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

          // Attempt to add block to the chain index.
          self._setBestChain(entry, block, function(err, mainChain) {
            if (err)
              return done(err);

            // Keep track of the number of blocks we
            // added and the number of orphans resolved.
            total++;

            // Emit our block (and potentially resolved
            // orphan) only if it is on the main chain.
            if (mainChain)
              self.emit('block', block, entry);
            else
              self.emit('competitor', block, entry);

            if (!initial)
              self.emit('resolved', block, entry);

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
  })(block, true);

  function done(err) {
    // Failsafe for large orphan chains. Do not
    // allow more than 20mb stored in memory.
    if (self.orphan.size > self.orphanLimit)
      self.pruneOrphans();

    // Keep track of total blocks handled.
    self.total += total;

    // Take heap snapshot for debugging.
    if (self.total % 20 === 0) {
      bcoin.profiler.snapshot();
      utils.gc();
    }

    utils.nextTick(function() {
      if (self.isFull())
        self.emit('full');

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

Chain.prototype.pruneOrphans = function pruneOrphans() {
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
      self.emit('unresolved', orphan);
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

      self.db.getHash(height, function(err, hash) {
        if (err)
          return next(err);

        assert(hash);

        hashes[i] = hash;

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
Chain.prototype.getState = function getState(prev, id, callback) {
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

  if (!prev)
    return callback(null, constants.thresholdStates.DEFINED);

  if (((prev.height + 1) % period) !== 0) {
    height = prev.height - ((prev.height + 1) % period);
    return prev.getAncestorByHeight(height, function(err, ancestor) {
      if (err)
        return callback(err);
      if (ancestor) {
        assert(ancestor.height === height);
        assert(((ancestor.height + 1) % period) === 0);
      }
      return self.getState(ancestor, id, callback);
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
    self.getState(prev, id, function(err, state) {
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
    version >>>= 0;

    return callback(null, version);
  });
};

Chain.prototype.isSegwitActive = function isSegwitActive(callback) {
  var self = this;
  var unlock;

  if (this.segwitActive != null)
    return utils.asyncify(callback)(null, this.segwitActive);

  if (!network.witness) {
    this.segwitActive = false;
    return utils.asyncify(callback)(null, false);
  }

  if (!this.tip)
    return utils.asyncify(callback)(null, false);

  unlock = this._lock(isSegwitActive, [callback]);
  if (!unlock)
    return;

  callback = utils.wrap(callback, unlock);

  if (network.type === 'segnet4') {
    return this.tip.getPrevious(function(err, prev) {
      if (err)
        return callback(err);

      return self.getState(prev, 'witness', function(err, state) {
        if (err)
          return callback(err);
        self.segwitActive = state === constants.thresholdStates.ACTIVE;
        return callback(null, self.segwitActive);
      });
    });
  }

  assert(network.type === 'segnet3');

  if (!(network.segwitHeight !== -1 && this.tip.height >= network.segwitHeight))
    return utils.asyncify(callback)(null, false);

  return this.tip.getPrevious(function(err, prev) {
    if (err)
      return callback(err);

    if (!prev) {
      self.segwitActive = false;
      return callback(null, false);
    }

    prev.ensureAncestors(function(err) {
      if (err)
        return callback(err);

      if (!prev.isUpgraded(5)) {
        prev.free();
        self.segwitActive = false;
        return callback(null, false);
      }

      prev.free();
      self.segwitActive = true;
      return callback(null, true);
    });
  });
};

Chain.prototype.checkFinal = function checkFinal(prev, tx, flags, callback) {
  var height = prev.height + 1;

  function check(err, ts) {
    if (err)
      return callback(err);

    return callback(null, tx.isFinal(ts, height));
  }

  if (flags & constants.flags.MEDIAN_TIME_PAST)
    return prev.getMedianTimeAsync(check);

  utils.asyncify(check)(null, utils.now());
};

Chain.prototype.getLocks = function getLocks(tx, flags, entry, callback) {
  var self = this;
  var mask = constants.sequenceLocktimeMask;
  var granularity = constants.sequenceLocktimeGranularity;
  var disableFlag = constants.sequenceLocktimeDisableFlag;
  var typeFlag = constants.sequenceLocktimeTypeFlag;
  var hasFlag = flags & constants.flags.VERIFY_SEQUENCE;
  var minHeight = -1;
  var minTime = -1;
  var coinHeight;

  if (tx.version < 2 || !hasFlag)
    return utils.asyncify(callback)(null, minHeight, minTime);

  utils.forEachSerial(tx.inputs, function(input, next) {
    if (input.sequence & disableFlag)
      return next();

    coinHeight = input.coin.height === -1
      ? self.chain.tip + 1
      : input.coin.height;

    if ((input.sequence & typeFlag) === 0) {
      coinHeight += (input.sequence & mask) - 1;
      minHeight = Math.max(minHeight, coinHeight);
      return next();
    }

    entry.getAncestorByHeight(Math.max(coinHeight - 1, 0), function(err, entry) {
      if (err)
        return next(err);

      assert(entry, 'Database is corrupt.');

      entry.getMedianTimeAsync(function(err, coinTime) {
        if (err)
          return next(err);

        coinTime += ((input.sequence & mask) << granularity) - 1;
        minTime = Math.max(minTime, coinTime);

        next();
      });
    });
  }, function(err) {
    if (err)
      return callback(err);
    return callback(null, minHeight, minTime);
  });
};

Chain.prototype.evalLocks = function evalLocks(entry, minHeight, minTime, callback) {
  if (minHeight >= entry.height)
    return utils.asyncify(callback)(null, false);

  if (minTime === -1)
    return utils.asyncify(callback)(null, true);

  entry.getMedianTimeAsync(function(err, medianTime) {
    if (err)
      return callback(err);

    if (minTime >= medianTime)
      return callback(null, false);

    return callback(null, true);
  });
};

Chain.prototype.checkLocks = function checkLocks(tx, flags, entry, callback) {
  var self = this;
  this.getLocks(tx, flags, entry, function(err, minHeight, minTime) {
    if (err)
      return callback(err);

    self.evalLocks(entry, minHeight, minTime, callback);
  });
};

/**
 * Expose
 */

module.exports = Chain;
