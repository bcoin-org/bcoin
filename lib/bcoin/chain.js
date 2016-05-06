/*!
 * chain.js - blockchain management for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/indutny/bcoin
 */

module.exports = function(bcoin) {

var EventEmitter = require('events').EventEmitter;
var bn = require('bn.js');
var constants = bcoin.protocol.constants;
var network = bcoin.protocol.network;
var utils = require('./utils');
var assert = utils.assert;
var VerifyError = bcoin.errors.VerifyError;

/**
 * Represents a blockchain.
 * @exports Chain
 * @constructor
 * @param {Object} options
 * @param {String?} options.name - Database name.
 * @param {String?} options.location - Database file location.
 * @param {String?} options.db - Database backend (`"leveldb"` by default).
 * @param {Number?} options.orphanLimit
 * @param {Number?} options.pendingLimit
 * @param {Boolean?} options.spv
 * @property {Boolean} loaded
 * @property {ChainDB} db - Note that Chain `options` will be passed
 * to the instantiated ChainDB.
 * @property {Number} total
 * @property {Number} orphanLimit
 * @property {Locker} locker
 * @property {Object} invalid
 * @property {Number} bestHeight
 * @property {ChainBlock?} tip
 * @property {Number} height
 * @property {Boolean} segwitActive
 * @property {Boolean} csvActive
 * @property {Object} orphan - Orphan map.
 * @emits Chain#open
 * @emits Chain#error
 * @emits Chain#block
 * @emits Chain#competitor
 * @emits Chain#resolved
 * @emits Chain#checkpoint
 * @emits Chain#fork
 * @emits Chain#invalid
 * @emits Chain#exists
 * @emits Chain#purge
 * @emits Chain#add entry
 * @emits Chain#remove entry
 * @emits Chain#add block
 * @emits Chain#remove block
 */

function Chain(options) {
  if (!(this instanceof Chain))
    return new Chain(options);

  EventEmitter.call(this);

  if (!options)
    options = {};

  this.options = options;

  this.loaded = false;
  this.db = new bcoin.chaindb(this, options);
  this.total = 0;
  this.adding = false;
  this.orphanLimit = options.orphanLimit || (20 << 20);
  this.pendingLimit = options.pendingLimit || (1024 << 20);
  this.locker = new bcoin.locker(this, this.add, this.pendingLimit);
  this.invalid = {};
  this.bestHeight = -1;
  this.tip = null;
  this.height = -1;
  this.synced = false;
  this.segwitActive = null;
  this.csvActive = null;
  this.stateCache = {};

  this.orphan = {
    map: {},
    bmap: {},
    count: 0,
    size: 0
  };

  this._init();
}

utils.inherits(Chain, EventEmitter);

Chain.prototype._init = function _init() {
  var self = this;

  this.locker.on('purge', function(total, size) {
    bcoin.debug('Warning: %dmb of pending objects. Purging.', utils.mb(size));
  });

  // Hook into events for debugging
  this.on('block', function(block, entry) {
    if (self.height < network.block.slowHeight)
      return;

    bcoin.debug('Block %s (%d) added to chain',
      utils.revHex(entry.hash), entry.height);
  });

  this.on('competitor', function(block, entry) {
    bcoin.debug('Heads up: Competing chain at height %d:'
      + ' tip-height=%d competitor-height=%d'
      + ' tip-hash=%s competitor-hash=%s'
      + ' tip-chainwork=%s competitor-chainwork=%s'
      + ' chainwork-diff=%s',
      entry.height,
      self.tip.height,
      entry.height,
      utils.revHex(self.tip.hash),
      utils.revHex(entry.hash),
      self.tip.chainwork.toString(),
      entry.chainwork.toString(),
      self.tip.chainwork.sub(entry.chainwork).toString());
  });

  this.on('resolved', function(block, entry) {
    bcoin.debug('Orphan %s (%d) was resolved.',
      utils.revHex(entry.hash), entry.height);
  });

  this.on('checkpoint', function(block, data) {
    bcoin.debug('Hit checkpoint block %s (%d).',
      utils.revHex(data.checkpoint), data.height);
  });

  this.on('fork', function(block, data) {
    bcoin.debug(
      'Fork at height %d: expected=%s received=%s checkpoint=%s',
      data.height,
      utils.revHex(data.expected),
      utils.revHex(data.received),
      data.checkpoint
    );
    if (data.checkpoint)
      bcoin.debug('WARNING: Block failed a checkpoint.');
  });

  this.on('invalid', function(block, data) {
    bcoin.debug(
      'Invalid block at height %d: hash=%s',
      data.height,
      utils.revHex(data.hash)
    );
    if (data.chain) {
      bcoin.debug(
        'Peer is sending an invalid continuation chain.');
    } else if (data.seen) {
      bcoin.debug('Peer is sending an invalid chain.');
    }
  });

  this.on('exists', function(block, data) {
    bcoin.debug('Already have block %s (%d).',
      utils.revHex(data.hash), data.height);
  });

  this.on('orphan', function(block, data) {
    bcoin.debug('Handled orphan %s.', utils.revHex(data.hash));
  });

  this.on('purge', function(count, size) {
    bcoin.debug('Warning: %d (%dmb) orphans cleared!', count, utils.mb(size));
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

  bcoin.debug('Chain is loading.');

  self.db.open(function(err) {
    if (err)
      return self.emit('error', err);

    self._preload(function(err) {
      if (err)
        return self.emit('error', err);

      self.db.getTip(function(err, tip) {
        if (err)
          return self.emit('error', err);

        assert(tip);

        self.tip = tip;
        self.height = tip.height;

        if (tip.height > self.bestHeight) {
          self.bestHeight = tip.height;
          network.height = tip.height;
        }

        self._getInitialState(function(err) {
          if (err)
            return self.emit('error', err);

          if (self.csvActive)
            bcoin.debug('CSV is active.');

          if (self.segwitActive)
            bcoin.debug('Segwit is active.');

          self.loaded = true;
          self.emit('open');
          self.emit('tip', tip);

          if (!self.synced && self.isFull()) {
            self.synced = true;
            self.emit('full');
          }
        });
      });
    });
  });
};

/**
 * Open the chain, wait for the database to load.
 * @param {Function} callback
 */

Chain.prototype.open = function open(callback) {
  if (this.loaded)
    return utils.nextTick(callback);

  this.once('open', callback);
};

/**
 * Close the chain, wait for the database to close.
 * @method
 * @param {Function} callback
 */

Chain.prototype.close =
Chain.prototype.destroy = function destroy(callback) {
  this.db.close(utils.ensure(callback));
};

Chain.prototype._lock = function _lock(func, args, force) {
  return this.locker.lock(func, args, force);
};

/**
 * Stream headers from electrum.org for quickly
 * preloading the chain. Electrum.org stores
 * headers in the standard block header format,
 * but they do not store chainwork, so we have
 * to calculate it ourselves.
 * @private
 * @param {Function} callback
 */

Chain.prototype._preload = function _preload(callback) {
  var self = this;
  var url = 'https://headers.electrum.org/blockchain_headers';
  var buf, height, stream;
  var request = require('./http/request');
  var locker = new bcoin.locker();

  if (!this.options.preload)
    return callback();

  if (!this.options.spv)
    return callback();

  if (network.type !== 'main')
    return callback();

  bcoin.debug('Loading %s', url);

  function parseHeader(buf) {
    var headers = bcoin.protocol.parser.parseBlockHeaders(buf);
    headers.hash = utils.dsha256(buf.slice(0, 80)).toString('hex');
    return headers;
  }

  function save(entry) {
    var unlock = locker.lock(save, [entry]);
    if (!unlock)
      return;

    self.db.save(entry, null, true, function(err) {
      if (err) {
        stream.destroy();
        locker.destroy();
        return callback(err);
      }

      if (locker.jobs.length === 0 && save.ended)
        return callback();

      unlock();
    });
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
      stream.destroy();
      return callback(err);
    });

    stream.on('data', function(data) {
      var blocks = [];
      var need = 80 - buf.size;
      var lastEntry, block, data, entry;

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

      for (i = 0; i < blocks.length; i++) {
        data = blocks[i];

        try {
          data = parseHeader(data);
        } catch (e) {
          stream.destroy();
          return callback(e);
        }

        data.height = height;

        // Make sure the genesis block is correct.
        if (data.height === 0 && data.hash !== network.genesis.hash) {
          stream.destroy();
          return callback(new Error('Bad genesis block.'));
        }

        // Do some paranoid checks.
        if (lastEntry && data.prevBlock !== lastEntry.hash) {
          stream.destroy();
          return callback(new Error('Corrupt headers.'));
        }

        // Create headers object for validation.
        block = new bcoin.headers(data);

        // Verify the block headers. We don't want to
        // trust an external centralized source completely.
        if (!block.verifyHeaders()) {
          stream.destroy();
          return callback(new Error('Bad headers.'));
        }

        // Create a chain entry.
        entry = new bcoin.chainblock(self, data, lastEntry);

        if (entry.height <= chainHeight)
          self.db.addCache(entry);
        else
          save(entry);

        if ((height + 1) % 50000 === 0)
          bcoin.debug('Received %d headers from electrum.org.', height + 1);

        lastEntry = entry;
        height++;
      }
    });

    stream.on('end', function() {
      save.ended = true;
      if (!locker.busy && locker.jobs.length === 0)
        return callback();
    });
  });
};

/**
 * Perform all necessary contextual verification on a block.
 * @private
 * @param {Block|MerkleBlock} block
 * @param {ChainBlock} entry
 * @param {Function} callback - Returns [{@link VerifyError}].
 */

Chain.prototype._verifyContext = function _verifyContext(block, prev, callback) {
  var self = this;

  this._verify(block, prev, function(err, state) {
    if (err)
      return callback(err);

    self._checkDuplicates(block, prev, function(err, result) {
      if (err)
        return callback(err);

      self._checkInputs(block, prev, state, function(err) {
        if (err)
          return callback(err);

        return callback();
      });
    });
  });
};

/**
 * Contextual verification for a block, including
 * version deployments (IsSuperMajority), versionbits,
 * coinbase height, finality checks.
 * @private
 * @param {Block|MerkleBlock} block
 * @param {ChainBlock} entry
 * @param {Function} callback - Returns
 * [{@link VerifyError}, {@link VerifyFlags}].
 */

Chain.prototype._verify = function _verify(block, prev, callback) {
  var self = this;
  var ret = {};
  var height, ts, i, tx, medianTime, commitmentHash;

  if (!block.verify(ret))
    return callback(new VerifyError(block, 'invalid', ret.reason, ret.score));

  if (this.options.spv || block.type !== 'block')
    return callback(null, constants.flags.MANDATORY_VERIFY_FLAGS);

  // Skip the genesis block
  if (block.isGenesis())
    return callback(null, constants.flags.MANDATORY_VERIFY_FLAGS);

  // Ensure it's not an orphan
  if (!prev)
    return callback(new VerifyError(block, 'invalid', 'bad-prevblk', 0));

  prev.getRetargetAncestors(function(err, ancestors) {
    if (err)
      return callback(err);

    height = prev.height + 1;
    medianTime = prev.getMedianTime();

    // Ensure the timestamp is correct
    if (block.ts <= medianTime) {
      return callback(new VerifyError(block,
        'invalid',
        'time-too-old',
        0));
    }

    if (block.bits !== self.getTarget(prev, block, ancestors)) {
      return callback(new VerifyError(block,
        'invalid',
        'bad-diffbits',
        100));
    }

    self._checkDeployments(block, prev, ancestors, function(err, state) {
      if (err)
        return callback(err);

      // Expose the state of csv and segwit globally.
      self.csvActive = state.csv;
      self.segwitActive = state.segwit;

      // Can't verify any further when merkleblock or headers.
      if (block.type !== 'block')
        return callback(null, state.flags);

      // Make sure the height contained in the coinbase is correct.
      if (state.coinbaseHeight) {
        if (block.getCoinbaseHeight() !== height) {
          return callback(new VerifyError(block,
            'invalid',
            'bad-cb-height',
            100));
        }
      }

      // Check the commitment hash for segwit.
      if (state.segwit) {
        commitmentHash = block.commitmentHash;
        if (commitmentHash) {
          if (!block.witnessNonce) {
            return callback(new VerifyError(block,
              'invalid',
              'bad-witness-merkle-size',
              100));
          }
          if (commitmentHash !== block.getCommitmentHash('hex')) {
            return callback(new VerifyError(block,
              'invalid',
              'bad-witness-merkle-match',
              100));
          }
        }
      }

      // Blocks that do not commit to
      // witness data data cannot contain it.
      if (!commitmentHash) {
        if (block.hasWitness()) {
          return callback(new VerifyError(block,
            'invalid',
            'unexpected-witness',
            100));
        }
      }

      // Check block cost (different from block size
      // check in non-contextual verification).
      if (block.getCost() > constants.block.MAX_COST) {
        return callback(new VerifyError(block,
          'invalid',
          'bad-blk-cost',
          100));
      }

      // Get timestamp for tx.isFinal().
      ts = (state.lockFlags & constants.flags.MEDIAN_TIME_PAST) !== 0
        ? medianTime
        : block.ts;

      // Check all transactions
      for (i = 0; i < block.txs.length; i++) {
        tx = block.txs[i];

        // Transactions must be finalized with
        // regards to nSequence and nLockTime.
        if (!tx.isFinal(height, ts)) {
          return callback(new VerifyError(block,
            'invalid',
            'bad-txns-nonfinal',
            10));
        }
      }

      return callback(null, state);
    });
  });
};

/**
 * Check all deployments on a chain, ranging from p2sh to segwit.
 * @private
 * @param {Block} block
 * @param {ChainBlock} prev
 * @param {ChainBlock[]} ancestors
 * @param {Function} callback - Returns
 * [{@link VerifyError}, {@link DeploymentState}].
 */

Chain.prototype._checkDeployments = function _checkDeployments(block, prev, ancestors, callback) {
  var self = this;
  var height = prev.height + 1;
  var state = {
    flags: constants.flags.MANDATORY_VERIFY_FLAGS,
    lockFlags: constants.flags.MANDATORY_LOCKTIME_FLAGS,
    coinbaseHeight: false,
    segwit: false,
    csv: false
  };

  // For some reason bitcoind has p2sh in the
  // mandatory flags by default, when in reality
  // it wasn't activated until march 30th 2012.
  // The first p2sh output and redeem script
  // appeared on march 7th 2012, only it did
  // not have a signature. See:
  // 6a26d2ecb67f27d1fa5524763b49029d7106e91e3cc05743073461a719776192
  // 9c08a4d78931342b37fd5f72900fb9983087e6f46c4a097d8a1f52c74e28eaf6
  if (block.ts < constants.block.BIP16_TIME)
    state.flags &= ~constants.flags.VERIFY_P2SH;

  // Only allow version 2 blocks (coinbase height)
  // once the majority of blocks are using it.
  if (block.version < 2 && prev.isOutdated(2, ancestors))
    return callback(new VerifyError(block, 'obsolete', 'bad-version', 0));

  // Only allow version 3 blocks (sig validation)
  // once the majority of blocks are using it.
  if (block.version < 3 && prev.isOutdated(3, ancestors))
    return callback(new VerifyError(block, 'obsolete', 'bad-version', 0));

  // Only allow version 4 blocks (checklocktimeverify)
  // once the majority of blocks are using it.
  if (block.version < 4 && prev.isOutdated(4, ancestors))
    return callback(new VerifyError(block, 'obsolete', 'bad-version', 0));

  // Only allow version 5 blocks (bip141 - segnet3)
  // once the majority of blocks are using it.
  if (network.segwitHeight !== -1 && height >= network.segwitHeight) {
    if (block.version < 5 && prev.isOutdated(5, ancestors))
      return callback(new VerifyError(block, 'obsolete', 'bad-version', 0));
  }

  // Make sure the height contained in the coinbase is correct.
  if (block.version >= 2 && prev.isUpgraded(2, ancestors))
    state.coinbaseHeight = true;

  // Signature validation is now enforced (bip66)
  if (block.version >= 3 && prev.isUpgraded(3, ancestors))
    state.flags |= constants.flags.VERIFY_DERSIG;

  // CHECKLOCKTIMEVERIFY is now usable (bip65)
  if (block.version >= 4 && prev.isUpgraded(4, ancestors))
    state.flags |= constants.flags.VERIFY_CHECKLOCKTIMEVERIFY;

  // Segregrated witness is now usable (bip141 - segnet3)
  if (network.segwitHeight !== -1 && height >= network.segwitHeight) {
    if (block.version >= 5 && prev.isUpgraded(5, ancestors)) {
      state.flags |= constants.flags.VERIFY_WITNESS;
      state.segwit = true;
    }
  }

  utils.serial([
    function(next) {
      // CHECKSEQUENCEVERIFY and median time
      // past locktimes are now usable (bip9 & bip113).
      self.isActive(prev, 'csv', function(err, active) {
        if (err)
          return next(err);

        if (active) {
          state.flags |= constants.flags.VERIFY_CHECKSEQUENCEVERIFY;
          state.lockFlags |= constants.flags.VERIFY_SEQUENCE;
          state.lockFlags |= constants.flags.MEDIAN_TIME_PAST;
          state.csv = true;
        }

        return next();
      });
    },
    function(next) {
      // Segregrated witness is now usable (bip141 - segnet4)
      self.isActive(prev, 'witness', function(err, active) {
        if (err)
          return next(err);

        if (active) {
          state.flags |= constants.flags.VERIFY_WITNESS;
          state.segwit = true;
        }

        return next();
      });
    }
  ], function(err) {
    if (err)
      return callback(err);

    return callback(null, state);
  });
};

/**
 * Determine whether to check block for duplicate txids in blockchain
 * history (BIP30). If we're on a chain that has bip34 activated, we
 * can skip this.
 * @private
 * @see https://github.com/bitcoin/bips/blob/master/bip-0030.mediawiki
 * @param {Block|MerkleBlock} block
 * @param {ChainBlock} prev
 * @param {Function} callback - Returns [{@link VerifyError}].
 */

Chain.prototype._checkDuplicates = function _checkDuplicates(block, prev, callback) {
  var self = this;
  var height = prev.height + 1;

  if (this.options.spv || block.type !== 'block')
    return callback();

  if (block.isGenesis())
    return callback();

  if (network.block.bip34height === -1 || height <= network.block.bip34height)
    return this._findDuplicates(block, prev, callback);

  this.db.get(network.block.bip34height, function(err, entry) {
    if (err)
      return callback(err);

    // It was no longer possible to create duplicate
    // TXs once bip34 went into effect. We can check
    // for this to avoid a DB lookup.
    if (entry && entry.hash === network.block.bip34hash)
      return callback();

    return self._findDuplicates(block, prev, callback);
  });
};

/**
 * Check block for duplicate txids in blockchain
 * history (BIP30). Note that txids are only considered
 * duplicate if they are not yet completely spent.
 * @private
 * @see https://github.com/bitcoin/bips/blob/master/bip-0030.mediawiki
 * @param {Block|MerkleBlock} block
 * @param {ChainBlock} prev
 * @param {Function} callback - Returns [{@link VerifyError}].
 */

Chain.prototype._findDuplicates = function _findDuplicates(block, prev, callback) {
  var self = this;
  var height = prev.height + 1;

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
        if (constants.bip30[height]) {
          if (block.hash('hex') === constants.bip30[height])
            return next();
        }
        return next(new VerifyError(block, 'invalid', 'bad-txns-BIP30', 100));
      }

      next();
    });
  }, callback);
};

/**
 * Check block transactions for all things pertaining
 * to inputs. This function is important because it is
 * what actually fills the coins into the block. This
 * function will check the block reward, the sigops,
 * the tx values, and execute and verify the scripts (it
 * will attempt to do this on the worker pool). If
 * useCheckpoints is enabled, it will skip verification
 * for historical data.
 * @private
 * @see TX#checkInputs
 * @param {Block} block
 * @param {ChainBlock} prev
 * @param {DeploymentState} state
 * @param {Function} callback - Returns [{@link VerifyError}].
 */

Chain.prototype._checkInputs = function _checkInputs(block, prev, state, callback) {
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

    if (err)
      return callback(err);

    // Check all transactions
    utils.forEachSerial(block.txs, function(tx, next) {
      var hash = tx.hash('hex');

      // Ensure tx is not double spending an output.
      if (!tx.isCoinbase()) {
        if (!tx.hasCoins()) {
          assert(!historical, 'BUG: Spent inputs in historical data!');
          return next(new VerifyError(block,
            'invalid',
            'bad-txns-inputs-missingorspent',
            100));
        }
      }

      self.checkLocks(tx, state.lockFlags, entry, function(err, valid) {
        if (err)
          return next(err);

        if (!valid) {
          return next(new VerifyError(block,
            'invalid',
            'bad-txns-nonfinal',
            100));
        }

        // Count sigops (legacy + scripthash? + witness?)
        sigops += tx.getSigopsCost(state.flags);

        if (sigops > constants.block.MAX_SIGOPS_COST) {
          return next(new VerifyError(block,
            'invalid',
            'bad-blk-sigops',
            100));
        }

        // Contextual sanity checks.
        if (!tx.isCoinbase()) {
          if (!tx.checkInputs(height, ret)) {
            return next(new VerifyError(block,
              'invalid',
              ret.reason,
              ret.score));
          }
        }

        return next();
      });
    }, function(err) {
      if (err)
        return callback(err);

      // Verify all txs in parallel.
      utils.every(block.txs, function(tx, next) {
        if (!scriptCheck)
          return next(null, true);

        tx.verifyAsync(null, true, state.flags, next);
      }, function(err, verified) {
        if (err)
          return callback(err);

        if (!verified) {
          assert(!historical, 'BUG: Invalid inputs in historical data!');
          return next(new VerifyError(block,
            'invalid',
            'mandatory-script-verify-flag-failed',
            100));
        }

        // Make sure the miner isn't trying to conjure more coins.
        if (block.getClaimed().cmp(block.getReward()) > 0) {
          return callback(new VerifyError(block,
            'invalid',
            'bad-cb-amount',
            100));
        }

        return callback();
      });
    });
  });
};

Chain.prototype._getCachedHeight = function _getCachedHeight(hash) {
  if (this.db.hasCache(hash))
    return this.db.getCache(hash).height;

  return -1;
};

/**
 * Find the block at which a fork ocurred.
 * @private
 * @param {ChainBlock} fork - The current chain.
 * @param {ChainBlock} longer - The competing chain.
 * @param {Function} callback - Returns [{@link Error}, {@link ChainBlock}].
 */

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

/**
 * Reorganize the blockchain (connect and disconnect inputs).
 * Called when a competing chain with a higher chainwork
 * is received.
 * @private
 * @param {ChainBlock} entry - The competing chain's tip.
 * @param {Block|MerkleBlock} block - The being being added.
 * @param {Function} callback
 */

Chain.prototype._reorganize = function _reorganize(entry, block, callback) {
  var self = this;
  var tip = this.tip;

  return this._findFork(tip, entry, function(err, fork) {
    if (err)
      return callback(err);

    assert(fork);

    // Disconnect blocks/txs.
    function disconnect(callback) {
      var entries = [];

      entries.push(tip);

      (function collect(entry) {
        entry.getPrevious(function(err, entry) {
          if (err)
            return callback(err);

          assert(entry);

          if (entry.hash === fork.hash)
            return finish();

          entries.push(entry);

          collect(entry);
        });
      })(tip);

      function finish() {
        utils.forEachSerial(entries, function(entry, next) {
          self.disconnect(entry, next);
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

          if (entry.hash === fork.hash)
            return finish();

          entries.push(entry);

          collect(entry);
        });
      })(entry);

      function finish() {
        entries = entries.slice().reverse();
        utils.forEachSerial(entries, function(entry, next) {
          self.connect(entry, next);
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
          expected: tip.hash,
          received: entry.hash,
          checkpoint: false
        });

        return callback();
      });
    });
  });
};

/**
 * Disconnect an entry from the chain (updates the tip).
 * @param {ChainBlock} entry
 * @param {Function} callback
 */

Chain.prototype.disconnect = function disconnect(entry, callback) {
  var self = this;

  this.db.disconnect(entry, function(err) {
    if (err)
      return callback(err);

    entry.getPrevious(function(err, entry) {
      if (err)
        return callback(err);

      assert(entry);

      self.tip = entry;
      self.height = entry.height;

      self.bestHeight = entry.height;
      network.height = entry.height;

      self.emit('tip', entry);

      return callback();
    });
  });
};

/**
 * Connect an entry to the chain (updates the tip).
 * This will do contextual-verification on the block
 * (necessary because we cannot validate the inputs
 * in alternate chains when they come in).
 * @param {ChainBlock} entry
 * @param {Function} callback
 */

Chain.prototype.connect = function connect(entry, callback) {
  var self = this;

  this.db.getBlock(entry.hash, function(err, block) {
    if (err)
      return callback(err);

    assert(block);

    entry.getPrevious(function(err, prev) {
      if (err)
        return callback(err);

      assert(prev);

      self._verifyContext(block, prev, function(err) {
        if (err) {
          if (err.type === 'VerifyError') {
            self.invalid[entry.hash] = true;
            self.emit('invalid', block, {
              height: entry.height,
              hash: entry.hash,
              seen: false,
              chain: false
            });
          }
          return callback(err);
        }

        self.db.connect(entry, block, function(err) {
          if (err)
            return callback(err);

          self.tip = entry;
          self.height = entry.height;

          self.bestHeight = entry.height;
          network.height = entry.height;

          self.emit('tip', entry);

          return callback();
        });
      });
    });
  });
};

/**
 * Set the best chain. This is called on every valid block
 * that comes in. It may add and connect the block (main chain),
 * save the block without connection (alternate chain), or
 * reorganize the chain (a higher fork).
 * @private
 * @param {ChainBlock} entry
 * @param {ChainBlock} prev
 * @param {Block|MerkleBlock} block
 * @param {Function} callback - Returns [{@link VerifyError}].
 */

Chain.prototype._setBestChain = function _setBestChain(entry, prev, block, callback) {
  var self = this;

  function done(err) {
    if (err)
      return callback(err);

    // Do "contextual" verification on our block
    // now that we're certain its previous
    // block is in the chain.
    self._verifyContext(block, prev, function(err) {
      if (err) {
        // Couldn't verify block.
        // Revert the height.
        block.setHeight(-1);

        if (err.type === 'VerifyError') {
          self.invalid[entry.hash] = true;
          self.emit('invalid', block, {
            height: entry.height,
            hash: entry.hash,
            seen: false,
            chain: false
          });
        }

        return callback(err);
      }

      // Save block and connect inputs.
      self.db.save(entry, block, true, function(err) {
        if (err)
          return callback(err);

        self.tip = entry;
        self.height = entry.height;

        self.emit('tip', entry);

        return callback();
      });
    });
  }

  // We don't have a genesis block yet.
  if (!this.tip) {
    if (entry.hash !== network.genesis.hash) {
      return utils.asyncify(callback)(new VerifyError(block,
        'invalid',
        'bad-genblk',
        100));
    }

    return done();
  }

  // Everything is in order.
  if (entry.prevBlock === this.tip.hash)
    return done();

  // A higher fork has arrived.
  // Time to reorganize the chain.
  bcoin.debug('WARNING: Reorganizing chain.');
  return this._reorganize(entry, block, done);
};

/**
 * Reset the chain to the desired height. This
 * is useful for replaying the blockchain download
 * for SPV.
 * @param {Number} height
 * @param {Function} callback
 */

Chain.prototype.reset = function reset(height, callback, force) {
  var self = this;

  var unlock = this._lock(reset, [height, callback], force);
  if (!unlock)
    return;

  callback = utils.wrap(callback, unlock);

  this.db.reset(height, function(err, result) {
    if (err)
      return callback(err);

    // Reset the orphan map completely. There may
    // have been some orphans on a forked chain we
    // no longer need.
    self.purgeOrphans();
    self.purgePending();

    callback(null, result);
  });
};

/**
 * Reset the chain to the desired timestamp (within 2
 * hours). This is useful for replaying the blockchain
 * download for SPV.
 * @param {Number} ts - Timestamp.
 * @param {Function} callback
 */

Chain.prototype.resetTime = function resetTime(ts, callback, force) {
  var self = this;

  var unlock = this._lock(resetTime, [ts, callback], force);
  if (!unlock)
    return;

  callback = utils.wrap(callback, unlock);

  this.byTime(ts, function(err, entry) {
    if (err)
      return callback(err);

    if (!entry)
      return callback();

    self.reset(entry.height, callback, true);
  }, true);
};

/**
 * Wait for the chain to flush (finish processing
 * all of the blocks in its queue).
 * @param {Function} callback
 */

Chain.prototype.onFlush = function onFlush(callback) {
  return this.locker.onFlush(callback);
};

/**
 * Test whether the chain is in the process of adding blocks.
 * @returns {Boolean}
 */

Chain.prototype.isBusy = function isBusy() {
  return this.adding || this.locker.pending.length > 0;
};

/**
 * Add a block to the chain, perform all necessary verification.
 * @param {Block|MerkleBlock|CompactBlock} block
 * @param {Function} callback - Returns [{@link VerifyError}].
 */

Chain.prototype.add = function add(block, callback, force) {
  var self = this;
  var total = 0;
  var ret = {};

  assert(this.loaded);

  var unlock = this._lock(add, [block, callback], force);
  if (!unlock)
    return;

  callback = utils.wrap(callback, unlock);

  this.adding = true;

  (function next(block, initial) {
    var hash = block.hash('hex');
    var prevHash = block.prevBlock;
    var height, checkpoint, orphan, entry;

    function handleOrphans() {
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
    }

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

        if (height > self.bestHeight) {
          self.bestHeight = height;
          network.height = height;
        }

        // If previous block wasn't ever seen,
        // add it current to orphans and break.
        if (!prev) {
          self.orphan.count++;
          self.orphan.size += block.getSize();
          self.orphan.map[prevHash] = block;
          self.orphan.bmap[hash] = block;

          // Update the best height based on the coinbase.
          // We do this even for orphans (peers will send
          // us their highest block during the initial
          // getblocks sync, making it an orphan).
          if (block.getCoinbaseHeight() > self.bestHeight) {
            self.bestHeight = block.getCoinbaseHeight();
            network.height = self.bestHeight;
          }

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
        if (block.compact) {
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
        block.setHeight(height);

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

        // The block is on a alternate chain if the
        // chainwork is less than or equal to
        // our tip's. Add the block but do _not_
        // connect the inputs.
        if (entry.chainwork.cmp(self.tip.chainwork) <= 0) {
          return self.db.save(entry, block, false, function(err) {
            if (err)
              return done(err);

            // Keep track of the number of blocks we
            // added and the number of orphans resolved.
            total++;

            // Emit our block (and potentially resolved
            // orphan) only if it is on the main chain.
            self.emit('competitor', block, entry);

            if (!initial)
              self.emit('competitor resolved', block, entry);

            handleOrphans();
          });
        }

        // Attempt to add block to the chain index.
        self._setBestChain(entry, prev, block, function(err) {
          if (err)
            return done(err);

          // Keep track of the number of blocks we
          // added and the number of orphans resolved.
          total++;

          // Emit our block (and potentially resolved
          // orphan) only if it is on the main chain.
          self.emit('block', block, entry);

          if (!initial)
            self.emit('resolved', block, entry);

          handleOrphans();
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
      if (!self.synced && self.isFull()) {
        self.synced = true;
        self.emit('full');
      }

      self.adding = false;

      if (err)
        callback(err);
      else
        callback(null, total);
    });
  }
};

/**
 * Purge any waiting orphans.
 */

Chain.prototype.purgeOrphans = function purgeOrphans() {
  this.emit('purge', this.orphan.count, this.orphan.size);
  this.orphan.map = {};
  this.orphan.bmap = {};
  this.orphan.count = 0;
  this.orphan.size = 0;
};

/**
 * Prune orphans, only keep the orphan with the highest
 * coinbase height (likely to be the peer's tip).
 */

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

/**
 * Purge any pending blocks in the queue: note that
 * this call is unpredictable and may screw up the
 * blockchain sync. It is only used as a last resort
 * if more than 500mb of pending blocks are in the queue.
 */

Chain.prototype.purgePending = function purgePending() {
  return this.locker.purgePending();
};

/**
 * Test the chain to see if it has a block, orphan, or pending block.
 * @param {Hash} hash
 * @param {Function} callback - Returns [Error, Boolean].
 */

Chain.prototype.has = function has(hash, callback) {
  if (this.hasOrphan(hash))
    return callback(null, true);

  if (this.hasPending(hash))
    return callback(null, true);

  return this.hasBlock(hash, callback);
};

/**
 * Find a block entry by timestamp.
 * @param {Number} ts - Timestamp.
 * @param {Function} callback - Returns [Error, {@link ChainBlock}].
 */

Chain.prototype.byTime = function byTime(ts, callback) {
  var self = this;
  var start = 0;
  var end = this.height;
  var pos, delta;

  function done(err, result) {
    if (err)
      return callback(err);

    if (result)
      return callback(null, result);

    self.db.get(start, callback);
  }

  if (ts >= this.tip.ts)
    return utils.asyncify(done)(null, this.tip);

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

/**
 * Test the chain to see if it contains a block.
 * @param {Hash} hash
 * @param {Function} callback - Returns [Error, Boolean].
 */

Chain.prototype.hasBlock = function hasBlock(hash, callback) {
  return this.db.has(hash, callback);
};

/**
 * Test the chain to see if it contains an orphan.
 * @param {Hash} hash
 * @param {Function} callback - Returns [Error, Boolean].
 */

Chain.prototype.hasOrphan = function hasOrphan(hash) {
  return !!this.getOrphan(hash);
};

/**
 * Test the chain to see if it contains a pending block in its queue.
 * @param {Hash} hash
 * @param {Function} callback - Returns [Error, Boolean].
 */

Chain.prototype.hasPending = function hasPending(hash) {
  return this.locker.hasPending(hash);
};

/**
 * Find the corresponding block entry by hash or height.
 * @param {Hash|Number} hash/height
 * @param {Function} callback - Returns [Error, {@link ChainBlock}].
 */

Chain.prototype.getEntry = function getEntry(hash, callback) {
  return this.db.get(hash, callback);
};

/**
 * Get an orphan block.
 * @param {Hash} hash
 * @returns {Block|MerkleBlock|CompactBlock}
 */

Chain.prototype.getOrphan = function getOrphan(hash) {
  return this.orphan.bmap[hash] || null;
};

/**
 * Test the chain to see if it is synced.
 * @returns {Boolean}
 */

Chain.prototype.isFull = function isFull() {
  return !this.isInitial();
};

/**
 * Test the chain to see if it is still in the initial
 * syncing phase. Mimic's bitcoind's `IsInitialBlockDownload()`
 * function.
 * @see IsInitalBlockDownload()
 * @returns {Boolean}
 */

Chain.prototype.isInitial = function isInitial() {
  if (!this.tip)
    return true;

  if (this.synced)
    return false;

  if (this.height < network.checkpoints.lastHeight)
    return true;

  return this.height < this.bestHeight - 24 * 6
    || this.tip.ts < utils.now() - network.block.maxTipAge;
};

/**
 * Get the fill percentage.
 * @returns {Number} percent - Ranges from 0.0 to 1.0.
 */

Chain.prototype.getProgress = function getProgress() {
  var start, current, end;

  if (!this.tip)
    return 0;

  start = network.genesis.ts;
  current = this.tip.ts - start;
  end = utils.now() - start - 40 * 60;

  return Math.min(1, current / end);
};

/**
 * Collect block hashes between a range of two timestamps.
 * @param {Number} start - Start time (unix time).
 * @param {Number} end - End time (unix time).
 * @param {Function} callback - Returns [Error, Hash[]].
 */

Chain.prototype.getHashRange = function getHashRange(start, end, callback) {
  var self = this;

  this.byTime(start, function(err, start) {
    if (err)
      return callback(err);

    self.byTime(end, function(err, end) {
      var hashes;

      if (err)
        return callback(err);

      hashes = [];

      if (!start || !end)
        return callback(null, hashes);

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
          return callback(err);
        return callback(null, hashes);
      });
    }, true);
  }, true);
};

/**
 * Calculate chain locator (an array of hashes).
 * @param {(Number|Hash)?} start - Height or hash to treat as the tip.
 * The current tip will be used if not present. Note that this can be a
 * non-existent hash, which is useful for headers-first locators.
 * @param {Function} callback - Returns [Error, {@link Hash}[]].
 */

Chain.prototype.getLocator = function getLocator(start, callback, force) {
  var self = this;
  var hashes = [];
  var top = this.height;
  var step = 1;
  var i;

  var unlock = this._lock(getLocator, [start, callback], force);
  if (!unlock)
    return;

  callback = utils.wrap(callback, unlock);

  function build(err, top) {
    if (err)
      return callback(err);

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

    utils.forEachSerial(hashes, function(height, next, i) {
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
      if (err)
        return callback(err);
      return callback(null, hashes);
    });
  }

  if (typeof start === 'string') {
    return self.db.getHeight(start, function(err, top) {
      if (err)
        return build(err);

      if (top === -1) {
        // We could simply `return [start]` here,
        // but there is no standardized "spacing"
        // for locator hashes. Pretend this hash
        // is our tip. This is useful for getheaders
        // when not using headers-first.
        hashes.push(start);
        top = self.height;
      }

      return build(null, top);
    });
  }

  if (typeof start === 'number')
    top = start;

  return build(null, top);
};

/**
 * Calculate the orphan root of the hash (if it is an orphan).
 * Will also calculate "orphan soil" -- the block needed
 * in * order to resolve the orphan root.
 * @param {Hash} hash
 * @returns {Object?} root - { root: {@link Hash}, soil: {@link Hash} }.
 */

Chain.prototype.getOrphanRoot = function getOrphanRoot(hash) {
  var root;

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

/**
 * Calculate the next target based on the chain tip.
 * @param {Function} callback - returns [Error, Number]
 * (target is in compact/mantissa form).
 */

Chain.prototype.getCurrentTarget = function getCurrentTarget(callback) {
  if (!this.tip)
    return callback(null, utils.toCompact(network.pow.limit));
  return this.getTargetAsync(this.tip, null, callback);
};

/**
 * Calculate the target based on the passed-in chain entry.
 * @param {ChainBlock} last - Previous entry.
 * @param {Block|MerkleBlock|null} - Current block.
 * @param {Function} callback - returns [Error, Number]
 * (target is in compact/mantissa form).
 */

Chain.prototype.getTargetAsync = function getTargetAsync(last, block, callback) {
  var self = this;

  if ((last.height + 1) % network.pow.retargetInterval !== 0) {
    if (!network.pow.allowMinDifficultyBlocks)
      return utils.asyncify(callback)(null, this.getTarget(last, block));
  }

  return last.getAncestors(network.pow.retargetInterval, function(err, ancestors) {
    if (err)
      return callback(err);

    return callback(null, self.getTarget(last, block, ancestors));
  });
};

/**
 * Calculate the target synchronously. _Must_
 * have ancestors pre-allocated.
 * @param {ChainBlock} last - Previous entry.
 * @param {Block|MerkleBlock|null} - Current block.
 * @param {Function} callback - returns [Error, Number]
 * (target is in compact/mantissa form).
 */

Chain.prototype.getTarget = function getTarget(last, block, ancestors) {
  var powLimit = utils.toCompact(network.pow.limit);
  var ts, first, i;

  // Genesis
  if (!last)
    return powLimit;

  // Do not retarget
  if ((last.height + 1) % network.pow.retargetInterval !== 0) {
    if (network.pow.allowMinDifficultyBlocks) {
      // Special behavior for testnet:
      ts = block ? (block.ts || block) : bcoin.now();
      if (ts > last.ts + network.pow.targetSpacing * 2)
        return powLimit;

      i = 1;
      while (ancestors[i]
        && last.height % network.pow.retargetInterval !== 0
        && last.bits === powLimit) {
        last = ancestors[i++];
      }
    }
    return last.bits;
  }

  // Back 2 weeks
  first = ancestors[network.pow.retargetInterval - 1];

  assert(first);

  return this.retarget(last, first);
};

/**
 * Retarget. This is called when the chain height
 * hits a retarget diff interval.
 * @param {ChainBlock} last - Previous entry.
 * @param {ChainBlock} first - Chain entry from 2 weeks prior.
 * @returns {Number} target - Target in compact/mantissa form.
 */

Chain.prototype.retarget = function retarget(last, first) {
  var powTargetTimespan = new bn(network.pow.targetTimespan);
  var actualTimespan, target;

  if (network.pow.noRetargeting)
    return last.bits;

  actualTimespan = new bn(last.ts - first.ts);
  target = utils.fromCompact(last.bits);

  if (actualTimespan.cmp(powTargetTimespan.divn(4)) < 0)
    actualTimespan = powTargetTimespan.divn(4);

  if (actualTimespan.cmp(powTargetTimespan.muln(4)) > 0)
    actualTimespan = powTargetTimespan.muln(4);

  target.imul(actualTimespan);
  target = target.div(powTargetTimespan);

  if (target.cmp(network.pow.limit) > 0)
    target = network.pow.limit.clone();

  return utils.toCompact(target);
};

/**
 * Find a locator. Analagous to bitcoind's `FindForkInMainChain()`.
 * @param {Hash[]} locator - Hashes.
 * @param {Function} callback - Returns [Error, {@link Hash}] (the
 * hash of the latest known block).
 */

Chain.prototype.findLocator = function findLocator(locator, callback) {
  var self = this;

  if (!locator)
    return utils.nextTick(callback);

  utils.forEachSerial(locator, function(hash, next) {
    self.db.has(hash, function(err, result) {
      if (err)
        return next(err);

      if (result)
        return callback(null, hash);

      next();
    });
  }, callback);
};

/**
 * Check whether a versionbits deployment is active (BIP9: versionbits).
 * @example
 * chain.isActive(entry, 'witness', callback);
 * @see https://github.com/bitcoin/bips/blob/master/bip-0009.mediawiki
 * @param {ChainBlock} prev - Previous chain entry.
 * @param {String} id - Deployment id.
 * @param {Function} callback - Returns [Error, Number].
 */

Chain.prototype.isActive = function isActive(prev, id, callback) {
  // Optimization for main
  if (network.type === 'main' && prev.height < 400000)
    return callback(null, false);

  this.getState(prev, id, function(err, state) {
    if (err)
      return callback(err);

    return callback(null, state === constants.thresholdStates.ACTIVE);
  });
};

/**
 * Get chain entry state for a deployment (BIP9: versionbits).
 * @example
 * chain.getState(entry, 'witness', callback);
 * @see https://github.com/bitcoin/bips/blob/master/bip-0009.mediawiki
 * @param {ChainBlock} prev - Previous chain entry.
 * @param {String} id - Deployment id.
 * @param {Function} callback - Returns [Error, Number].
 */

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

    if (self.stateCache[entry.hash])
      return walkForward(self.stateCache[entry.hash]);

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
    var entry, count, i;

    if (compute.length === 0)
      return callback(null, state);

    entry = compute.pop();

    switch (state) {
      case constants.thresholdStates.DEFINED:
        return entry.getMedianTimeAsync(function(err, medianTime) {
          if (err)
            return callback(err);

          if (medianTime >= timeTimeout) {
            self.stateCache[entry.hash] = constants.thresholdStates.FAILED;
            return walkForward(constants.thresholdStates.FAILED);
          }

          if (medianTime >= timeStart) {
            self.stateCache[entry.hash] = constants.thresholdStates.STARTED;
            return walkForward(constants.thresholdStates.STARTED);
          }

          self.stateCache[entry.hash] = state;
          return walkForward(state);
        });
      case constants.thresholdStates.STARTED:
        return entry.getMedianTimeAsync(function(err, medianTime) {
          if (err)
            return callback(err);

          if (medianTime >= timeTimeout) {
            self.stateCache[entry.hash] = constants.thresholdStates.FAILED;
            return walkForward(constants.thresholdStates.FAILED);
          }

          count = 0;
          i = 0;

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

            if (count >= threshold) {
              self.stateCache[entry.hash] = constants.thresholdStates.LOCKED_IN;
              return walkForward(constants.thresholdStates.LOCKED_IN);
            }

            self.stateCache[entry.hash] = state;
            return walkForward(state);
          }
        });
      case constants.thresholdStates.LOCKED_IN:
        self.stateCache[entry.hash] = constants.thresholdStates.ACTIVE;
        return walkForward(constants.thresholdStates.ACTIVE);
      case constants.thresholdStates.FAILED:
      case constants.thresholdStates.ACTIVE:
        self.stateCache[entry.hash] = state;
        return walkForward(state);
    }

    assert(false, 'Bad state.');
  }
};

/**
 * Compute the version for a new block (BIP9: versionbits).
 * @see https://github.com/bitcoin/bips/blob/master/bip-0009.mediawiki
 * @param {ChainBlock} prev - Previous chain entry (usually the tip).
 * @param {Function} callback - Returns [Error, Number].
 */

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

/**
 * A helper function to test whether segwit is active at any
 * given time. Since segwit affects almost all of bitcoin, it
 * is one deployment that needs to be checked frequently.
 * @private
 * @param {Function} callback - Returns [Error, Boolean].
 */

Chain.prototype._getInitialState = function _getInitialState(callback) {
  var self = this;

  if (this.segwitActive != null)
    return utils.nextTick(callback);

  if (!this.tip)
    return utils.nextTick(callback);

  return this.tip.getPrevious(function(err, prev) {
    if (err)
      return callback(err);

    if (!prev) {
      self.csvActive = false;
      self.segwitActive = false;
      return callback();
    }

    prev.getRetargetAncestors(function(err, ancestors) {
      if (err)
        return callback(err);

      self._checkDeployments(self.tip, prev, ancestors, function(err, state) {
        if (err)
          return callback(err);

        self.csvActive = state.csv;
        self.segwitActive = state.segwit;

        return callback();
      });
    });
  });
};

/**
 * Check transaction finality, taking into account MEDIAN_TIME_PAST
 * if it is present in the lock flags.
 * @param {ChainBlock} prev - Previous chain entry.
 * @param {TX} tx
 * @param {LockFlags}
 * @param {Function} callback - Returns [Error, Boolean].
 */

Chain.prototype.checkFinal = function checkFinal(prev, tx, flags, callback) {
  var height = prev.height + 1;

  function check(err, ts) {
    if (err)
      return callback(err);

    return callback(null, tx.isFinal(height, ts));
  }

  if (flags & constants.flags.MEDIAN_TIME_PAST)
    return prev.getMedianTimeAsync(check);

  utils.asyncify(check)(null, bcoin.now());
};

/**
 * Get the necessary minimum time and height sequence locks for a transaction.
 * @param {TX} tx
 * @param {LockFlags} flags
 * @param {ChainBlock} entry
 * @param {Function} callback - Returns
 * [Error, Number(minTime), Number(minHeight)].
 */

Chain.prototype.getLocks = function getLocks(tx, flags, entry, callback) {
  var self = this;
  var mask = constants.sequence.MASK;
  var granularity = constants.sequence.GRANULARITY;
  var disableFlag = constants.sequence.DISABLE_FLAG;
  var typeFlag = constants.sequence.TYPE_FLAG;
  var hasFlag = flags & constants.flags.VERIFY_SEQUENCE;
  var minHeight = -1;
  var minTime = -1;
  var coinHeight;

  if (tx.isCoinbase() || tx.version < 2 || !hasFlag)
    return utils.asyncify(callback)(null, minHeight, minTime);

  utils.forEachSerial(tx.inputs, function(input, next) {
    if (input.sequence & disableFlag)
      return next();

    coinHeight = input.coin.height === -1
      ? self.height + 1
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

/**
 * Evaluate sequence locks.
 * @param {ChainBlock} entry
 * @param {Number} minHeight
 * @param {Number} minTime
 * @param {Function} callback - Returns [Error, Boolean].
 */

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

/**
 * Verify sequence locks.
 * @param {TX} tx
 * @param {LockFlags} flags
 * @param {ChainBlock} entry
 * @param {Function} callback - Returns [Error, Boolean].
 */

Chain.prototype.checkLocks = function checkLocks(tx, flags, entry, callback) {
  var self = this;

  this.getLocks(tx, flags, entry, function(err, minHeight, minTime) {
    if (err)
      return callback(err);

    self.evalLocks(entry, minHeight, minTime, callback);
  });
};

/**
 * Calculate the difficulty.
 * @param {ChainBlock} entry
 * @returns {Number} Difficulty.
 */

Chain.prototype.getDifficulty = function getDifficulty(entry) {
  var shift, diff;

  if (!entry) {
    if (!this.tip)
      return 1.0;
    entry = this.tip;
  }

  shift = (entry.bits >>> 24) & 0xff;
  diff = 0x0000ffff / (entry.bits & 0x00ffffff);

  while (shift < 29) {
    diff *= 256.0;
    shift++;
  }

  while (shift > 29) {
    diff /= 256.0;
    shift--;
  }

  return diff;
};

return Chain;
};
