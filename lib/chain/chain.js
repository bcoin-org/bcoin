/*!
 * chain.js - blockchain management for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var bcoin = require('../env');
var AsyncObject = require('../utils/async');
var constants = bcoin.constants;
var utils = require('../utils/utils');
var assert = utils.assert;
var VerifyError = bcoin.errors.VerifyError;
var VerifyResult = utils.VerifyResult;

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
 * @property {ChainEntry?} tip
 * @property {Number} height
 * @property {DeploymentState} state
 * @property {Object} orphan - Orphan map.
 * @emits Chain#open
 * @emits Chain#error
 * @emits Chain#block
 * @emits Chain#competitor
 * @emits Chain#resolved
 * @emits Chain#checkpoint
 * @emits Chain#fork
 * @emits Chain#reorganize
 * @emits Chain#invalid
 * @emits Chain#exists
 * @emits Chain#purge
 * @emits Chain#connect
 * @emits Chain#reconnect
 * @emits Chain#disconnect
 */

function Chain(options) {
  if (!(this instanceof Chain))
    return new Chain(options);

  AsyncObject.call(this);

  if (!options)
    options = {};

  this.options = options;

  this.network = bcoin.network.get(options.network);
  this.logger = options.logger || bcoin.defaultLogger;
  this.db = new bcoin.chaindb(this);
  this.total = 0;
  this.currentBlock = null;
  this.orphanLimit = options.orphanLimit || (20 << 20);
  this.locker = new bcoin.locker(this, this.add);
  this.invalid = {};
  this.bestHeight = -1;
  this.tip = null;
  this.height = -1;
  this.synced = false;
  this.state = new DeploymentState();
  this.stateCache = {};
  this._time = utils.hrtime();

  this.orphan = {
    map: {},
    bmap: {},
    count: 0,
    size: 0
  };

  this._init();
}

utils.inherits(Chain, AsyncObject);

/**
 * Initialize the chain.
 * @private
 */

Chain.prototype._init = function _init() {
  var self = this;
  var keys = Object.keys(this.network.deployments);
  var i, id;

  // Setup state caches.
  for (i = 0; i < keys.length; i++) {
    id = keys[i];
    this.stateCache[id] = {};
  }

  this.locker.on('purge', function(total, size) {
    self.logger.warning('Warning: %dmb of pending objects. Purging.', utils.mb(size));
  });

  this.on('competitor', function(block, entry) {
    self.logger.warning('Heads up: Competing chain at height %d:'
      + ' tip-height=%d competitor-height=%d'
      + ' tip-hash=%s competitor-hash=%s'
      + ' tip-chainwork=%s competitor-chainwork=%s'
      + ' chainwork-diff=%s',
      entry.height,
      self.tip.height,
      entry.height,
      self.tip.rhash,
      entry.rhash,
      self.tip.chainwork.toString(),
      entry.chainwork.toString(),
      self.tip.chainwork.sub(entry.chainwork).toString());
  });

  this.on('resolved', function(block, entry) {
    self.logger.debug('Orphan %s (%d) was resolved.',
      block.rhash, entry.height);
  });

  this.on('checkpoint', function(block, height) {
    self.logger.debug('Hit checkpoint block %s (%d).',
      block.rhash, height);
  });

  this.on('fork', function(block, height, expected) {
    self.logger.warning(
      'Fork at height %d: expected=%s received=%s',
      height,
      utils.revHex(expected),
      block.rhash
    );
  });

  this.on('reorganize', function(block, height, expected) {
    self.logger.warning(
      'Reorg at height %d: old=%s new=%s',
      height,
      utils.revHex(expected),
      block.rhash
    );
  });

  this.on('invalid', function(block, height) {
    self.logger.warning('Invalid block at height %d: hash=%s',
      height, block.rhash);
  });

  this.on('exists', function(block, height) {
    self.logger.debug('Already have block %s (%d).', block.rhash, height);
  });

  this.on('orphan', function(block, height) {
    self.logger.debug('Handled orphan %s (%d).', block.rhash, height);
  });

  this.on('purge', function(count, size) {
    self.logger.debug('Warning: %d (%dmb) orphans cleared!',
      count, utils.mb(size));
  });
};

/**
 * Open the chain, wait for the database to load.
 * @alias Chain#open
 * @param {Function} callback
 */

Chain.prototype._open = function open(callback) {
  var self = this;

  this.logger.info('Chain is loading.');

  if (this.options.useCheckpoints)
    this.logger.info('Checkpoints are enabled.');

  if (this.options.coinCache)
    this.logger.info('Coin cache is enabled.');

  this.db.open(function(err) {
    if (err)
      return callback(err);

    self.db.getTip(function(err, tip) {
      if (err)
        return callback(err);

      assert(tip);

      self.tip = tip;
      self.height = tip.height;

      self.logger.info('Chain Height: %d', tip.height);

      if (tip.height > self.bestHeight) {
        self.bestHeight = tip.height;
        self.network.updateHeight(tip.height);
      }

      self.logger.memory();

      self.getDeploymentState(function(err, state) {
        if (err)
          return callback(err);

        self.state = state;

        self.logger.memory();

        self.emit('tip', tip);

        if (!self.synced && self.isFull()) {
          self.synced = true;
          self.emit('full');
        }

        callback();
      });
    });
  });
};

/**
 * Close the chain, wait for the database to close.
 * @alias Chain#close
 * @param {Function} callback
 */

Chain.prototype._close = function close(callback) {
  this.db.close(callback);
};

/**
 * Invoke mutex lock.
 * @private
 * @returns {Function} unlock
 */

Chain.prototype._lock = function _lock(func, args, force) {
  return this.locker.lock(func, args, force);
};

/**
 * Perform all necessary contextual verification on a block.
 * @private
 * @param {Block|MerkleBlock} block
 * @param {ChainEntry} entry
 * @param {Function} callback - Returns [{@link VerifyError}].
 */

Chain.prototype.verifyContext = function verifyContext(block, prev, callback) {
  var self = this;

  this.verify(block, prev, function(err, state) {
    if (err)
      return callback(err);

    self.checkDuplicates(block, prev, function(err) {
      if (err)
        return callback(err);

      self.checkInputs(block, prev, state, function(err, view) {
        if (err)
          return callback(err);

        // Expose the state globally.
        self.state = state;

        callback(null, view);
      });
    });
  });
};

/**
 * Test whether a block is the genesis block.
 * @param {Block} block
 * @returns {Boolean}
 */

Chain.prototype.isGenesis = function isGenesis(block) {
  return block.hash('hex') === this.network.genesis.hash;
};

/**
 * Contextual verification for a block, including
 * version deployments (IsSuperMajority), versionbits,
 * coinbase height, finality checks.
 * @private
 * @param {Block|MerkleBlock} block
 * @param {ChainEntry} entry
 * @param {Function} callback - Returns
 * [{@link VerifyError}, {@link VerifyFlags}].
 */

Chain.prototype.verify = function verify(block, prev, callback) {
  var self = this;
  var ret = new VerifyResult();
  var i, height, ts, tx, medianTime, commitmentHash;

  if (!block.verify(ret)) {
    return callback(new VerifyError(block,
      'invalid',
      ret.reason,
      ret.score));
  }

  // Skip the genesis block. Skip all blocks in spv mode.
  if (this.options.spv || this.isGenesis(block))
    return callback(null, this.state);

  // Ensure it's not an orphan
  if (!prev) {
    return callback(new VerifyError(block,
      'invalid',
      'bad-prevblk',
      0));
  }

  if (prev.isHistorical())
    return callback(null, this.state);

  prev.getRetargetAncestors(function(err, ancestors) {
    if (err)
      return callback(err);

    height = prev.height + 1;
    medianTime = prev.getMedianTime(ancestors);

    // Ensure the timestamp is correct
    if (block.ts <= medianTime) {
      return callback(new VerifyError(block,
        'invalid',
        'time-too-old',
        0));
    }

    if (block.bits !== self.getTarget(block, prev, ancestors)) {
      return callback(new VerifyError(block,
        'invalid',
        'bad-diffbits',
        100));
    }

    self.getDeployments(block, prev, ancestors, function(err, state) {
      if (err)
        return callback(err);

      // Can't verify any further when merkleblock or headers.
      if (self.options.spv)
        return callback(null, state);

      // Make sure the height contained in the coinbase is correct.
      if (state.hasBIP34()) {
        if (block.getCoinbaseHeight() !== height) {
          return callback(new VerifyError(block,
            'invalid',
            'bad-cb-height',
            100));
        }
      }

      // Check the commitment hash for segwit.
      if (state.hasWitness()) {
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
      // witness data cannot contain it.
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
      ts = state.hasMTP() ? medianTime : block.ts;

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

      callback(null, state);
    });
  });
};

/**
 * Check all deployments on a chain, ranging from p2sh to segwit.
 * @param {Block} block
 * @param {ChainEntry} prev
 * @param {ChainEntry[]} ancestors
 * @param {Function} callback - Returns
 * [{@link VerifyError}, {@link DeploymentState}].
 */

Chain.prototype.getDeployments = function getDeployments(block, prev, ancestors, callback) {
  var self = this;
  var state = new DeploymentState();

  // For some reason bitcoind has p2sh in the
  // mandatory flags by default, when in reality
  // it wasn't activated until march 30th 2012.
  // The first p2sh output and redeem script
  // appeared on march 7th 2012, only it did
  // not have a signature. See:
  // 6a26d2ecb67f27d1fa5524763b49029d7106e91e3cc05743073461a719776192
  // 9c08a4d78931342b37fd5f72900fb9983087e6f46c4a097d8a1f52c74e28eaf6
  if (block.ts >= constants.block.BIP16_TIME) {
    state.flags |= constants.flags.VERIFY_P2SH;
    if (!this.state.hasP2SH())
      this.logger.warning('P2SH has been activated.');
  }

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
  if (this.options.witness && this.network.oldWitness) {
    if (block.version < 5 && prev.isOutdated(5, ancestors))
      return callback(new VerifyError(block, 'obsolete', 'bad-version', 0));
  }

  // Make sure the height contained in the coinbase is correct.
  if (block.version >= 2 && prev.isUpgraded(2, ancestors)) {
    state.bip34 = true;
    if (!this.state.hasBIP34())
      this.logger.warning('BIP34 has been activated.');
  }

  // Signature validation is now enforced (bip66)
  if (block.version >= 3 && prev.isUpgraded(3, ancestors)) {
    state.flags |= constants.flags.VERIFY_DERSIG;
    if (!this.state.hasBIP66())
      this.logger.warning('BIP66 has been activated.');
  }

  // CHECKLOCKTIMEVERIFY is now usable (bip65)
  if (block.version >= 4 && prev.isUpgraded(4, ancestors)) {
    state.flags |= constants.flags.VERIFY_CHECKLOCKTIMEVERIFY;
    if (!this.state.hasCLTV())
      this.logger.warning('BIP65 has been activated.');
  }

  // Segregrated witness is now usable (bip141 - segnet3)
  if (this.options.witness && this.network.oldWitness) {
    if (block.version >= 5 && prev.isUpgraded(5, ancestors)) {
      state.flags |= constants.flags.VERIFY_WITNESS;
      if (!this.state.hasWitness())
        this.logger.warning('Segwit has been activated.');
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
          if (!self.state.hasCSV())
            self.logger.warning('CSV has been activated.');
        }

        next();
      });
    },
    function(next) {
      if (self.network.oldWitness)
        return next();

      // Segregrated witness is now usable (bip141 - segnet4)
      self.isActive(prev, 'witness', function(err, active) {
        if (err)
          return next(err);

        if (active && self.options.witness) {
          state.flags |= constants.flags.VERIFY_WITNESS;
          if (!self.state.hasWitness())
            self.logger.warning('Segwit has been activated.');
        }

        next();
      });
    }
  ], function(err) {
    if (err)
      return callback(err);

    callback(null, state);
  });
};

/**
 * Determine whether to check block for duplicate txids in blockchain
 * history (BIP30). If we're on a chain that has bip34 activated, we
 * can skip this.
 * @private
 * @see https://github.com/bitcoin/bips/blob/master/bip-0030.mediawiki
 * @param {Block|MerkleBlock} block
 * @param {ChainEntry} prev
 * @param {Function} callback - Returns [{@link VerifyError}].
 */

Chain.prototype.checkDuplicates = function checkDuplicates(block, prev, callback) {
  var self = this;
  var height = prev.height + 1;

  if (this.options.spv)
    return callback();

  if (this.isGenesis(block))
    return callback();

  if (prev.isHistorical())
    return callback();

  if (this.network.block.bip34height === -1
      || height <= this.network.block.bip34height) {
    return this.findDuplicates(block, prev, callback);
  }

  this.db.get(this.network.block.bip34height, function(err, entry) {
    if (err)
      return callback(err);

    // It was no longer possible to create duplicate
    // TXs once bip34 went into effect. We can check
    // for this to avoid a DB lookup.
    if (entry && entry.hash === self.network.block.bip34hash)
      return callback();

    self.findDuplicates(block, prev, callback);
  });
};

/**
 * Check block for duplicate txids in blockchain
 * history (BIP30). Note that txids are only considered
 * duplicate if they are not yet completely spent.
 * @private
 * @see https://github.com/bitcoin/bips/blob/master/bip-0030.mediawiki
 * @param {Block|MerkleBlock} block
 * @param {ChainEntry} prev
 * @param {Function} callback - Returns [{@link VerifyError}].
 */

Chain.prototype.findDuplicates = function findDuplicates(block, prev, callback) {
  var self = this;
  var height = prev.height + 1;

  // Check all transactions
  utils.forEachSerial(block.txs, function(tx, next) {
    // BIP30 - Ensure there are no duplicate txids
    self.db.hasCoins(tx.hash(), function(err, result) {
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
 * @param {ChainEntry} prev
 * @param {DeploymentState} state
 * @param {Function} callback - Returns [{@link VerifyError}].
 */

Chain.prototype.checkInputs = function checkInputs(block, prev, state, callback) {
  var self = this;
  var height = prev.height + 1;
  var historical = prev.isHistorical();
  var sigops = 0;
  var ret = new VerifyResult();

  if (this.options.spv)
    return callback();

  if (this.isGenesis(block))
    return callback();

  this.db.getCoinView(block, function(err, view) {
    if (err)
      return callback(err);

    // Check all transactions
    utils.forEachSerial(block.txs, function(tx, next) {
      // Ensure tx is not double spending an output.
      if (!tx.isCoinbase()) {
        if (!view.fillCoins(tx)) {
          assert(!historical, 'BUG: Spent inputs in historical data!');
          return next(new VerifyError(block,
            'invalid',
            'bad-txns-inputs-missingorspent',
            100));
        }
      }

      // Skip everything if we're
      // using checkpoints.
      if (historical) {
        view.addTX(tx);
        return next();
      }

      // Verify sequence locks.
      self.checkLocks(prev, tx, state.lockFlags, function(err, valid) {
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

        // Add new coins.
        view.addTX(tx);

        next();
      });
    }, function(err) {
      if (err)
        return callback(err);

      if (historical)
        return callback(null, view);

      // Verify all txs in parallel.
      utils.every(block.txs, function(tx, next) {
        tx.verifyAsync(state.flags, next);
      }, function(err, verified) {
        if (err)
          return callback(err);

        if (!verified) {
          return callback(new VerifyError(block,
            'invalid',
            'mandatory-script-verify-flag-failed',
            100));
        }

        // Make sure the miner isn't trying to conjure more coins.
        if (block.getClaimed() > block.getReward(self.network)) {
          return callback(new VerifyError(block,
            'invalid',
            'bad-cb-amount',
            100));
        }

        callback(null, view);
      });
    });
  });
};

/**
 * Get the cached height for a hash if present.
 * @private
 * @param {Hash} hash
 * @returns {Number}
 */

Chain.prototype._getCachedHeight = function _getCachedHeight(hash) {
  if (this.db.hasCache(hash))
    return this.db.getCache(hash).height;

  return -1;
};

/**
 * Find the block at which a fork ocurred.
 * @private
 * @param {ChainEntry} fork - The current chain.
 * @param {ChainEntry} longer - The competing chain.
 * @param {Function} callback - Returns [{@link Error}, {@link ChainEntry}].
 */

Chain.prototype.findFork = function findFork(fork, longer, callback) {
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
 * @param {ChainEntry} entry - The competing chain's tip.
 * @param {Block|MerkleBlock} block - The being being added.
 * @param {Function} callback
 */

Chain.prototype.reorganize = function reorganize(entry, block, callback) {
  var self = this;
  var tip = this.tip;

  this.findFork(tip, entry, function(err, fork) {
    if (err)
      return callback(err);

    assert(fork);

    // Disconnect blocks/txs.
    function disconnect(callback) {
      var entries = [];

      (function collect(entry) {
        if (entry.hash === fork.hash)
          return finish();

        entries.push(entry);

        entry.getPrevious(function(err, entry) {
          if (err)
            return callback(err);

          assert(entry);

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
    function reconnect(callback) {
      var entries = [];

      (function collect(entry) {
        if (entry.hash === fork.hash)
          return finish();

        entries.push(entry);

        entry.getPrevious(function(err, entry) {
          if (err)
            return callback(err);

          assert(entry);

          collect(entry);
        });
      })(entry);

      function finish() {
        entries = entries.slice().reverse();

        // We don't want to connect the new tip here.
        // That will be done outside in setBestChain.
        entries.pop();

        utils.forEachSerial(entries, function(entry, next) {
          self.reconnect(entry, next);
        }, callback);
      }
    }

    disconnect(function(err) {
      if (err)
        return callback(err);

      reconnect(function(err) {
        if (err)
          return callback(err);

        self.emit('reorganize', block, tip.height, tip.hash);

        callback();
      });
    });
  });
};

/**
 * Disconnect an entry from the chain (updates the tip).
 * @param {ChainEntry} entry
 * @param {Function} callback
 */

Chain.prototype.disconnect = function disconnect(entry, callback) {
  var self = this;

  this.db.disconnect(entry, function(err, entry, block) {
    if (err)
      return callback(err);

    entry.getPrevious(function(err, prev) {
      if (err)
        return callback(err);

      assert(prev);

      self.tip = prev;
      self.height = prev.height;

      self.bestHeight = prev.height;
      self.network.updateHeight(prev.height);

      self.emit('tip', prev);
      self.emit('disconnect', entry, block);

      callback();
    });
  });
};

/**
 * Reconnect an entry to the chain (updates the tip).
 * This will do contextual-verification on the block
 * (necessary because we cannot validate the inputs
 * in alternate chains when they come in).
 * @param {ChainEntry} entry
 * @param {Function} callback
 */

Chain.prototype.reconnect = function reconnect(entry, callback) {
  var self = this;

  this.db.getBlock(entry.hash, function(err, block) {
    if (err)
      return callback(err);

    if (!block) {
      assert(self.options.spv);
      block = entry.toHeaders();
    }

    entry.getPrevious(function(err, prev) {
      if (err)
        return callback(err);

      assert(prev);

      self.verifyContext(block, prev, function(err, view) {
        if (err) {
          if (err.type === 'VerifyError') {
            self.invalid[entry.hash] = true;
            self.emit('invalid', block, entry.height);
          }
          return callback(err);
        }

        self.db.reconnect(entry, block, view, function(err) {
          if (err)
            return callback(err);

          self.tip = entry;
          self.height = entry.height;

          self.bestHeight = entry.height;
          self.network.updateHeight(entry.height);

          self.emit('tip', entry);
          self.emit('reconnect', entry, block);
          self.emit('connect', entry, block);

          callback();
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
 * @param {ChainEntry} entry
 * @param {Block|MerkleBlock} block
 * @param {ChainEntry} prev
 * @param {Function} callback - Returns [{@link VerifyError}].
 */

Chain.prototype.setBestChain = function setBestChain(entry, block, prev, callback) {
  var self = this;

  function done(err) {
    if (err)
      return callback(err);

    // Do "contextual" verification on our block
    // now that we're certain its previous
    // block is in the chain.
    self.verifyContext(block, prev, function(err, view) {
      if (err) {
        // Couldn't verify block.
        // Revert the height.
        block.setHeight(-1);

        if (err.type === 'VerifyError') {
          self.invalid[entry.hash] = true;
          self.emit('invalid', block, entry.height);
        }

        return callback(err);
      }

      // Save block and connect inputs.
      self.db.save(entry, block, view, true, function(err) {
        if (err)
          return callback(err);

        self.tip = entry;
        self.height = entry.height;

        self.emit('tip', entry);

        callback();
      });
    });
  }

  // We don't have a genesis block yet.
  if (!this.tip) {
    if (entry.hash !== this.network.genesis.hash) {
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
  this.logger.warning('WARNING: Reorganizing chain.');
  this.reorganize(entry, block, done);
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

  callback = this._lock(reset, [height, callback], force);

  if (!callback)
    return;

  this.db.reset(height, function(err, result) {
    if (err)
      return callback(err);

    // Reset the orphan map completely. There may
    // have been some orphans on a forked chain we
    // no longer need.
    self.purgeOrphans();

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

Chain.prototype.resetTime = function resetTime(ts, callback) {
  var self = this;

  callback = this._lock(resetTime, [ts, callback]);

  if (!callback)
    return;

  this.byTime(ts, function(err, entry) {
    if (err)
      return callback(err);

    if (!entry)
      return callback();

    self.reset(entry.height, callback, true);
  }, true);
};

/**
 * Wait for the chain to drain (finish processing
 * all of the blocks in its queue).
 * @param {Function} callback
 */

Chain.prototype.onDrain = function onDrain(callback) {
  this.locker.onDrain(callback);
};

/**
 * Test whether the chain is in the process of adding blocks.
 * @returns {Boolean}
 */

Chain.prototype.isBusy = function isBusy() {
  if (this.currentBlock)
    return true;
  return this.locker.pending.length > 0;
};

/**
 * Add a block to the chain, perform all necessary verification.
 * @param {Block|MerkleBlock|MemBlock} block
 * @param {Function} callback - Returns [{@link VerifyError}].
 */

Chain.prototype.add = function add(block, callback) {
  var self = this;
  var ret;

  assert(this.loaded);

  callback = this._lock(add, [block, callback]);

  if (!callback)
    return;

  ret = new VerifyResult();

  (function next(block, initial) {
    var hash = block.hash('hex');
    var prevBlock = block.prevBlock;
    var height, checkpoint, orphan, entry;

    self.currentBlock = hash;
    self._mark();

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
    if (self.invalid[hash] || self.invalid[prevBlock]) {
      self.emit('invalid', block, block.getCoinbaseHeight());
      self.invalid[hash] = true;
      return done(new VerifyError(block, 'duplicate', 'duplicate', 100));
    }

    // Do we already have this block?
    if (self.hasPending(hash)) {
      self.emit('exists', block, block.getCoinbaseHeight());
      return done(new VerifyError(block, 'duplicate', 'duplicate', 0));
    }

    // If the block is already known to be
    // an orphan, ignore it.
    orphan = self.orphan.map[prevBlock];
    if (orphan) {
      // The orphan chain forked.
      if (orphan.hash('hex') !== hash) {
        self.emit('fork', block,
          block.getCoinbaseHeight(),
          orphan.hash('hex'));
      }

      self.emit('orphan', block, block.getCoinbaseHeight());

      return done(new VerifyError(block, 'invalid', 'bad-prevblk', 0));
    }

    // Special case for genesis block.
    if (self.isGenesis(block))
      return done();

    // Validate the block we want to add.
    // This is only necessary for new
    // blocks coming in, not the resolving
    // orphans.
    if (initial && !block.verify(ret)) {
      self.invalid[hash] = true;
      self.emit('invalid', block, block.getCoinbaseHeight());
      return done(new VerifyError(block, 'invalid', ret.reason, ret.score));
    }

    self.db.has(hash, function(err, existing) {
      if (err)
        return done(err);

      // Do we already have this block?
      if (existing) {
        self.emit('exists', block, block.getCoinbaseHeight());
        return done(new VerifyError(block, 'duplicate', 'duplicate', 0));
      }

      // Find the previous block height/index.
      self.db.get(prevBlock, function(err, prev) {
        if (err)
          return done(err);

        height = !prev ? -1 : prev.height + 1;

        if (height > self.bestHeight) {
          self.bestHeight = height;
          self.network.updateHeight(height);
        }

        // If previous block wasn't ever seen,
        // add it current to orphans and break.
        if (!prev) {
          self.orphan.count++;
          self.orphan.size += block.getSize();
          self.orphan.map[prevBlock] = block;
          self.orphan.bmap[hash] = block;

          // Update the best height based on the coinbase.
          // We do this even for orphans (peers will send
          // us their highest block during the initial
          // getblocks sync, making it an orphan).
          if (block.getCoinbaseHeight() > self.bestHeight) {
            self.bestHeight = block.getCoinbaseHeight();
            self.network.updateHeight(self.bestHeight);
          }

          self.emit('orphan', block, block.getCoinbaseHeight());

          return done(new VerifyError(block, 'invalid', 'bad-prevblk', 0));
        }

        // Verify the checkpoint.
        if (self.options.useCheckpoints) {
          checkpoint = self.network.checkpoints[height];
          if (checkpoint) {
            // Someone is very likely trying to fool us.
            if (hash !== checkpoint) {
              self.purgeOrphans();

              self.emit('fork', block, height, checkpoint);

              return done(new VerifyError(block,
                'checkpoint',
                'checkpoint mismatch',
                100));
            }

            self.emit('checkpoint', block, height);
          }
        }

        // Explanation: we try to keep as much data
        // off the javascript heap as possible. Blocks
        // in the future may be 8mb or 20mb, who knows.
        // In fullnode-mode we store the blocks in
        // "compact" form (the headers plus the raw
        // Buffer object) until they're ready to be
        // fully validated here. They are deserialized,
        // validated, and emitted. Hopefully the deserialized
        // blocks get cleaned up by the GC quickly.
        if (block.memory) {
          try {
            block = block.toBlock();
          } catch (e) {
            self.logger.error(e);
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
        entry = bcoin.chainentry.fromBlock(self, block, prev);

        // The block is on a alternate chain if the
        // chainwork is less than or equal to
        // our tip's. Add the block but do _not_
        // connect the inputs.
        if (entry.chainwork.cmp(self.tip.chainwork) <= 0) {
          return self.db.save(entry, block, null, false, function(err) {
            if (err)
              return done(err);

            // Keep track of stats.
            self._done(block, entry);

            // Emit our block (and potentially resolved
            // orphan) only if it is on the main chain.
            self.emit('competitor', block, entry);

            if (!initial)
              self.emit('competitor resolved', block, entry);

            handleOrphans();
          });
        }

        // Attempt to add block to the chain index.
        self.setBestChain(entry, block, prev, function(err) {
          if (err)
            return done(err);

          // Keep track of stats.
          self._done(block, entry);

          // Emit our block (and potentially resolved
          // orphan) only if it is on the main chain.
          self.emit('block', block, entry);
          self.emit('connect', entry, block);

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

    utils.nextTick(function() {
      if (!self.synced && self.isFull()) {
        self.synced = true;
        self.emit('full');
      }

      self.currentBlock = null;

      callback(err);
    });
  }
};

/**
 * Test whether the chain has reached its slow height.
 * @private
 * @returns {Boolean}
 */

Chain.prototype._isSlow = function _isSlow() {
  if (this.options.spv)
    return false;

  if (this.total === 1 || this.total % 20 === 0)
    return true;

  return this.synced || this.height >= this.network.block.slowHeight;
};

/**
 * Mark the start time for block processing.
 * @private
 */

Chain.prototype._mark = function _mark() {
  this._time = utils.hrtime();
};

/**
 * Calculate the time difference from
 * start time and log block.
 * @private
 * @param {Block} block
 * @param {ChainEntry} entry
 */

Chain.prototype._done = function _done(block, entry) {
  var elapsed, time;

  // Keep track of total blocks handled.
  this.total += 1;

  if (!this._isSlow())
    return;

  // Report memory for debugging.
  utils.gc();
  this.logger.memory();

  elapsed = utils.hrtime(this._time);
  time = elapsed[0] * 1000 + elapsed[1] / 1e6;

  this.logger.info(
    'Block %s (%d) added to chain (size=%d, txs=%d time=%d).',
    entry.rhash,
    entry.height,
    block.getSize(),
    block.txs.length,
    time);
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
  var i, hashes, hash, orphan, height, best, last;

  hashes = Object.keys(this.orphan.map);

  if (hashes.length === 0)
    return;

  for (i = 0; i < hashes.length; i++) {
    hash = hashes[i];
    orphan = this.orphan.map[hash];
    height = orphan.getCoinbaseHeight();

    delete this.orphan.map[hash];

    if (!best || height > best.getCoinbaseHeight())
      best = orphan;

    last = orphan;
  }

  // Save the best for last... or the
  // last for best in this case.
  if (best.getCoinbaseHeight() <= 0)
    best = last;

  hashes = Object.keys(this.orphan.bmap);

  for (i = 0; i < hashes.length; i++) {
    hash = hashes[i];
    orphan = this.orphan.bmap[hash];

    delete this.orphan.bmap[hash];

    if (orphan !== best)
      this.emit('unresolved', orphan);
  }

  this.emit('purge',
    this.orphan.count - 1,
    this.orphan.size - best.getSize());

  this.orphan.map[best.prevBlock] = best;
  this.orphan.bmap[best.hash('hex')] = best;
  this.orphan.count = 1;
  this.orphan.size = best.getSize();
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

  if (hash === this.currentBlock)
    return callback(null, true);

  this.hasBlock(hash, callback);
};

/**
 * Find a block entry by timestamp.
 * @param {Number} ts - Timestamp.
 * @param {Function} callback - Returns [Error, {@link ChainEntry}].
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
  this.db.has(hash, callback);
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
 * @param {Function} callback - Returns [Error, {@link ChainEntry}].
 */

Chain.prototype.getEntry = function getEntry(hash, callback) {
  this.db.get(hash, callback);
};

/**
 * Get an orphan block.
 * @param {Hash} hash
 * @returns {Block|MerkleBlock|MemBlock}
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

  if (this.height < this.network.checkpoints.lastHeight)
    return true;

  return this.height < this.bestHeight - 24 * 6
    || this.tip.ts < utils.now() - this.network.block.maxTipAge;
};

/**
 * Get the fill percentage.
 * @returns {Number} percent - Ranges from 0.0 to 1.0.
 */

Chain.prototype.getProgress = function getProgress() {
  var start, current, end;

  if (!this.tip)
    return 0;

  start = this.network.genesis.ts;
  current = this.tip.ts - start;
  end = utils.now() - start - 40 * 60;

  return Math.min(1, current / end);
};

/**
 * Calculate chain locator (an array of hashes).
 * @param {(Number|Hash)?} start - Height or hash to treat as the tip.
 * The current tip will be used if not present. Note that this can be a
 * non-existent hash, which is useful for headers-first locators.
 * @param {Function} callback - Returns [Error, {@link Hash}[]].
 */

Chain.prototype.getLocator = function getLocator(start, callback) {
  var self = this;
  var hashes = [];
  var step = 1;
  var height;

  callback = this._lock(getLocator, [start, callback]);

  if (!callback)
    return;

  if (start == null)
    start = this.tip.hash;

  this.db.get(start, function(err, entry) {
    if (err)
      return callback(err);

    if (!entry) {
      // We could simply return `start` here,
      // but there is no required "spacing"
      // for locator hashes. Pretend this hash
      // is our tip. This is useful for
      // getheaders.
      if (typeof start === 'string')
        hashes.push(start);
      entry = self.tip;
    }

    height = entry.height;

    entry.isMainChain(function(err, main) {
      if (err)
        return callback(err);

      (function next(err, hash) {
        if (err)
          return callback(err);

        if (!hash)
          return callback(null, hashes);

        hashes.push(hash);

        if (height === 0)
          return callback(null, hashes);

        height = Math.max(height - step, 0);

        if (hashes.length > 10)
          step *= 2;

        if (height === 0)
          return next(null, self.network.genesis.hash);

        // If we're on the main chain, we can
        // do a fast lookup of the hash.
        if (main)
          return self.db.getHash(height, next);

        entry.getAncestorByHeight(height, function(err, entry) {
          if (err)
            return callback(err);

          if (!entry)
            return next();

          next(null, entry.hash);
        });
      })(null, entry.hash);
    });
  });
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

  return root;
};

/**
 * Calculate the next target based on the chain tip.
 * @param {Function} callback - returns [Error, Number]
 * (target is in compact/mantissa form).
 */

Chain.prototype.getCurrentTarget = function getCurrentTarget(callback) {
  if (!this.tip)
    return callback(null, this.network.pow.bits);
  this.getTargetAsync(null, this.tip, callback);
};

/**
 * Calculate the target based on the passed-in chain entry.
 * @param {ChainEntry} prev - Previous entry.
 * @param {Block|MerkleBlock|null} - Current block.
 * @param {Function} callback - returns [Error, Number]
 * (target is in compact/mantissa form).
 */

Chain.prototype.getTargetAsync = function getTargetAsync(block, prev, callback) {
  var self = this;

  if ((prev.height + 1) % this.network.pow.retargetInterval !== 0) {
    if (!this.network.pow.difficultyReset)
      return utils.asyncify(callback)(null, this.getTarget(block, prev));
  }

  prev.getAncestors(this.network.pow.retargetInterval, function(err, ancestors) {
    if (err)
      return callback(err);

    callback(null, self.getTarget(block, prev, ancestors));
  });
};

/**
 * Calculate the target synchronously. _Must_
 * have ancestors pre-allocated.
 * @param {Block|MerkleBlock|null} - Current block.
 * @param {ChainEntry} prev - Previous entry.
 * @param {Function} callback - returns [Error, Number]
 * (target is in compact/mantissa form).
 */

Chain.prototype.getTarget = function getTarget(block, prev, ancestors) {
  var ts, first, i;

  // Genesis
  if (!prev)
    return this.network.pow.bits;

  // Do not retarget
  if ((prev.height + 1) % this.network.pow.retargetInterval !== 0) {
    if (this.network.pow.difficultyReset) {
      // Special behavior for testnet:
      ts = block ? (block.ts || block) : bcoin.now();
      if (ts > prev.ts + this.network.pow.targetSpacing * 2)
        return this.network.pow.bits;

      i = 1;
      while (ancestors[i]
        && prev.height % this.network.pow.retargetInterval !== 0
        && prev.bits === this.network.pow.bits) {
        prev = ancestors[i++];
      }
    }
    return prev.bits;
  }

  // Back 2 weeks
  first = ancestors[this.network.pow.retargetInterval - 1];

  assert(first);

  return this.retarget(prev, first);
};

/**
 * Retarget. This is called when the chain height
 * hits a retarget diff interval.
 * @param {ChainEntry} prev - Previous entry.
 * @param {ChainEntry} first - Chain entry from 2 weeks prior.
 * @returns {Number} target - Target in compact/mantissa form.
 */

Chain.prototype.retarget = function retarget(prev, first) {
  var targetTimespan = this.network.pow.targetTimespan;
  var actualTimespan, target;

  if (this.network.pow.noRetargeting)
    return prev.bits;

  actualTimespan = prev.ts - first.ts;
  target = utils.fromCompact(prev.bits);

  if (actualTimespan < targetTimespan / 4)
    actualTimespan = targetTimespan / 4;

  if (actualTimespan > targetTimespan * 4)
    actualTimespan = targetTimespan * 4;

  target.imuln(actualTimespan);
  target.idivn(targetTimespan);

  if (target.cmp(this.network.pow.limit) > 0)
    return this.network.pow.bits;

  return utils.toCompact(target);
};

/**
 * Find a locator. Analagous to bitcoind's `FindForkInGlobalIndex()`.
 * @param {Hash[]} locator - Hashes.
 * @param {Function} callback - Returns [Error, {@link Hash}] (the
 * hash of the latest known block).
 */

Chain.prototype.findLocator = function findLocator(locator, callback) {
  var self = this;

  utils.forEachSerial(locator, function(hash, next) {
    self.db.isMainChain(hash, function(err, result) {
      if (err)
        return next(err);

      if (result)
        return callback(null, hash);

      next();
    });
  }, function(err) {
    if (err)
      return callback(err);

    callback(null, self.network.genesis.hash);
  });
};

/**
 * Check whether a versionbits deployment is active (BIP9: versionbits).
 * @example
 * chain.isActive(entry, 'witness', callback);
 * @see https://github.com/bitcoin/bips/blob/master/bip-0009.mediawiki
 * @param {ChainEntry} prev - Previous chain entry.
 * @param {String} id - Deployment id.
 * @param {Function} callback - Returns [Error, Number].
 */

Chain.prototype.isActive = function isActive(prev, id, callback) {
  if (prev.isHistorical())
    return callback(null, false);

  this.getState(prev, id, function(err, state) {
    if (err)
      return callback(err);

    callback(null, state === constants.thresholdStates.ACTIVE);
  });
};

/**
 * Get chain entry state for a deployment (BIP9: versionbits).
 * @example
 * chain.getState(entry, 'witness', callback);
 * @see https://github.com/bitcoin/bips/blob/master/bip-0009.mediawiki
 * @param {ChainEntry} prev - Previous chain entry.
 * @param {String} id - Deployment id.
 * @param {Function} callback - Returns [Error, Number].
 */

Chain.prototype.getState = function getState(prev, id, callback) {
  var self = this;
  var period = this.network.minerWindow;
  var threshold = this.network.activationThreshold;
  var deployment = this.network.deployments[id];
  var stateCache = this.stateCache[id];
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

      self.getState(ancestor, id, callback);
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

    if (stateCache[entry.hash] != null)
      return walkForward(stateCache[entry.hash]);

    entry.getMedianTimeAsync(function(err, medianTime) {
      if (err)
        return walk(err);

      if (medianTime < timeStart)
        return walkForward(constants.thresholdStates.DEFINED);

      compute.push(entry);

      height = entry.height - period;

      entry.getAncestorByHeight(height, walk);
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
            stateCache[entry.hash] = constants.thresholdStates.FAILED;
            return walkForward(constants.thresholdStates.FAILED);
          }

          if (medianTime >= timeStart) {
            stateCache[entry.hash] = constants.thresholdStates.STARTED;
            return walkForward(constants.thresholdStates.STARTED);
          }

          stateCache[entry.hash] = state;
          return walkForward(state);
        });
      case constants.thresholdStates.STARTED:
        return entry.getMedianTimeAsync(function(err, medianTime) {
          if (err)
            return callback(err);

          if (medianTime >= timeTimeout) {
            stateCache[entry.hash] = constants.thresholdStates.FAILED;
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

            entry.getPrevious(next);
          })(null, entry);

          function doneCounting(err) {
            if (err)
              return callback(err);

            if (count >= threshold) {
              stateCache[entry.hash] = constants.thresholdStates.LOCKED_IN;
              return walkForward(constants.thresholdStates.LOCKED_IN);
            }

            stateCache[entry.hash] = state;
            return walkForward(state);
          }
        });
      case constants.thresholdStates.LOCKED_IN:
        stateCache[entry.hash] = constants.thresholdStates.ACTIVE;
        return walkForward(constants.thresholdStates.ACTIVE);
      case constants.thresholdStates.FAILED:
      case constants.thresholdStates.ACTIVE:
        stateCache[entry.hash] = state;
        return walkForward(state);
      default:
        assert(false, 'Bad state.');
        break;
    }
  }
};

/**
 * Compute the version for a new block (BIP9: versionbits).
 * @see https://github.com/bitcoin/bips/blob/master/bip-0009.mediawiki
 * @param {ChainEntry} prev - Previous chain entry (usually the tip).
 * @param {Function} callback - Returns [Error, Number].
 */

Chain.prototype.computeBlockVersion = function computeBlockVersion(prev, callback) {
  var self = this;
  var keys = Object.keys(this.network.deployments);
  var version = 0;

  utils.forEachSerial(keys, function(id, next) {
    var deployment = self.network.deployments[id];
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

    version |= constants.versionbits.TOP_BITS;
    version >>>= 0;

    callback(null, version);
  });
};

/**
 * Get the current deployment state of the chain. Called on load.
 * @private
 * @param {Function} callback - Returns [Error, {@link DeploymentState}].
 */

Chain.prototype.getDeploymentState = function getDeploymentState(callback) {
  var self = this;

  if (!this.tip)
    return callback(null, this.state);

  this.tip.getPrevious(function(err, prev) {
    if (err)
      return callback(err);

    if (!prev)
      return callback(null, self.state);

    prev.getRetargetAncestors(function(err, ancestors) {
      if (err)
        return callback(err);

      self.getDeployments(self.tip, prev, ancestors, callback);
    });
  });
};

/**
 * Check transaction finality, taking into account MEDIAN_TIME_PAST
 * if it is present in the lock flags.
 * @param {ChainEntry} prev - Previous chain entry.
 * @param {TX} tx
 * @param {LockFlags} flags
 * @param {Function} callback - Returns [Error, Boolean].
 */

Chain.prototype.checkFinal = function checkFinal(prev, tx, flags, callback) {
  var height = prev.height + 1;

  function check(err, ts) {
    if (err)
      return callback(err);

    callback(null, tx.isFinal(height, ts));
  }

  // We can skip MTP if the locktime is height.
  if (tx.locktime < constants.LOCKTIME_THRESHOLD)
    return utils.asyncify(check)(null, -1);

  if (flags & constants.flags.MEDIAN_TIME_PAST)
    return prev.getMedianTimeAsync(check);

  utils.asyncify(check)(null, bcoin.now());
};

/**
 * Get the necessary minimum time and height sequence locks for a transaction.
 * @param {TX} tx
 * @param {LockFlags} flags
 * @param {ChainEntry} prev
 * @param {Function} callback - Returns
 * [Error, Number(minTime), Number(minHeight)].
 */

Chain.prototype.getLocks = function getLocks(prev, tx, flags, callback) {
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
    return callback(null, minHeight, minTime);

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

    prev.getAncestorByHeight(Math.max(coinHeight - 1, 0), function(err, entry) {
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
    callback(null, minHeight, minTime);
  });
};

/**
 * Evaluate sequence locks.
 * @param {ChainEntry} prev
 * @param {Number} minHeight
 * @param {Number} minTime
 * @param {Function} callback - Returns [Error, Boolean].
 */

Chain.prototype.evalLocks = function evalLocks(prev, minHeight, minTime, callback) {
  if (minHeight >= prev.height + 1)
    return callback(null, false);

  if (minTime === -1)
    return callback(null, true);

  prev.getMedianTimeAsync(function(err, medianTime) {
    if (err)
      return callback(err);

    if (minTime >= medianTime)
      return callback(null, false);

    callback(null, true);
  });
};

/**
 * Verify sequence locks.
 * @param {TX} tx
 * @param {LockFlags} flags
 * @param {ChainEntry} prev
 * @param {Function} callback - Returns [Error, Boolean].
 */

Chain.prototype.checkLocks = function checkLocks(prev, tx, flags, callback) {
  var self = this;

  this.getLocks(prev, tx, flags, function(err, minHeight, minTime) {
    if (err)
      return callback(err);

    self.evalLocks(prev, minHeight, minTime, callback);
  });
};

/**
 * Represents the deployment state of the chain.
 * @constructor
 * @property {VerifyFlags} flags
 * @property {LockFlags} lockFlags
 * @property {Boolean} bip34
 */

function DeploymentState() {
  if (!(this instanceof DeploymentState))
    return new DeploymentState();

  this.flags = constants.flags.MANDATORY_VERIFY_FLAGS;
  this.flags &= ~constants.flags.VERIFY_P2SH;
  this.lockFlags = constants.flags.MANDATORY_LOCKTIME_FLAGS;
  this.bip34 = false;
}

/**
 * Test whether p2sh is active.
 * @returns {Boolean}
 */

DeploymentState.prototype.hasP2SH = function hasP2SH() {
  return (this.flags & constants.flags.VERIFY_P2SH) !== 0;
};

/**
 * Test whether bip34 (coinbase height) is active.
 * @returns {Boolean}
 */

DeploymentState.prototype.hasBIP34 = function hasBIP34() {
  return this.bip34;
};

/**
 * Test whether bip66 (VERIFY_DERSIG) is active.
 * @returns {Boolean}
 */

DeploymentState.prototype.hasBIP66 = function hasBIP66() {
  return (this.flags & constants.flags.VERIFY_DERSIG) !== 0;
};

/**
 * Test whether cltv is active.
 * @returns {Boolean}
 */

DeploymentState.prototype.hasCLTV = function hasCLTV() {
  return (this.flags & constants.flags.VERIFY_CHECKLOCKTIMEVERIFY) !== 0;
};

/**
 * Test whether median time past locktime is active.
 * @returns {Boolean}
 */

DeploymentState.prototype.hasMTP = function hasMTP() {
  return (this.lockFlags & constants.flags.MEDIAN_TIME_PAST) !== 0;
};

/**
 * Test whether csv is active.
 * @returns {Boolean}
 */

DeploymentState.prototype.hasCSV = function hasCSV() {
  return (this.flags & constants.flags.VERIFY_CHECKSEQUENCEVERIFY) !== 0;
};

/**
 * Test whether segwit is active.
 * @returns {Boolean}
 */

DeploymentState.prototype.hasWitness = function hasWitness() {
  return (this.flags & constants.flags.VERIFY_WITNESS) !== 0;
};

/*
 * Expose
 */

module.exports = Chain;
