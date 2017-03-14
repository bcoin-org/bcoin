/*!
 * chain.js - blockchain management for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var assert = require('assert');
var AsyncObject = require('../utils/asyncobject');
var Network = require('../protocol/network');
var Logger = require('../node/logger');
var ChainDB = require('./chaindb');
var common = require('./common');
var consensus = require('../protocol/consensus');
var util = require('../utils/util');
var Lock = require('../utils/lock');
var LRU = require('../utils/lru');
var ChainEntry = require('./chainentry');
var CoinView = require('../coins/coinview');
var Script = require('../script/script');
var errors = require('../protocol/errors');
var co = require('../utils/co');
var VerifyError = errors.VerifyError;
var VerifyResult = errors.VerifyResult;

/**
 * Represents a blockchain.
 * @alias module:blockchain.Chain
 * @constructor
 * @param {Object} options
 * @param {String?} options.name - Database name.
 * @param {String?} options.location - Database file location.
 * @param {String?} options.db - Database backend (`"leveldb"` by default).
 * @param {Number?} options.orphanLimit
 * @param {Boolean?} options.spv
 * @property {Boolean} loaded
 * @property {ChainDB} db - Note that Chain `options` will be passed
 * to the instantiated ChainDB.
 * @property {Number} total
 * @property {Lock} locker
 * @property {Object} invalid
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

  this.options = new ChainOptions(options);

  this.network = this.options.network;
  this.logger = this.options.logger.context('chain');
  this.checkpoints = this.options.checkpoints;

  this.locker = new Lock(true);
  this.invalid = new LRU(100);
  this.state = new DeploymentState();

  this.tip = null;
  this.height = -1;
  this.synced = false;
  this.total = 0;
  this.startTime = util.hrtime();

  this.orphanMap = {};
  this.orphanPrev = {};
  this.orphanCount = 0;
  this.orphanSize = 0;

  this.db = new ChainDB(this);
}

util.inherits(Chain, AsyncObject);

/**
 * Open the chain, wait for the database to load.
 * @method
 * @alias Chain#open
 * @returns {Promise}
 */

Chain.prototype._open = co(function* open() {
  var tip, state;

  this.logger.info('Chain is loading.');

  if (this.options.checkpoints)
    this.logger.info('Checkpoints are enabled.');

  if (this.options.coinCache)
    this.logger.info('Coin cache is enabled.');

  yield this.db.open();

  tip = yield this.db.getTip();

  assert(tip);

  this.tip = tip;
  this.height = tip.height;

  this.logger.info('Chain Height: %d', tip.height);

  this.logger.memory();

  state = yield this.getDeploymentState();

  this.setDeploymentState(state);

  this.logger.memory();

  this.emit('tip', tip);

  this.maybeSync();
});

/**
 * Close the chain, wait for the database to close.
 * @alias Chain#close
 * @returns {Promise}
 */

Chain.prototype._close = function close() {
  return this.db.close();
};

/**
 * Perform all necessary contextual verification on a block.
 * @method
 * @private
 * @param {Block} block
 * @param {ChainEntry} prev
 * @param {Number} flags
 * @returns {Promise} - Returns {@link ContextResult}.
 */

Chain.prototype.verifyContext = co(function* verifyContext(block, prev, flags) {
  var state, view;

  // Initial non-contextual verification.
  state = yield this.verify(block, prev, flags);

  // BIP30 - Verify there are no duplicate txids.
  yield this.verifyDuplicates(block, prev, state);

  // Verify scripts, spend and add coins.
  view = yield this.verifyInputs(block, prev, state);

  return new ContextResult(view, state);
});

/**
 * Perform all necessary contextual verification
 * on a block, without POW check.
 * @method
 * @param {Block} block
 * @returns {Promise}
 */

Chain.prototype.verifyBlock = co(function* verifyBlock(block) {
  var unlock = yield this.locker.lock();
  try {
    return yield this._verifyBlock(block);
  } finally {
    unlock();
  }
});

/**
 * Perform all necessary contextual verification
 * on a block, without POW check (no lock).
 * @method
 * @private
 * @param {Block} block
 * @returns {Promise}
 */

Chain.prototype._verifyBlock = co(function* verifyBlock(block) {
  var flags = common.flags.DEFAULT_FLAGS & ~common.flags.VERIFY_POW;
  return yield this.verifyContext(block, this.tip, flags);
});

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
 * @method
 * @private
 * @param {Block} block
 * @param {ChainEntry} prev
 * @param {Number} flags
 * @returns {Promise} - Returns {@link DeploymentState}.
 */

Chain.prototype.verify = co(function* verify(block, prev, flags) {
  var ret = new VerifyResult();
  var now = this.network.now();
  var height = prev.height + 1;
  var i, ts, tx, mtp;
  var commit, state, bits;

  assert(typeof flags === 'number');

  // Extra sanity check.
  if (block.prevBlock !== prev.hash)
    throw new VerifyError(block, 'invalid', 'bad-prevblk', 0);

  // Skip everything when using checkpoints.
  // We can do this safely because every
  // block in between each checkpoint was
  // validated outside in the header chain.
  if (prev.isHistorical()) {
    if (this.options.spv)
      return new DeploymentState();

    // Once segwit is active, we will still
    // need to check for block mutability.
    if (!block.hasWitness() && !block.getCommitmentHash())
      return new DeploymentState();

    flags &= ~common.flags.VERIFY_BODY;
  }

  // Non-contextual checks.
  if (flags & common.flags.VERIFY_BODY) {
    if (!block.verifyBody(ret)) {
      throw new VerifyError(block,
        'invalid',
        ret.reason,
        ret.score,
        true);
    }
  }

  // Skip all blocks in spv mode.
  if (this.options.spv)
    return this.state;

  // Ensure the POW is what we expect.
  bits = yield this.getTarget(block.ts, prev);

  if (block.bits !== bits) {
    throw new VerifyError(block,
      'invalid',
      'bad-diffbits',
      100);
  }

  // Ensure the timestamp is correct.
  mtp = yield prev.getMedianTime();

  if (block.ts <= mtp) {
    throw new VerifyError(block,
      'invalid',
      'time-too-old',
      0);
  }

  // Check timestamp against adj-time+2hours.
  // If this fails we may be able to accept
  // the block later.
  if (block.ts > now + 2 * 60 * 60) {
    throw new VerifyError(block,
      'invalid',
      'time-too-new',
      0,
      true);
  }

  // Only allow version 2 blocks (coinbase height)
  // once the majority of blocks are using it.
  if (block.version < 2 && height >= this.network.block.bip34height)
    throw new VerifyError(block, 'obsolete', 'bad-version', 0);

  // Only allow version 3 blocks (sig validation)
  // once the majority of blocks are using it.
  if (block.version < 3 && height >= this.network.block.bip66height)
    throw new VerifyError(block, 'obsolete', 'bad-version', 0);

  // Only allow version 4 blocks (checklocktimeverify)
  // once the majority of blocks are using it.
  if (block.version < 4 && height >= this.network.block.bip65height)
    throw new VerifyError(block, 'obsolete', 'bad-version', 0);

  // Get the new deployment state.
  state = yield this.getDeployments(block.ts, prev);

  // Get timestamp for tx.isFinal().
  ts = state.hasMTP() ? mtp : block.ts;

  // Transactions must be finalized with
  // regards to nSequence and nLockTime.
  for (i = 0; i < block.txs.length; i++) {
    tx = block.txs[i];

    if (!tx.isFinal(height, ts)) {
      throw new VerifyError(block,
        'invalid',
        'bad-txns-nonfinal',
        10);
    }
  }

  // Make sure the height contained
  // in the coinbase is correct.
  if (state.hasBIP34()) {
    if (block.getCoinbaseHeight() !== height) {
      throw new VerifyError(block,
        'invalid',
        'bad-cb-height',
        100);
    }
  }

  // Check the commitment hash for segwit.
  if (state.hasWitness()) {
    commit = block.getCommitmentHash();
    if (commit) {
      // These are totally malleable. Someone
      // may have even accidentally sent us
      // the non-witness version of the block.
      // We don't want to consider this block
      // "invalid" if either of these checks
      // fail.
      if (!block.getWitnessNonce()) {
        throw new VerifyError(block,
          'invalid',
          'bad-witness-nonce-size',
          100,
          true);
      }

      if (!util.equal(commit, block.createCommitmentHash())) {
        throw new VerifyError(block,
          'invalid',
          'bad-witness-merkle-match',
          100,
          true);
      }
    }
  }

  // Blocks that do not commit to
  // witness data cannot contain it.
  if (!commit) {
    if (block.hasWitness()) {
      throw new VerifyError(block,
        'invalid',
        'unexpected-witness',
        100,
        true);
    }
  }

  // Check block weight (different from block size
  // check in non-contextual verification).
  if (block.getWeight() > consensus.MAX_BLOCK_WEIGHT) {
    throw new VerifyError(block,
      'invalid',
      'bad-blk-weight',
      100);
  }

  return state;
});

/**
 * Check all deployments on a chain, ranging from p2sh to segwit.
 * @method
 * @param {Number} ts
 * @param {ChainEntry} prev
 * @returns {Promise} - Returns [{@link VerifyError}, {@link DeploymentState}].
 */

Chain.prototype.getDeployments = co(function* getDeployments(ts, prev) {
  var deployments = this.network.deployments;
  var height = prev.height + 1;
  var state = new DeploymentState();
  var active;

  // For some reason bitcoind has p2sh in the
  // mandatory flags by default, when in reality
  // it wasn't activated until march 30th 2012.
  // The first p2sh output and redeem script
  // appeared on march 7th 2012, only it did
  // not have a signature. See:
  // 6a26d2ecb67f27d1fa5524763b49029d7106e91e3cc05743073461a719776192
  // 9c08a4d78931342b37fd5f72900fb9983087e6f46c4a097d8a1f52c74e28eaf6
  if (ts >= consensus.BIP16_TIME)
    state.flags |= Script.flags.VERIFY_P2SH;

  // Coinbase heights are now enforced (bip34).
  if (height >= this.network.block.bip34height)
    state.bip34 = true;

  // Signature validation is now enforced (bip66).
  if (height >= this.network.block.bip66height)
    state.flags |= Script.flags.VERIFY_DERSIG;

  // CHECKLOCKTIMEVERIFY is now usable (bip65)
  if (height >= this.network.block.bip65height)
    state.flags |= Script.flags.VERIFY_CHECKLOCKTIMEVERIFY;

  // CHECKSEQUENCEVERIFY and median time
  // past locktimes are now usable (bip9 & bip113).
  active = yield this.isActive(prev, deployments.csv);
  if (active) {
    state.flags |= Script.flags.VERIFY_CHECKSEQUENCEVERIFY;
    state.lockFlags |= common.lockFlags.VERIFY_SEQUENCE;
    state.lockFlags |= common.lockFlags.MEDIAN_TIME_PAST;
  }

  // Segregrated witness is now usable (bip141 - segnet4)
  active = yield this.isActive(prev, deployments.segwit);
  if (active) {
    state.flags |= Script.flags.VERIFY_WITNESS;
    // BIP147
    state.flags |= Script.flags.VERIFY_NULLDUMMY;
  }

  return state;
});

/**
 * Set a new deployment state.
 * @param {DeploymentState} state
 */

Chain.prototype.setDeploymentState = function setDeploymentState(state) {
  if (!this.state.hasP2SH() && state.hasP2SH())
    this.logger.warning('P2SH has been activated.');

  if (!this.state.hasBIP34() && state.hasBIP34())
    this.logger.warning('BIP34 has been activated.');

  if (!this.state.hasBIP66() && state.hasBIP66())
    this.logger.warning('BIP66 has been activated.');

  if (!this.state.hasCLTV() && state.hasCLTV())
    this.logger.warning('BIP65 has been activated.');

  if (!this.state.hasCSV() && state.hasCSV())
    this.logger.warning('CSV has been activated.');

  if (!this.state.hasWitness() && state.hasWitness())
    this.logger.warning('Segwit has been activated.');

  this.state = state;
};

/**
 * Determine whether to check block for duplicate txids in blockchain
 * history (BIP30). If we're on a chain that has bip34 activated, we
 * can skip this.
 * @method
 * @private
 * @see https://github.com/bitcoin/bips/blob/master/bip-0030.mediawiki
 * @param {Block} block
 * @param {ChainEntry} prev
 * @returns {Promise}
 */

Chain.prototype.verifyDuplicates = co(function* verifyDuplicates(block, prev, state) {
  var height = prev.height + 1;
  var i, tx, result;

  if (this.options.spv)
    return;

  if (prev.isHistorical())
    return;

  // BIP34 made it impossible to
  // create duplicate txids.
  if (state.hasBIP34())
    return;

  // Check all transactions.
  for (i = 0; i < block.txs.length; i++) {
    tx = block.txs[i];
    result = yield this.db.hasCoins(tx.hash());

    if (result) {
      // Blocks 91842 and 91880 created duplicate
      // txids by using the same exact output script
      // and extraNonce.
      if (this.network.bip30[height]) {
        if (block.hash('hex') === this.network.bip30[height])
          continue;
      }
      throw new VerifyError(block, 'invalid', 'bad-txns-BIP30', 100);
    }
  }
});

/**
 * Check block transactions for all things pertaining
 * to inputs. This function is important because it is
 * what actually fills the coins into the block. This
 * function will check the block reward, the sigops,
 * the tx values, and execute and verify the scripts (it
 * will attempt to do this on the worker pool). If
 * `checkpoints` is enabled, it will skip verification
 * for historical data.
 * @method
 * @private
 * @see TX#checkInputs
 * @param {Block} block
 * @param {ChainEntry} prev
 * @param {DeploymentState} state
 * @returns {Promise} - Returns {@link CoinView}.
 */

Chain.prototype.verifyInputs = co(function* verifyInputs(block, prev, state) {
  var interval = this.network.halvingInterval;
  var ret = new VerifyResult();
  var view = new CoinView();
  var height = prev.height + 1;
  var historical = prev.isHistorical();
  var sigops = 0;
  var reward = 0;
  var jobs = [];
  var i, tx, valid, fee;

  if (this.options.spv)
    return view;

  // Check all transactions
  for (i = 0; i < block.txs.length; i++) {
    tx = block.txs[i];

    // Ensure tx is not double spending an output.
    if (i > 0) {
      if (!(yield view.spendInputs(this.db, tx))) {
        assert(!historical, 'BUG: Spent inputs in historical data!');
        throw new VerifyError(block,
          'invalid',
          'bad-txns-inputs-missingorspent',
          100);
      }
    }

    // Skip everything if we're
    // using checkpoints.
    if (historical) {
      view.addTX(tx, height);
      continue;
    }

    // Verify sequence locks.
    if (i > 0 && tx.version >= 2) {
      valid = yield this.verifyLocks(prev, tx, view, state.lockFlags);

      if (!valid) {
        throw new VerifyError(block,
          'invalid',
          'bad-txns-nonfinal',
          100);
      }
    }

    // Count sigops (legacy + scripthash? + witness?)
    sigops += tx.getSigopsCost(view, state.flags);

    if (sigops > consensus.MAX_BLOCK_SIGOPS_COST) {
      throw new VerifyError(block,
        'invalid',
        'bad-blk-sigops',
        100);
    }

    // Contextual sanity checks.
    if (i > 0) {
      fee = tx.checkContext(view, height, ret);

      if (fee === -1) {
        throw new VerifyError(block,
          'invalid',
          ret.reason,
          ret.score);
      }

      reward += fee;

      if (reward > consensus.MAX_MONEY) {
        throw new VerifyError(block,
          'invalid',
          'bad-cb-amount',
          100);
      }

      // Push onto verification queue.
      jobs.push(tx.verifyAsync(view, state.flags));
    }

    // Add new coins.
    view.addTX(tx, height);
  }

  if (historical)
    return view;

  // Make sure the miner isn't trying to conjure more coins.
  reward += consensus.getReward(height, interval);

  if (block.getClaimed() > reward) {
    throw new VerifyError(block,
      'invalid',
      'bad-cb-amount',
      100);
  }

  // Verify all txs in parallel.
  valid = yield co.every(jobs);

  if (!valid) {
    throw new VerifyError(block,
      'invalid',
      'mandatory-script-verify-flag-failed',
      100);
  }

  return view;
});

/**
 * Get the cached height for a hash if present.
 * @private
 * @param {Hash} hash
 * @returns {Number}
 */

Chain.prototype.checkHeight = function checkHeight(hash) {
  var entry = this.db.getCache(hash);

  if (!entry)
    return -1;

  return entry.height;
};

/**
 * Find the block at which a fork ocurred.
 * @private
 * @method
 * @param {ChainEntry} fork - The current chain.
 * @param {ChainEntry} longer - The competing chain.
 * @returns {Promise}
 */

Chain.prototype.findFork = co(function* findFork(fork, longer) {
  while (fork.hash !== longer.hash) {
    while (longer.height > fork.height) {
      longer = yield longer.getPrevious();
      if (!longer)
        throw new Error('No previous entry for new tip.');
    }

    if (fork.hash === longer.hash)
      return fork;

    fork = yield fork.getPrevious();

    if (!fork)
      throw new Error('No previous entry for old tip.');
  }

  return fork;
});

/**
 * Reorganize the blockchain (connect and disconnect inputs).
 * Called when a competing chain with a higher chainwork
 * is received.
 * @method
 * @private
 * @param {ChainEntry} competitor - The competing chain's tip.
 * @param {Block} block - The being being added.
 * @returns {Promise}
 */

Chain.prototype.reorganize = co(function* reorganize(competitor, block) {
  var tip = this.tip;
  var fork = yield this.findFork(tip, competitor);
  var disconnect = [];
  var connect = [];
  var i, entry;

  assert(fork, 'No free space or data corruption.');

  // Blocks to disconnect.
  entry = tip;
  while (entry.hash !== fork.hash) {
    disconnect.push(entry);
    entry = yield entry.getPrevious();
    assert(entry);
  }

  // Blocks to connect.
  entry = competitor;
  while (entry.hash !== fork.hash) {
    connect.push(entry);
    entry = yield entry.getPrevious();
    assert(entry);
  }

  // Disconnect blocks/txs.
  for (i = 0; i < disconnect.length; i++) {
    entry = disconnect[i];
    yield this.disconnect(entry);
  }

  // Connect blocks/txs.
  // We don't want to connect the new tip here.
  // That will be done outside in setBestChain.
  for (i = connect.length - 1; i >= 1; i--) {
    entry = connect[i];
    yield this.reconnect(entry);
  }

  this.logger.warning(
    'Chain reorganization: old=%s(%d) new=%s(%d)',
    tip.rhash(),
    tip.height,
    competitor.rhash(),
    competitor.height
  );

  this.emit('reorganize', tip, competitor);
});

/**
 * Reorganize the blockchain for SPV. This
 * will reset the chain to the fork block.
 * @method
 * @private
 * @param {ChainEntry} competitor - The competing chain's tip.
 * @param {Block} block - The being being added.
 * @returns {Promise}
 */

Chain.prototype.reorganizeSPV = co(function* reorganizeSPV(competitor, block) {
  var tip = this.tip;
  var fork = yield this.findFork(tip, competitor);
  var disconnect = [];
  var entry = tip;
  var i, headers, view;

  assert(fork, 'No free space or data corruption.');

  // Buffer disconnected blocks.
  while (entry.hash !== fork.hash) {
    disconnect.push(entry);
    entry = yield entry.getPrevious();
    assert(entry);
  }

  // Reset the main chain back
  // to the fork block, causing
  // us to redownload the blocks
  // on the new main chain.
  yield this._reset(fork.hash, true);

  // Emit disconnection events now that
  // the chain has successfully reset.
  for (i = 0; i < disconnect.length; i++) {
    entry = disconnect[i];
    headers = entry.toHeaders();
    view = new CoinView();
    yield this.fire('disconnect', entry, headers, view);
  }

  this.logger.warning(
    'SPV reorganization: old=%s(%d) new=%s(%d)',
    tip.rhash(),
    tip.height,
    competitor.rhash(),
    competitor.height
  );

  this.logger.warning(
    'Chain replay from height %d necessary.',
    fork.height);

  this.emit('reorganize', tip, competitor);
});

/**
 * Disconnect an entry from the chain (updates the tip).
 * @method
 * @param {ChainEntry} entry
 * @returns {Promise}
 */

Chain.prototype.disconnect = co(function* disconnect(entry) {
  var block = yield this.db.getBlock(entry.hash);
  var prev, view;

  if (!block) {
    if (!this.options.spv)
      throw new Error('Block not found.');
    block = entry.toHeaders();
  }

  prev = yield entry.getPrevious();
  view = yield this.db.disconnect(entry, block);

  assert(prev);

  this.tip = prev;
  this.height = prev.height;

  this.emit('tip', prev);
  yield this.fire('disconnect', entry, block, view);
});

/**
 * Reconnect an entry to the chain (updates the tip).
 * This will do contextual-verification on the block
 * (necessary because we cannot validate the inputs
 * in alternate chains when they come in).
 * @method
 * @param {ChainEntry} entry
 * @param {Number} flags
 * @returns {Promise}
 */

Chain.prototype.reconnect = co(function* reconnect(entry) {
  var block = yield this.db.getBlock(entry.hash);
  var flags = common.flags.VERIFY_NONE;
  var prev, result;

  if (!block) {
    if (!this.options.spv)
      throw new Error('Block not found.');
    block = entry.toHeaders();
  }

  prev = yield entry.getPrevious();
  assert(prev);

  try {
    result = yield this.verifyContext(block, prev, flags);
  } catch (err) {
    if (err.type === 'VerifyError') {
      if (!err.malleated)
        this.setInvalid(entry.hash);
      this.logger.warning(
        'Tried to reconnect invalid block: %s (%d).',
        entry.rhash(), entry.height);
    }
    throw err;
  }

  yield this.db.reconnect(entry, block, result.view);

  this.tip = entry;
  this.height = entry.height;
  this.setDeploymentState(result.state);

  this.emit('tip', entry);
  this.emit('reconnect', entry, block);
  yield this.fire('connect', entry, block, result.view);
});

/**
 * Set the best chain. This is called on every valid block
 * that comes in. It may add and connect the block (main chain),
 * save the block without connection (alternate chain), or
 * reorganize the chain (a higher fork).
 * @method
 * @private
 * @param {ChainEntry} entry
 * @param {Block} block
 * @param {ChainEntry} prev
 * @param {Number} flags
 * @returns {Promise}
 */

Chain.prototype.setBestChain = co(function* setBestChain(entry, block, prev, flags) {
  var result;

  // A higher fork has arrived.
  // Time to reorganize the chain.
  if (entry.prevBlock !== this.tip.hash) {
    this.logger.warning('WARNING: Reorganizing chain.');

    // In spv-mode, we reset the
    // chain and redownload the blocks.
    if (this.options.spv)
      return yield this.reorganizeSPV(entry, block);

    yield this.reorganize(entry, block);
  }

  // Warn of unknown versionbits.
  if (entry.hasUnknown()) {
    this.logger.warning(
      'Unknown version bits in block %d: %d.',
      entry.height, entry.version);
  }

  // Otherwise, everything is in order.
  // Do "contextual" verification on our block
  // now that we're certain its previous
  // block is in the chain.
  try {
    result = yield this.verifyContext(block, prev, flags);
  } catch (err) {
    if (err.type === 'VerifyError') {
      if (!err.malleated)
        this.setInvalid(entry.hash);
      this.logger.warning(
        'Tried to connect invalid block: %s (%d).',
        entry.rhash(), entry.height);
    }
    throw err;
  }

  // Save block and connect inputs.
  yield this.db.save(entry, block, result.view);

  // Expose the new state.
  this.tip = entry;
  this.height = entry.height;
  this.setDeploymentState(result.state);

  this.emit('tip', entry);
  this.emit('block', block, entry);
  yield this.fire('connect', entry, block, result.view);
});

/**
 * Save block on an alternate chain.
 * @method
 * @private
 * @param {ChainEntry} entry
 * @param {Block} block
 * @param {ChainEntry} prev
 * @param {Number} flags
 * @returns {Promise}
 */

Chain.prototype.saveAlternate = co(function* saveAlternate(entry, block, prev, flags) {
  try {
    // Do as much verification
    // as we can before saving.
    yield this.verify(block, prev, flags);
  } catch (err) {
    if (err.type === 'VerifyError') {
      if (!err.malleated)
        this.setInvalid(entry.hash);
      this.logger.warning(
        'Invalid block on alternate chain: %s (%d).',
        entry.rhash(), entry.height);
    }
    throw err;
  }

  // Warn of unknown versionbits.
  if (entry.hasUnknown()) {
    this.logger.warning(
      'Unknown version bits in block %d: %d.',
      entry.height, entry.version);
  }

  yield this.db.save(entry, block);

  this.logger.warning('Heads up: Competing chain at height %d:'
    + ' tip-height=%d competitor-height=%d'
    + ' tip-hash=%s competitor-hash=%s'
    + ' tip-chainwork=%s competitor-chainwork=%s'
    + ' chainwork-diff=%s',
    entry.height,
    this.tip.height,
    entry.height,
    this.tip.rhash(),
    entry.rhash(),
    this.tip.chainwork.toString(),
    entry.chainwork.toString(),
    this.tip.chainwork.sub(entry.chainwork).toString());

  // Emit as a "competitor" block.
  this.emit('competitor', block, entry);
});

/**
 * Reset the chain to the desired block. This
 * is useful for replaying the blockchain download
 * for SPV.
 * @method
 * @param {Hash|Number} block
 * @returns {Promise}
 */

Chain.prototype.reset = co(function* reset(block) {
  var unlock = yield this.locker.lock();
  try {
    return yield this._reset(block, false);
  } finally {
    unlock();
  }
});

/**
 * Reset the chain to the desired block without a lock.
 * @method
 * @private
 * @param {Hash|Number} block
 * @returns {Promise}
 */

Chain.prototype._reset = co(function* reset(block, silent) {
  var tip = yield this.db.reset(block);
  var state;

  // Reset state.
  this.tip = tip;
  this.height = tip.height;
  this.synced = false;

  state = yield this.getDeploymentState();

  this.setDeploymentState(state);

  this.emit('tip', tip);

  if (!silent)
    yield this.fire('reset', tip);

  // Reset the orphan map completely. There may
  // have been some orphans on a forked chain we
  // no longer need.
  this.purgeOrphans();

  this.maybeSync();
});

/**
 * Reset the chain to a height or hash. Useful for replaying
 * the blockchain download for SPV.
 * @method
 * @param {Hash|Number} block - hash/height
 * @returns {Promise}
 */

Chain.prototype.replay = co(function* replay(block) {
  var unlock = yield this.locker.lock();
  try {
    return yield this._replay(block, true);
  } finally {
    unlock();
  }
});

/**
 * Reset the chain without a lock.
 * @method
 * @private
 * @param {Hash|Number} block - hash/height
 * @param {Boolean?} silent
 * @returns {Promise}
 */

Chain.prototype._replay = co(function* replay(block, silent) {
  var entry = yield this.db.getEntry(block);

  if (!entry)
    throw new Error('Block not found.');

  if (!(yield entry.isMainChain()))
    throw new Error('Cannot reset on alternate chain.');

  if (entry.isGenesis())
    return yield this._reset(entry.hash, silent);

  yield this._reset(entry.prevBlock, silent);
});

/**
 * Invalidate block.
 * @method
 * @param {Hash} hash
 * @returns {Promise}
 */

Chain.prototype.invalidate = co(function* invalidate(hash) {
  var unlock = yield this.locker.lock();
  try {
    return yield this._invalidate(hash);
  } finally {
    unlock();
  }
});

/**
 * Invalidate block (no lock).
 * @method
 * @param {Hash} hash
 * @returns {Promise}
 */

Chain.prototype._invalidate = co(function* _invalidate(hash) {
  yield this._replay(hash, false);
  this.chain.setInvalid(hash);
});

/**
 * Scan the blockchain for transactions containing specified address hashes.
 * @method
 * @param {Hash} start - Block hash to start at.
 * @param {Bloom} filter - Bloom filter containing tx and address hashes.
 * @param {Function} iter - Iterator.
 * @returns {Promise}
 */

Chain.prototype.scan = co(function* scan(start, filter, iter) {
  var unlock = yield this.locker.lock();
  try {
    return yield this.db.scan(start, filter, iter);
  } finally {
    unlock();
  }
});

/**
 * Reset the chain to the desired timestamp (within 2
 * hours). This is useful for replaying the blockchain
 * download for SPV.
 * @method
 * @param {Number} ts - Timestamp.
 * @returns {Promise}
 */

Chain.prototype.resetTime = co(function* resetTime(ts) {
  var unlock = yield this.locker.lock();
  try {
    return yield this._resetTime(ts);
  } finally {
    unlock();
  }
});

/**
 * Reset the chain to the desired timestamp without a lock.
 * @private
 * @method
 * @param {Number} ts - Timestamp.
 * @returns {Promise}
 */

Chain.prototype._resetTime = co(function* resetTime(ts) {
  var entry = yield this.byTime(ts);

  if (!entry)
    return;

  yield this._reset(entry.height, false);
});

/**
 * Add a block to the chain, perform all necessary verification.
 * @method
 * @param {Block} block
 * @param {Number} flags
 * @returns {Promise}
 */

Chain.prototype.add = co(function* add(block, flags) {
  var hash = block.hash('hex');
  var unlock = yield this.locker.lock(hash);
  try {
    return yield this._add(block, flags);
  } finally {
    unlock();
  }
});

/**
 * Add a block to the chain without a lock.
 * @method
 * @private
 * @param {Block} block
 * @param {Number} flags
 * @returns {Promise}
 */

Chain.prototype._add = co(function* add(block, flags) {
  var initial = true;
  var result = null;
  var hash, entry, prev;

  if (flags == null)
    flags = common.flags.DEFAULT_FLAGS;

  assert(block);

  while (block) {
    hash = block.hash('hex');

    // Mark the start time.
    this.mark();

    // Special case for genesis block.
    if (hash === this.network.genesis.hash) {
      this.logger.debug('Saw genesis block: %s.', block.rhash());
      throw new VerifyError(block, 'duplicate', 'duplicate', 0);
    }

    // Do we already have this block in the queue?
    if (this.hasPending(hash)) {
      this.logger.debug('Already have pending block: %s.', block.rhash());
      throw new VerifyError(block, 'duplicate', 'duplicate', 0);
    }

    // If the block is already known to be
    // an orphan, ignore it.
    if (this.hasOrphan(hash)) {
      this.logger.debug('Already have orphan block: %s.', block.rhash());
      throw new VerifyError(block, 'duplicate', 'duplicate', 0);
    }

    // Do not revalidate known invalid blocks.
    if (this.hasInvalid(hash, block)) {
      this.logger.debug('Invalid ancestors for block: %s.', block.rhash());
      throw new VerifyError(block, 'duplicate', 'duplicate', 100);
    }

    // Check the POW before doing anything.
    if (flags & common.flags.VERIFY_POW) {
      if (!block.verifyPOW())
        throw new VerifyError(block, 'invalid', 'high-hash', 50);
    }

    // Do we already have this block?
    if (yield this.db.hasEntry(hash)) {
      this.logger.debug('Already have block: %s.', block.rhash());
      throw new VerifyError(block, 'duplicate', 'duplicate', 0);
    }

    // Find the previous block entry.
    prev = yield this.db.getEntry(block.prevBlock);

    // If previous block wasn't ever seen,
    // add it current to orphans and break.
    if (!prev) {
      assert(initial);
      assert(!result);
      this.storeOrphan(block);
      break;
    }

    // Verify a checkpoint if there is one.
    if (!this.verifyCheckpoint(prev, hash)) {
      throw new VerifyError(block,
        'checkpoint',
        'checkpoint mismatch',
        100);
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
        this.logger.error(e);
        throw new VerifyError(block,
          'malformed',
          'error parsing message',
          10);
      }
    }

    // Create a new chain entry.
    entry = ChainEntry.fromBlock(this, block, prev);

    // The block is on a alternate chain if the
    // chainwork is less than or equal to
    // our tip's. Add the block but do _not_
    // connect the inputs.
    if (entry.chainwork.cmp(this.tip.chainwork) <= 0) {
      // Save block to an alternate chain.
      yield this.saveAlternate(entry, block, prev, flags);
    } else {
      // Attempt to add block to the chain index.
      yield this.setBestChain(entry, block, prev, flags);
    }

    // Emit the resolved orphan.
    if (!initial) {
      this.logger.debug(
        'Orphan block was resolved: %s (%d).',
        block.rhash(), entry.height);
      this.emit('resolved', block, entry);
    }

    // Keep track of stats.
    this.finish(block, entry);

    // Try to resolve orphan chain.
    block = this.resolveOrphan(hash);
    initial = false;

    if (!result)
      result = entry;
  }

  // Failsafe for large orphan chains. Do not
  // allow more than 20mb stored in memory.
  this.pruneOrphans();

  // Check sync state.
  this.maybeSync();

  return result;
});

/**
 * Test whether the chain has reached its slow height.
 * @private
 * @returns {Boolean}
 */

Chain.prototype.isSlow = function isSlow() {
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

Chain.prototype.mark = function mark() {
  this.startTime = util.hrtime();
};

/**
 * Calculate the time difference from
 * start time and log block.
 * @private
 * @param {Block} block
 * @param {ChainEntry} entry
 */

Chain.prototype.finish = function finish(block, entry) {
  var elapsed;

  // Keep track of total blocks handled.
  this.total += 1;

  if (!this.isSlow())
    return;

  // Report memory for debugging.
  util.gc();
  this.logger.memory();

  elapsed = util.hrtime(this.startTime);

  this.logger.info(
    'Block %s (%d) added to chain (size=%d txs=%d time=%d).',
    entry.rhash(),
    entry.height,
    block.getSize(),
    block.txs.length,
    elapsed);

  if (this.db.coinCache.capacity > 0) {
    this.logger.debug('Coin Cache: size=%dmb, items=%d.',
      util.mb(this.db.coinCache.size), this.db.coinCache.items);
  }
};

/**
 * Verify a block hash and height against the checkpoints.
 * @private
 * @param {ChainEntry} prev
 * @param {Hash} hash
 * @returns {Boolean}
 */

Chain.prototype.verifyCheckpoint = function verifyCheckpoint(prev, hash) {
  var height = prev.height + 1;
  var checkpoint;

  if (!this.checkpoints)
    return true;

  checkpoint = this.network.checkpointMap[height];

  if (!checkpoint)
    return true;

  if (hash === checkpoint) {
    this.logger.debug('Hit checkpoint block %s (%d).',
      util.revHex(hash), height);
    this.emit('checkpoint', hash, height);
    return true;
  }

  // Someone is either mining on top of
  // an old block for no reason, or the
  // consensus protocol is broken and
  // there was a 20k+ block reorg.
  this.logger.warning(
    'Checkpoint mismatch at height %d: expected=%s received=%s',
    height,
    util.revHex(checkpoint),
    util.revHex(hash)
  );

  this.purgeOrphans();

  return false;
};

/**
 * Store an orphan.
 * @private
 * @param {Block} block
 */

Chain.prototype.storeOrphan = function storeOrphan(block) {
  var hash = block.hash('hex');
  var height = block.getCoinbaseHeight();
  var orphan = this.orphanPrev[block.prevBlock];

  // The orphan chain forked.
  if (orphan) {
    assert(orphan.hash('hex') !== hash);
    assert(orphan.prevBlock === block.prevBlock);

    this.logger.warning(
      'Removing forked orphan block: %s (%d).',
      orphan.rhash(), height);

    this.resolveOrphan(block.prevBlock);
  }

  this.orphanCount++;
  this.orphanSize += block.getSize();
  this.orphanPrev[block.prevBlock] = block;
  this.orphanMap[hash] = block;

  this.logger.debug(
    'Storing orphan block: %s (%d).',
    block.rhash(), height);

  this.emit('orphan', block);
};

/**
 * Resolve an orphan.
 * @private
 * @param {Hash} hash - Previous block hash.
 * @returns {Block}
 */

Chain.prototype.resolveOrphan = function resolveOrphan(hash) {
  var block = this.orphanPrev[hash];

  if (!block)
    return;

  delete this.orphanMap[block.hash('hex')];
  delete this.orphanPrev[hash];

  this.orphanCount--;
  this.orphanSize -= block.getSize();

  return block;
};

/**
 * Purge any waiting orphans.
 */

Chain.prototype.purgeOrphans = function purgeOrphans() {
  var count = this.orphanCount;
  var size = this.orphanSize;

  if (count === 0)
    return;

  this.orphanPrev = {};
  this.orphanMap = {};
  this.orphanCount = 0;
  this.orphanSize = 0;

  this.logger.debug('Purged %d orphans (%dmb).',
    count, util.mb(size));
};

/**
 * Prune orphans, only keep the orphan with the highest
 * coinbase height (likely to be the peer's tip).
 */

Chain.prototype.pruneOrphans = function pruneOrphans() {
  var i, hashes, hash, orphan, height;
  var bestOrphan, bestHeight, lastOrphan;

  if (this.orphanSize <= this.options.orphanLimit)
    return false;

  this.logger.warning('Pruning %d (%dmb) orphans!',
    this.orphanCount, util.mb(this.orphanSize));

  hashes = Object.keys(this.orphanPrev);

  if (hashes.length === 0)
    return false;

  for (i = 0; i < hashes.length; i++) {
    hash = hashes[i];
    orphan = this.orphanPrev[hash];
    height = orphan.getCoinbaseHeight();

    delete this.orphanPrev[hash];

    if (!bestOrphan || height > bestHeight) {
      bestOrphan = orphan;
      bestHeight = height;
    }

    lastOrphan = orphan;
  }

  // Save the best for last... or the
  // last for best in this case.
  if (bestHeight === -1)
    bestOrphan = lastOrphan;

  hashes = Object.keys(this.orphanMap);

  for (i = 0; i < hashes.length; i++) {
    hash = hashes[i];
    orphan = this.orphanMap[hash];

    delete this.orphanMap[hash];

    if (orphan !== bestOrphan)
      this.emit('unresolved', orphan);
  }

  this.orphanPrev[bestOrphan.prevBlock] = bestOrphan;
  this.orphanMap[bestOrphan.hash('hex')] = bestOrphan;
  this.orphanCount = 1;
  this.orphanSize = bestOrphan.getSize();

  return true;
};

/**
 * Test whether an invalid block hash has been seen.
 * @private
 * @param {Hash} hash
 * @param {Block} block
 * @returns {Boolean}
 */

Chain.prototype.hasInvalid = function hasInvalid(hash, block) {
  if (this.invalid.has(hash))
    return true;

  if (this.invalid.has(block.prevBlock)) {
    this.setInvalid(hash);
    return true;
  }

  return false;
};

/**
 * Mark a block as invalid.
 * @private
 * @param {Hash} hash
 */

Chain.prototype.setInvalid = function setInvalid(hash) {
  this.invalid.set(hash, true);
};

/**
 * Forget an invalid block hash.
 * @private
 * @param {Hash} hash
 */

Chain.prototype.removeInvalid = function removeInvalid(hash) {
  this.invalid.remove(hash);
};

/**
 * Test the chain to see if it contains
 * a block, or has recently seen a block.
 * @method
 * @param {Hash} hash
 * @returns {Promise} - Returns Boolean.
 */

Chain.prototype.has = co(function* has(hash) {
  if (this.hasOrphan(hash))
    return true;

  if (this.locker.has(hash))
    return true;

  if (this.invalid.has(hash))
    return true;

  return yield this.hasEntry(hash);
});

/**
 * Find the corresponding block entry by hash or height.
 * @param {Hash|Number} hash/height
 * @returns {Promise} - Returns {@link ChainEntry}.
 */

Chain.prototype.getEntry = function getEntry(hash) {
  return this.db.getEntry(hash);
};

/**
 * Test the chain to see if it contains a block.
 * @param {Hash} hash
 * @returns {Promise} - Returns Boolean.
 */

Chain.prototype.hasEntry = function hasEntry(hash) {
  return this.db.hasEntry(hash);
};

/**
 * Get an orphan block.
 * @param {Hash} hash
 * @returns {Block}
 */

Chain.prototype.getOrphan = function getOrphan(hash) {
  return this.orphanMap[hash] || null;
};

/**
 * Test the chain to see if it contains an orphan.
 * @param {Hash} hash
 * @returns {Promise} - Returns Boolean.
 */

Chain.prototype.hasOrphan = function hasOrphan(hash) {
  return this.orphanMap[hash] != null;
};

/**
 * Test the chain to see if it contains a pending block in its queue.
 * @param {Hash} hash
 * @returns {Promise} - Returns Boolean.
 */

Chain.prototype.hasPending = function hasPending(hash) {
  return this.locker.hasPending(hash);
};

/**
 * Get coin viewpoint (spent).
 * @method
 * @param {TX} tx
 * @returns {Promise} - Returns {@link CoinView}.
 */

Chain.prototype.getSpentView = co(function* getSpentView(tx) {
  var unlock = yield this.locker.lock();
  try {
    return yield this.db.getSpentView(tx);
  } finally {
    unlock();
  }
});

/**
 * Test the chain to see if it is synced.
 * @returns {Boolean}
 */

Chain.prototype.isFull = function isFull() {
  return this.synced;
};

/**
 * Potentially emit a `full` event.
 * @private
 */

Chain.prototype.maybeSync = function maybeSync() {
  if (this.synced)
    return;

  if (this.checkpoints) {
    if (this.tip.height < this.network.lastCheckpoint)
      return;

    this.logger.info('Last checkpoint reached. Disabling checkpoints.');
    this.checkpoints = false;
  }

  if (this.tip.ts < util.now() - this.network.block.maxTipAge)
    return;

  if (!this.hasChainwork())
    return;

  this.synced = true;
  this.emit('full');
};

/**
 * Test the chain to see if it has the
 * minimum required chainwork for the
 * network.
 * @returns {Boolean}
 */

Chain.prototype.hasChainwork = function hasChainwork() {
  return this.tip.chainwork.cmp(this.network.pow.chainwork) >= 0;
};

/**
 * Get the fill percentage.
 * @returns {Number} percent - Ranges from 0.0 to 1.0.
 */

Chain.prototype.getProgress = function getProgress() {
  var start = this.network.genesis.ts;
  var current = this.tip.ts - start;
  var end = util.now() - start - 40 * 60;
  return Math.min(1, current / end);
};

/**
 * Calculate chain locator (an array of hashes).
 * @method
 * @param {Hash} start - Height or hash to treat as the tip.
 * The current tip will be used if not present. Note that this can be a
 * non-existent hash, which is useful for headers-first locators.
 * @returns {Promise} - Returns {@link Hash}[].
 */

Chain.prototype.getLocator = co(function* getLocator(start) {
  var unlock = yield this.locker.lock();
  try {
    return yield this._getLocator(start);
  } finally {
    unlock();
  }
});

/**
 * Calculate chain locator without a lock.
 * @method
 * @private
 * @param {Hash} start
 * @returns {Promise}
 */

Chain.prototype._getLocator = co(function* getLocator(start) {
  var hashes = [];
  var step = 1;
  var height, entry, main, hash;

  if (start == null)
    start = this.tip.hash;

  assert(typeof start === 'string');

  entry = yield this.db.getEntry(start);

  if (!entry) {
    hashes.push(start);
    entry = this.tip;
  }

  hash = entry.hash;
  height = entry.height;
  main = yield entry.isMainChain();

  while (hash) {
    hashes.push(hash);

    if (height === 0)
      break;

    height = Math.max(0, height - step);

    if (hashes.length > 10)
      step *= 2;

    if (height === 0) {
      hash = this.network.genesis.hash;
      continue;
    }

    // If we're on the main chain, we can
    // do a fast lookup of the hash.
    if (main) {
      hash = yield this.db.getHash(height);
      continue;
    }

    entry = yield entry.getAncestor(height);

    if (!entry)
      break;

    hash = entry.hash;
  }

  return hashes;
});

/**
 * Calculate the orphan root of the hash (if it is an orphan).
 * @param {Hash} hash
 * @returns {Hash}
 */

Chain.prototype.getOrphanRoot = function getOrphanRoot(hash) {
  var root;

  assert(hash);

  while (this.orphanMap[hash]) {
    root = hash;
    hash = this.orphanMap[hash].prevBlock;
  }

  return root;
};

/**
 * Calculate the time difference (in seconds)
 * between two blocks by examining chainworks.
 * @param {ChainEntry} to
 * @param {ChainEntry} from
 * @returns {Number}
 */

Chain.prototype.getProofTime = function getProofTime(to, from) {
  var sign, work;

  if (to.chainwork.cmp(from.chainwork) > 0) {
    work = to.chainwork.sub(from.chainwork);
    sign = 1;
  } else {
    work = from.chainwork.sub(to.chainwork);
    sign = -1;
  }

  work = work.imuln(this.network.pow.targetSpacing);
  work = work.idiv(this.tip.getProof());

  if (work.bitLength() > 53)
    return sign * util.MAX_SAFE_INTEGER;

  return sign * work.toNumber();
};

/**
 * Calculate the next target based on the chain tip.
 * @method
 * @returns {Promise} - returns Number
 * (target is in compact/mantissa form).
 */

Chain.prototype.getCurrentTarget = co(function* getCurrentTarget() {
  return yield this.getTarget(this.network.now(), this.tip);
});

/**
 * Calculate the next target.
 * @method
 * @param {Number} ts - Next block timestamp.
 * @param {ChainEntry} prev - Previous entry.
 * @returns {Promise} - returns Number
 * (target is in compact/mantissa form).
 */

Chain.prototype.getTarget = co(function* getTarget(ts, prev) {
  var pow = this.network.pow;
  var first, cache, height;

  // Genesis
  if (!prev) {
    assert(ts === this.network.genesis.ts);
    return pow.bits;
  }

  // Do not retarget
  if ((prev.height + 1) % pow.retargetInterval !== 0) {
    if (pow.targetReset) {
      // Special behavior for testnet:
      if (ts > prev.ts + pow.targetSpacing * 2)
        return pow.bits;

      while (prev.height !== 0
        && prev.height % pow.retargetInterval !== 0
        && prev.bits === pow.bits) {
        cache = prev.getPrevCache();

        if (cache) {
          prev = cache;
          continue;
        }

        prev = yield prev.getPrevious();
        assert(prev);
      }
    }
    return prev.bits;
  }

  // Back 2 weeks
  height = prev.height - (pow.retargetInterval - 1);
  assert(height >= 0);

  first = yield prev.getAncestor(height);
  assert(first);

  return this.retarget(prev, first);
});

/**
 * Retarget. This is called when the chain height
 * hits a retarget diff interval.
 * @param {ChainEntry} prev - Previous entry.
 * @param {ChainEntry} first - Chain entry from 2 weeks prior.
 * @returns {Number} target - Target in compact/mantissa form.
 */

Chain.prototype.retarget = function retarget(prev, first) {
  var pow = this.network.pow;
  var targetTimespan = pow.targetTimespan;
  var actualTimespan, target;

  if (pow.noRetargeting)
    return prev.bits;

  actualTimespan = prev.ts - first.ts;
  target = consensus.fromCompact(prev.bits);

  if (actualTimespan < targetTimespan / 4 | 0)
    actualTimespan = targetTimespan / 4 | 0;

  if (actualTimespan > targetTimespan * 4)
    actualTimespan = targetTimespan * 4;

  target.imuln(actualTimespan);
  target.idivn(targetTimespan);

  if (target.cmp(pow.limit) > 0)
    return pow.bits;

  return consensus.toCompact(target);
};

/**
 * Find a locator. Analagous to bitcoind's `FindForkInGlobalIndex()`.
 * @method
 * @param {Hash[]} locator - Hashes.
 * @returns {Promise} - Returns {@link Hash} (the
 * hash of the latest known block).
 */

Chain.prototype.findLocator = co(function* findLocator(locator) {
  var i, hash;

  for (i = 0; i < locator.length; i++) {
    hash = locator[i];
    if (yield this.db.isMainChain(hash))
      return hash;
  }

  return this.network.genesis.hash;
});

/**
 * Check whether a versionbits deployment is active (BIP9: versionbits).
 * @example
 * yield chain.isActive(tip, deployments.segwit);
 * @method
 * @see https://github.com/bitcoin/bips/blob/master/bip-0009.mediawiki
 * @param {ChainEntry} prev - Previous chain entry.
 * @param {String} id - Deployment id.
 * @returns {Promise} - Returns Number.
 */

Chain.prototype.isActive = co(function* isActive(prev, deployment) {
  var state = yield this.getState(prev, deployment);
  return state === common.thresholdStates.ACTIVE;
});

/**
 * Get chain entry state for a deployment (BIP9: versionbits).
 * @method
 * @example
 * yield chain.getState(tip, deployments.segwit);
 * @see https://github.com/bitcoin/bips/blob/master/bip-0009.mediawiki
 * @param {ChainEntry} prev - Previous chain entry.
 * @param {String} id - Deployment id.
 * @returns {Promise} - Returns Number.
 */

Chain.prototype.getState = co(function* getState(prev, deployment) {
  var period = this.network.minerWindow;
  var threshold = this.network.activationThreshold;
  var thresholdStates = common.thresholdStates;
  var bit = deployment.bit;
  var compute = [];
  var i, entry, count, state, cached;
  var block, time, height;

  if (((prev.height + 1) % period) !== 0) {
    height = prev.height - ((prev.height + 1) % period);
    prev = yield prev.getAncestor(height);

    if (!prev)
      return thresholdStates.DEFINED;

    assert(prev.height === height);
    assert(((prev.height + 1) % period) === 0);
  }

  entry = prev;
  state = thresholdStates.DEFINED;

  while (entry) {
    cached = this.db.stateCache.get(bit, entry);

    if (cached !== -1) {
      state = cached;
      break;
    }

    time = yield entry.getMedianTime();

    if (time < deployment.startTime) {
      state = thresholdStates.DEFINED;
      this.db.stateCache.set(bit, entry, state);
      break;
    }

    compute.push(entry);

    height = entry.height - period;
    entry = yield entry.getAncestor(height);
  }

  while (compute.length) {
    entry = compute.pop();

    switch (state) {
      case thresholdStates.DEFINED:
        time = yield entry.getMedianTime();

        if (time >= deployment.timeout) {
          state = thresholdStates.FAILED;
          break;
        }

        if (time >= deployment.startTime) {
          state = thresholdStates.STARTED;
          break;
        }

        break;
      case thresholdStates.STARTED:
        time = yield entry.getMedianTime();

        if (time >= deployment.timeout) {
          state = thresholdStates.FAILED;
          break;
        }

        block = entry;
        count = 0;

        for (i = 0; i < period; i++) {
          if (block.hasBit(bit))
            count++;

          if (count >= threshold) {
            state = thresholdStates.LOCKED_IN;
            break;
          }

          block = yield block.getPrevious();
          assert(block);
        }

        break;
      case thresholdStates.LOCKED_IN:
        state = thresholdStates.ACTIVE;
        break;
      case thresholdStates.FAILED:
      case thresholdStates.ACTIVE:
        break;
      default:
        assert(false, 'Bad state.');
        break;
    }

    this.db.stateCache.set(bit, entry, state);
  }

  return state;
});

/**
 * Compute the version for a new block (BIP9: versionbits).
 * @method
 * @see https://github.com/bitcoin/bips/blob/master/bip-0009.mediawiki
 * @param {ChainEntry} prev - Previous chain entry (usually the tip).
 * @returns {Promise} - Returns Number.
 */

Chain.prototype.computeBlockVersion = co(function* computeBlockVersion(prev) {
  var version = 0;
  var i, deployment, state;

  for (i = 0; i < this.network.deploys.length; i++) {
    deployment = this.network.deploys[i];
    state = yield this.getState(prev, deployment);

    if (state === common.thresholdStates.LOCKED_IN
        || state === common.thresholdStates.STARTED) {
      version |= 1 << deployment.bit;
    }
  }

  version |= consensus.VERSION_TOP_BITS;
  version >>>= 0;

  return version;
});

/**
 * Get the current deployment state of the chain. Called on load.
 * @method
 * @private
 * @returns {Promise} - Returns {@link DeploymentState}.
 */

Chain.prototype.getDeploymentState = co(function* getDeploymentState() {
  var prev = yield this.tip.getPrevious();

  if (!prev) {
    assert(this.tip.isGenesis());
    return this.state;
  }

  if (this.options.spv)
    return this.state;

  return yield this.getDeployments(this.tip.ts, prev);
});

/**
 * Check transaction finality, taking into account MEDIAN_TIME_PAST
 * if it is present in the lock flags.
 * @method
 * @param {ChainEntry} prev - Previous chain entry.
 * @param {TX} tx
 * @param {LockFlags} flags
 * @returns {Promise} - Returns Boolean.
 */

Chain.prototype.verifyFinal = co(function* verifyFinal(prev, tx, flags) {
  var height = prev.height + 1;
  var ts;

  // We can skip MTP if the locktime is height.
  if (tx.locktime < consensus.LOCKTIME_THRESHOLD)
    return tx.isFinal(height, -1);

  if (flags & common.lockFlags.MEDIAN_TIME_PAST) {
    ts = yield prev.getMedianTime();
    return tx.isFinal(height, ts);
  }

  return tx.isFinal(height, this.network.now());
});

/**
 * Get the necessary minimum time and height sequence locks for a transaction.
 * @method
 * @param {ChainEntry} prev
 * @param {TX} tx
 * @param {CoinView} view
 * @param {LockFlags} flags
 * @returns {Promise}
 * [Error, Number(minTime), Number(minHeight)].
 */

Chain.prototype.getLocks = co(function* getLocks(prev, tx, view, flags) {
  var mask = consensus.SEQUENCE_MASK;
  var granularity = consensus.SEQUENCE_GRANULARITY;
  var disableFlag = consensus.SEQUENCE_DISABLE_FLAG;
  var typeFlag = consensus.SEQUENCE_TYPE_FLAG;
  var hasFlag = flags & common.lockFlags.VERIFY_SEQUENCE;
  var nextHeight = this.height + 1;
  var minHeight = -1;
  var minTime = -1;
  var coinHeight, coinTime;
  var i, input, entry;

  if (tx.isCoinbase() || tx.version < 2 || !hasFlag)
    return new LockTimes(minHeight, minTime);

  for (i = 0; i < tx.inputs.length; i++) {
    input = tx.inputs[i];

    if (input.sequence & disableFlag)
      continue;

    coinHeight = view.getHeight(input);

    if (coinHeight === -1)
      coinHeight = nextHeight;

    if ((input.sequence & typeFlag) === 0) {
      coinHeight += (input.sequence & mask) - 1;
      minHeight = Math.max(minHeight, coinHeight);
      continue;
    }

    entry = yield prev.getAncestor(Math.max(coinHeight - 1, 0));
    assert(entry, 'Database is corrupt.');

    coinTime = yield entry.getMedianTime();
    coinTime += ((input.sequence & mask) << granularity) - 1;
    minTime = Math.max(minTime, coinTime);
  }

  return new LockTimes(minHeight, minTime);
});

/**
 * Verify sequence locks.
 * @method
 * @param {ChainEntry} prev
 * @param {TX} tx
 * @param {CoinView} view
 * @param {LockFlags} flags
 * @returns {Promise} - Returns Boolean.
 */

Chain.prototype.verifyLocks = co(function* verifyLocks(prev, tx, view, flags) {
  var locks = yield this.getLocks(prev, tx, view, flags);
  var mtp;

  // Also catches case where
  // height is `-1`. Fall through.
  if (locks.height >= prev.height + 1)
    return false;

  if (locks.time === -1)
    return true;

  mtp = yield prev.getMedianTime();

  if (locks.time >= mtp)
    return false;

  return true;
});

/**
 * ChainOptions
 * @alias module:blockchain.ChainOptions
 * @constructor
 * @param {Object} options
 */

function ChainOptions(options) {
  if (!(this instanceof ChainOptions))
    return new ChainOptions(options);

  this.network = Network.primary;
  this.logger = Logger.global;

  this.prefix = null;
  this.location = null;
  this.db = 'memory';
  this.maxFiles = 64;
  this.cacheSize = 32 << 20;
  this.compression = true;
  this.bufferKeys = ChainDB.layout.binary;

  this.spv = false;
  this.prune = false;
  this.indexTX = false;
  this.indexAddress = false;
  this.forceWitness = false;

  this.coinCache = 0;
  this.entryCache = 5000;
  this.orphanLimit = 20 << 20;
  this.checkpoints = true;

  if (options)
    this.fromOptions(options);
}

/**
 * Inject properties from object.
 * @private
 * @param {Object} options
 * @returns {ChainOptions}
 */

ChainOptions.prototype.fromOptions = function fromOptions(options) {
  if (options.network != null)
    this.network = Network.get(options.network);

  if (options.logger != null) {
    assert(typeof options.logger === 'object');
    this.logger = options.logger;
  }

  if (options.spv != null) {
    assert(typeof options.spv === 'boolean');
    this.spv = options.spv;
  }

  if (options.prefix != null) {
    assert(typeof options.prefix === 'string');
    this.prefix = options.prefix;
    this.location = this.spv
      ? this.prefix + '/spvchain'
      : this.prefix + '/chain';
  }

  if (options.location != null) {
    assert(typeof options.location === 'string');
    this.location = options.location;
  }

  if (options.db != null) {
    assert(typeof options.db === 'string');
    this.db = options.db;
  }

  if (options.maxFiles != null) {
    assert(util.isNumber(options.maxFiles));
    this.maxFiles = options.maxFiles;
  }

  if (options.cacheSize != null) {
    assert(util.isNumber(options.cacheSize));
    this.cacheSize = options.cacheSize;
  }

  if (options.compression != null) {
    assert(typeof options.compression === 'boolean');
    this.compression = options.compression;
  }

  if (options.prune != null) {
    assert(typeof options.prune === 'boolean');
    this.prune = options.prune;
  }

  if (options.indexTX != null) {
    assert(typeof options.indexTX === 'boolean');
    this.indexTX = options.indexTX;
  }

  if (options.indexAddress != null) {
    assert(typeof options.indexAddress === 'boolean');
    this.indexAddress = options.indexAddress;
  }

  if (options.forceWitness != null) {
    assert(typeof options.forceWitness === 'boolean');
    this.forceWitness = options.forceWitness;
  }

  if (options.coinCache != null) {
    assert(util.isNumber(options.coinCache));
    this.coinCache = options.coinCache;
  }

  if (options.entryCache != null) {
    assert(util.isNumber(options.entryCache));
    this.entryCache = options.entryCache;
  }

  if (options.orphanLimit != null) {
    assert(util.isNumber(options.orphanLimit));
    this.orphanLimit = options.orphanLimit;
  }

  if (options.checkpoints != null) {
    assert(typeof options.checkpoints === 'boolean');
    this.checkpoints = options.checkpoints;
  }

  return this;
};

/**
 * Instantiate chain options from object.
 * @param {Object} options
 * @returns {ChainOptions}
 */

ChainOptions.fromOptions = function fromOptions(options) {
  return new ChainOptions().fromOptions(options);
};

/**
 * Represents the deployment state of the chain.
 * @alias module:blockchain.DeploymentState
 * @constructor
 * @property {VerifyFlags} flags
 * @property {LockFlags} lockFlags
 * @property {Boolean} bip34
 */

function DeploymentState() {
  if (!(this instanceof DeploymentState))
    return new DeploymentState();

  this.flags = Script.flags.MANDATORY_VERIFY_FLAGS;
  this.flags &= ~Script.flags.VERIFY_P2SH;
  this.lockFlags = common.lockFlags.MANDATORY_LOCKTIME_FLAGS;
  this.bip34 = false;
}

/**
 * Test whether p2sh is active.
 * @returns {Boolean}
 */

DeploymentState.prototype.hasP2SH = function hasP2SH() {
  return (this.flags & Script.flags.VERIFY_P2SH) !== 0;
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
  return (this.flags & Script.flags.VERIFY_DERSIG) !== 0;
};

/**
 * Test whether cltv is active.
 * @returns {Boolean}
 */

DeploymentState.prototype.hasCLTV = function hasCLTV() {
  return (this.flags & Script.flags.VERIFY_CHECKLOCKTIMEVERIFY) !== 0;
};

/**
 * Test whether median time past locktime is active.
 * @returns {Boolean}
 */

DeploymentState.prototype.hasMTP = function hasMTP() {
  return (this.lockFlags & common.lockFlags.MEDIAN_TIME_PAST) !== 0;
};

/**
 * Test whether csv is active.
 * @returns {Boolean}
 */

DeploymentState.prototype.hasCSV = function hasCSV() {
  return (this.flags & Script.flags.VERIFY_CHECKSEQUENCEVERIFY) !== 0;
};

/**
 * Test whether segwit is active.
 * @returns {Boolean}
 */

DeploymentState.prototype.hasWitness = function hasWitness() {
  return (this.flags & Script.flags.VERIFY_WITNESS) !== 0;
};

/**
 * LockTimes
 * @constructor
 * @ignore
 */

function LockTimes(height, time) {
  this.height = height;
  this.time = time;
}

/**
 * ContextResult
 * @constructor
 * @ignore
 */

function ContextResult(view, state) {
  this.view = view;
  this.state = state;
}

/*
 * Expose
 */

module.exports = Chain;
