/*!
 * chain.js - blockchain management for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var AsyncObject = require('../utils/async');
var Network = require('../protocol/network');
var Logger = require('../node/logger');
var ChainDB = require('./chaindb');
var constants = require('../protocol/constants');
var util = require('../utils/util');
var btcutils = require('../btc/utils');
var Locker = require('../utils/locker');
var ChainEntry = require('./chainentry');
var CoinView = require('./coinview');
var assert = require('assert');
var errors = require('../btc/errors');
var VerifyError = errors.VerifyError;
var VerifyResult = errors.VerifyResult;
var co = require('../utils/co');

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

  this.network = Network.get(options.network);
  this.logger = options.logger || Logger.global;
  this.db = new ChainDB(this);
  this.total = 0;
  this.currentBlock = null;
  this.orphanLimit = options.orphanLimit || (20 << 20);
  this.locker = new Locker(true);
  this.invalid = {};
  this.bestHeight = -1;
  this.tip = null;
  this.height = -1;
  this.synced = false;
  this.state = new DeploymentState();
  this._time = util.hrtime();

  this.orphan = {
    map: {},
    bmap: {},
    count: 0,
    size: 0
  };

  this._init();
}

util.inherits(Chain, AsyncObject);

/**
 * Initialize the chain.
 * @private
 */

Chain.prototype._init = function _init() {
  var self = this;

  this.locker.on('purge', function(total, size) {
    self.logger.warning('Warning: %dmb of pending objects. Purging.', util.mb(size));
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
      util.revHex(expected),
      block.rhash
    );
  });

  this.on('reorganize', function(block, height, expected) {
    self.logger.warning(
      'Reorg at height %d: old=%s new=%s',
      height,
      util.revHex(expected),
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
      count, util.mb(size));
  });
};

/**
 * Open the chain, wait for the database to load.
 * @alias Chain#open
 * @returns {Promise}
 */

Chain.prototype._open = co(function* open() {
  var tip, state;

  this.logger.info('Chain is loading.');

  if (this.options.useCheckpoints)
    this.logger.info('Checkpoints are enabled.');

  if (this.options.coinCache)
    this.logger.info('Coin cache is enabled.');

  yield this.db.open();

  tip = yield this.db.getTip();

  assert(tip);

  this.tip = tip;
  this.height = tip.height;

  this.logger.info('Chain Height: %d', tip.height);

  if (tip.height > this.bestHeight)
    this.bestHeight = tip.height;

  this.logger.memory();

  state = yield this.getDeploymentState();

  this.setDeploymentState(state);

  this.logger.memory();

  this.emit('tip', tip);

  if (!this.synced && this.isFull()) {
    this.synced = true;
    this.emit('full');
  }
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
 * @private
 * @param {Block|MerkleBlock} block
 * @param {ChainEntry} entry
 * @returns {Promise}
 */

Chain.prototype.verifyContext = co(function* verifyContext(block, prev) {
  var state, view;

  // Initial non-contextual verification.
  state = yield this.verify(block, prev);

  // BIP30 - Verify there are no duplicate txids.
  yield this.verifyDuplicates(block, prev, state);

  // Verify scripts, spend and add coins.
  view = yield this.verifyInputs(block, prev, state);

  return new ContextResult(view, state);
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
 * @private
 * @param {Block|MerkleBlock} block
 * @param {ChainEntry} entry
 * @returns {Promise}
 * [{@link VerifyError}, {@link VerifyFlags}].
 */

Chain.prototype.verify = co(function* verify(block, prev) {
  var ret = new VerifyResult();
  var now = this.network.now();
  var i, err, height, ts, tx, medianTime;
  var commit, ancestors, state;

  // Skip the genesis block.
  if (this.isGenesis(block))
    return this.state;

  if (!block.verify(now, ret)) {
    err = new VerifyError(block,
      'invalid',
      ret.reason,
      ret.score);

    // High hash is the only thing an
    // adversary couldn't mutate in
    // otherwise valid non-contextual
    // checks. The block timestamp
    // can't be mutated, but our
    // adjusted time might be off.
    // We may be able to accept the
    // block later.
    if (ret.reason !== 'high-hash')
      err.malleated = true;

    throw err;
  }

  // Skip all blocks in spv mode.
  if (this.options.spv)
    return this.state;

  // Skip any blocks below the
  // last checkpoint.
  if (!this.options.witness) {
    // We can't skip this with segwit
    // enabled since the block may have
    // been malleated: we don't know
    // until we verify the witness
    // merkle root.
    if (prev.isHistorical())
      return this.state;
  }

  height = prev.height + 1;
  ancestors = yield prev.getRetargetAncestors();
  medianTime = prev.getMedianTime(ancestors);

  // Ensure the timestamp is correct.
  if (block.ts <= medianTime) {
    throw new VerifyError(block,
      'invalid',
      'time-too-old',
      0);
  }

  // Ensure the POW is what we expect.
  if (block.bits !== this.getTarget(block, prev, ancestors)) {
    throw new VerifyError(block,
      'invalid',
      'bad-diffbits',
      100);
  }

  // Get the new deployment state.
  state = yield this.getDeployments(block, prev);

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
        err = new VerifyError(block,
          'invalid',
          'bad-witness-merkle-size',
          100);
        err.malleated = true;
        throw err;
      }

      if (!util.equal(commit, block.createCommitmentHash())) {
        err = new VerifyError(block,
          'invalid',
          'bad-witness-merkle-match',
          100);
        err.malleated = true;
        throw err;
      }
    }
  }

  // Blocks that do not commit to
  // witness data cannot contain it.
  if (!commit) {
    if (block.hasWitness()) {
      err = new VerifyError(block,
        'invalid',
        'unexpected-witness',
        100);
      err.malleated = true;
      throw err;
    }
  }

  // Check block weight (different from block size
  // check in non-contextual verification).
  if (block.getWeight() > constants.block.MAX_WEIGHT) {
    throw new VerifyError(block,
      'invalid',
      'bad-blk-weight',
      100);
  }

  // Get timestamp for tx.isFinal().
  ts = state.hasMTP() ? medianTime : block.ts;

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

  return state;
});

/**
 * Check all deployments on a chain, ranging from p2sh to segwit.
 * @param {Block} block
 * @param {ChainEntry} prev
 * @returns {Promise}
 * [{@link VerifyError}, {@link DeploymentState}].
 */

Chain.prototype.getDeployments = co(function* getDeployments(block, prev) {
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
  if (block.ts >= constants.block.BIP16_TIME)
    state.flags |= constants.flags.VERIFY_P2SH;

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

  // Only allow version 5 blocks (bip141 - segnet3)
  // once the majority of blocks are using it.
  if (this.options.witness && this.network.oldWitness) {
    if (block.version < 5 && height >= this.network.block.bip141height)
      throw new VerifyError(block, 'obsolete', 'bad-version', 0);
  }

  // Coinbase heights are now enforced (bip34).
  if (height >= this.network.block.bip34height)
    state.bip34 = true;

  // Signature validation is now enforced (bip66).
  if (height >= this.network.block.bip66height)
    state.flags |= constants.flags.VERIFY_DERSIG;

  // CHECKLOCKTIMEVERIFY is now usable (bip65)
  if (height >= this.network.block.bip65height)
    state.flags |= constants.flags.VERIFY_CHECKLOCKTIMEVERIFY;

  // Segregrated witness is now usable (bip141 - segnet3)
  if (this.options.witness && this.network.oldWitness) {
    if (height >= this.network.block.bip141height)
      state.flags |= constants.flags.VERIFY_WITNESS;
  }

  if (this.network.oldWitness)
    return state;

  // CHECKSEQUENCEVERIFY and median time
  // past locktimes are now usable (bip9 & bip113).
  active = yield this.isActive(prev, deployments.csv);
  if (active) {
    state.flags |= constants.flags.VERIFY_CHECKSEQUENCEVERIFY;
    state.lockFlags |= constants.flags.VERIFY_SEQUENCE;
    state.lockFlags |= constants.flags.MEDIAN_TIME_PAST;
  }

  // Segregrated witness is now usable (bip141 - segnet4)
  active = yield this.isActive(prev, deployments.witness);
  if (active) {
    if (this.options.witness)
      state.flags |= constants.flags.VERIFY_WITNESS;
    // BIP147
    state.flags |= constants.flags.VERIFY_NULLDUMMY;
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

  if (!this.state.hasWitness() && state.hasWitness())
    this.logger.warning('Segwit has been activated.');

  if (!this.state.hasCSV() && state.hasCSV())
    this.logger.warning('CSV has been activated.');

  this.state = state;
};

/**
 * Determine whether to check block for duplicate txids in blockchain
 * history (BIP30). If we're on a chain that has bip34 activated, we
 * can skip this.
 * @private
 * @see https://github.com/bitcoin/bips/blob/master/bip-0030.mediawiki
 * @param {Block|MerkleBlock} block
 * @param {ChainEntry} prev
 * @returns {Promise}
 */

Chain.prototype.verifyDuplicates = co(function* verifyDuplicates(block, prev, state) {
  var height = prev.height + 1;
  var i, tx, result;

  if (this.options.spv)
    return;

  if (this.isGenesis(block))
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
      if (constants.bip30[height]) {
        if (block.hash('hex') === constants.bip30[height])
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
 * useCheckpoints is enabled, it will skip verification
 * for historical data.
 * @private
 * @see TX#checkInputs
 * @param {Block} block
 * @param {ChainEntry} prev
 * @param {DeploymentState} state
 * @returns {Promise}
 */

Chain.prototype.verifyInputs = co(function* verifyInputs(block, prev, state) {
  var height = prev.height + 1;
  var historical = prev.isHistorical();
  var sigops = 0;
  var jobs = [];
  var ret = new VerifyResult();
  var i, view, tx, valid;

  if (this.options.spv)
    return new CoinView();

  if (this.isGenesis(block))
    return new CoinView();

  view = yield this.db.getCoinView(block);

  // Check all transactions
  for (i = 0; i < block.txs.length; i++) {
    tx = block.txs[i];

    // Ensure tx is not double spending an output.
    if (!tx.isCoinbase()) {
      if (!view.fillCoins(tx)) {
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
      view.addTX(tx);
      continue;
    }

    // Verify sequence locks.
    valid = yield this.verifyLocks(prev, tx, state.lockFlags);

    if (!valid) {
      throw new VerifyError(block,
        'invalid',
        'bad-txns-nonfinal',
        100);
    }

    // Count sigops (legacy + scripthash? + witness?)
    sigops += tx.getSigopsWeight(state.flags);

    if (sigops > constants.block.MAX_SIGOPS_WEIGHT) {
      throw new VerifyError(block,
        'invalid',
        'bad-blk-sigops',
        100);
    }

    // Contextual sanity checks.
    if (!tx.isCoinbase()) {
      if (!tx.checkInputs(height, ret)) {
        throw new VerifyError(block,
          'invalid',
          ret.reason,
          ret.score);
      }

      // Push onto verification queue.
      jobs.push(tx.verifyAsync(state.flags));
    }

    // Add new coins.
    view.addTX(tx);
  }

  if (historical)
    return view;

  // Verify all txs in parallel.
  valid = yield co.every(jobs);

  if (!valid) {
    throw new VerifyError(block,
      'invalid',
      'mandatory-script-verify-flag-failed',
      100);
  }

  // Make sure the miner isn't trying to conjure more coins.
  if (block.getClaimed() > block.getReward(this.network)) {
    throw new VerifyError(block,
      'invalid',
      'bad-cb-amount',
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
 * @private
 * @param {ChainEntry} competitor - The competing chain's tip.
 * @param {Block|MerkleBlock} block - The being being added.
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

  this.emit('reorganize', block, tip.height, tip.hash);
});

/**
 * Reorganize the blockchain for SPV. This
 * will reset the chain to the fork block.
 * @private
 * @param {ChainEntry} competitor - The competing chain's tip.
 * @param {Block|MerkleBlock} block - The being being added.
 * @returns {Promise}
 */

Chain.prototype.reorganizeSPV = co(function* reorganizeSPV(competitor, block) {
  var tip = this.tip;
  var fork = yield this.findFork(tip, competitor);
  var disconnect = [];
  var entry = tip;
  var i;

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
    this.emit('disconnect', entry, entry.toHeaders());
  }

  this.emit('reorganize', block, tip.height, tip.hash);
});

/**
 * Disconnect an entry from the chain (updates the tip).
 * @param {ChainEntry} entry
 * @returns {Promise}
 */

Chain.prototype.disconnect = co(function* disconnect(entry) {
  var block = yield this.db.disconnect(entry);
  var prev = yield entry.getPrevious();

  assert(prev);

  this.tip = prev;
  this.height = prev.height;
  this.bestHeight = prev.height;

  this.emit('tip', prev);
  this.emit('disconnect', entry, block);
});

/**
 * Reconnect an entry to the chain (updates the tip).
 * This will do contextual-verification on the block
 * (necessary because we cannot validate the inputs
 * in alternate chains when they come in).
 * @param {ChainEntry} entry
 * @returns {Promise}
 */

Chain.prototype.reconnect = co(function* reconnect(entry) {
  var block = yield this.db.getBlock(entry.hash);
  var prev, result;

  if (this.options.spv) {
    assert(!block);
    block = entry.toHeaders();
  } else {
    assert(block);
  }

  prev = yield entry.getPrevious();
  assert(prev);

  try {
    result = yield this.verifyContext(block, prev);
  } catch (e) {
    if (e.type === 'VerifyError') {
      if (!e.malleated)
        this.invalid[entry.hash] = true;
      this.emit('invalid', block, entry.height);
    }
    throw e;
  }

  yield this.db.reconnect(entry, block, result.view);

  this.tip = entry;
  this.height = entry.height;
  this.bestHeight = entry.height;
  this.setDeploymentState(result.state);

  this.emit('tip', entry);
  this.emit('reconnect', entry, block);
  this.emit('connect', entry, block);
});

/**
 * Set the best chain. This is called on every valid block
 * that comes in. It may add and connect the block (main chain),
 * save the block without connection (alternate chain), or
 * reorganize the chain (a higher fork).
 * @private
 * @param {ChainEntry} entry
 * @param {Block|MerkleBlock} block
 * @param {ChainEntry} prev
 * @returns {Promise}
 */

Chain.prototype.setBestChain = co(function* setBestChain(entry, block, prev) {
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
    result = yield this.verifyContext(block, prev);
  } catch (e) {
    // Couldn't verify block.
    // Revert the height.
    block.setHeight(-1);

    if (e.type === 'VerifyError') {
      if (!e.malleated)
        this.invalid[entry.hash] = true;
      this.emit('invalid', block, entry.height);
    }

    throw e;
  }

  // Save block and connect inputs.
  yield this.db.save(entry, block, result.view);

  // Expose the new state.
  this.tip = entry;
  this.height = entry.height;
  this.setDeploymentState(result.state);

  this.emit('tip', entry);
});

/**
 * Save block on an alternate chain.
 * @private
 * @param {ChainEntry} entry
 * @param {Block|MerkleBlock} block
 * @param {ChainEntry} prev
 * @returns {Promise}
 */

Chain.prototype.saveAlternate = co(function* saveAlternate(entry, block, prev) {
  try {
    // Do as much verification
    // as we can before saving.
    yield this.verify(block, prev);
  } catch (e) {
    // Couldn't verify block.
    // Revert the height.
    block.setHeight(-1);

    if (e.type === 'VerifyError') {
      if (!e.malleated)
        this.invalid[entry.hash] = true;
      this.emit('invalid', block, entry.height);
    }

    throw e;
  }

  // Warn of unknown versionbits.
  if (entry.hasUnknown()) {
    this.logger.warning(
      'Unknown version bits in block %d: %d.',
      entry.height, entry.version);
  }

  yield this.db.save(entry, block);
});

/**
 * Reset the chain to the desired block. This
 * is useful for replaying the blockchain download
 * for SPV.
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
  this.synced = this.isFull(true);

  state = yield this.getDeploymentState();
  this.setDeploymentState(state);

  this.emit('tip', tip);

  if (!silent)
    this.emit('reset', tip);

  // Reset the orphan map completely. There may
  // have been some orphans on a forked chain we
  // no longer need.
  this.purgeOrphans();
});

/**
 * Reset the chain to a height or hash. Useful for replaying
 * the blockchain download for SPV.
 * @param {Hash|Number} block - hash/height
 * @returns {Promise}
 */

Chain.prototype.replay = co(function* replay(block) {
  var unlock = yield this.locker.lock();
  try {
    return yield this._replay(block);
  } finally {
    unlock();
  }
});

/**
 * Reset the chain without a lock.
 * @private
 * @param {Hash|Number} block - hash/height
 * @returns {Promise}
 */

Chain.prototype._replay = co(function* replay(block) {
  var entry = yield this.db.getEntry(block);

  if (!entry)
    throw new Error('Block not found.');

  if (!(yield entry.isMainChain()))
    throw new Error('Cannot reset on alternate chain.');

  if (entry.isGenesis())
    return yield this._reset(entry.hash, true);

  yield this._reset(entry.prevBlock, true);
});

/**
 * Scan the blockchain for transactions containing specified address hashes.
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
 * Wait for the chain to drain (finish processing
 * all of the blocks in its queue).
 * @returns {Promise}
 */

Chain.prototype.onDrain = function onDrain() {
  return this.locker.onDrain();
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
 * @returns {Promise}
 */

Chain.prototype.add = co(function* add(block) {
  var unlock = yield this.locker.lock(block);

  assert(!this.currentBlock);

  this.currentBlock = block.hash('hex');

  try {
    return yield this._add(block);
  } finally {
    this.currentBlock = null;
    unlock();
  }
});

/**
 * Add a block to the chain without a lock.
 * @private
 * @param {Block|MerkleBlock|MemBlock} block
 * @returns {Promise}
 */

Chain.prototype._add = co(function* add(block) {
  var ret = new VerifyResult();
  var now = this.network.now();
  var initial = true;
  var hash, prevBlock, height, checkpoint;
  var orphan, entry, existing, prev;

  while (block) {
    hash = block.hash('hex');
    prevBlock = block.prevBlock;
    height = -1;

    // Mark the start time.
    this.mark();

    // Do not revalidate known invalid blocks.
    if (this.invalid[hash] || this.invalid[prevBlock]) {
      this.emit('invalid', block, block.getCoinbaseHeight());
      this.invalid[hash] = true;
      throw new VerifyError(block, 'duplicate', 'duplicate', 100);
    }

    // Do we already have this block?
    if (this.hasPending(hash)) {
      this.emit('exists', block, block.getCoinbaseHeight());
      throw new VerifyError(block, 'duplicate', 'duplicate', 0);
    }

    // If the block is already known to be
    // an orphan, ignore it.
    orphan = this.orphan.map[prevBlock];
    if (orphan) {
      // The orphan chain forked.
      if (orphan.hash('hex') !== hash) {
        this.emit('fork', block,
          block.getCoinbaseHeight(),
          orphan.hash('hex'));
      }

      this.emit('orphan', block, block.getCoinbaseHeight());

      throw new VerifyError(block, 'invalid', 'bad-prevblk', 0);
    }

    // Special case for genesis block.
    if (hash === this.network.genesis.hash)
      break;

    // Validate the block we want to add.
    // This is only necessary for new
    // blocks coming in, not the resolving
    // orphans.
    if (initial && !block.verify(now, ret)) {
      if (ret.reason === 'high-hash')
        this.invalid[hash] = true;
      this.emit('invalid', block, block.getCoinbaseHeight());
      throw new VerifyError(block, 'invalid', ret.reason, ret.score);
    }

    existing = yield this.db.hasEntry(hash);

    // Do we already have this block?
    if (existing) {
      this.emit('exists', block, block.getCoinbaseHeight());
      throw new VerifyError(block, 'duplicate', 'duplicate', 0);
    }

    // Find the previous block height/index.
    prev = yield this.db.getEntry(prevBlock);

    if (prev)
      height = prev.height + 1;

    if (height > this.bestHeight)
      this.bestHeight = height;

    // If previous block wasn't ever seen,
    // add it current to orphans and break.
    if (!prev) {
      this.orphan.count++;
      this.orphan.size += block.getSize();
      this.orphan.map[prevBlock] = block;
      this.orphan.bmap[hash] = block;

      // Update the best height based on the coinbase.
      // We do this even for orphans (peers will send
      // us their highest block during the initial
      // getblocks sync, making it an orphan).
      if (block.getCoinbaseHeight() > this.bestHeight)
        this.bestHeight = block.getCoinbaseHeight();

      this.emit('orphan', block, block.getCoinbaseHeight());

      throw new VerifyError(block, 'invalid', 'bad-prevblk', 0);
    }

    // Verify the checkpoint.
    if (this.options.useCheckpoints) {
      checkpoint = this.network.checkpoints[height];
      if (checkpoint) {
        // Someone is either mining on top of
        // an old block for no reason, or the
        // consensus protocol is broken and
        // there was a 20k+ block reorg.
        if (hash !== checkpoint) {
          this.logger.warning('Checkpoint mismatch!');

          this.purgeOrphans();

          this.emit('fork', block, height, checkpoint);

          throw new VerifyError(block,
            'checkpoint',
            'checkpoint mismatch',
            100);
        }

        this.emit('checkpoint', block, height);
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
        this.logger.error(e);
        throw new VerifyError(block,
          'malformed',
          'error parsing message',
          100);
      }
    }

    // Update the block height early
    // Some things in verifyContext may
    // need access to height on txs.
    block.setHeight(height);

    // Create a new chain entry.
    entry = ChainEntry.fromBlock(this, block, prev);

    // The block is on a alternate chain if the
    // chainwork is less than or equal to
    // our tip's. Add the block but do _not_
    // connect the inputs.
    if (entry.chainwork.cmp(this.tip.chainwork) <= 0) {
      // Save block to an alternate chain.
      yield this.saveAlternate(entry, block, prev);

      // Emit as a "competitor" block.
      this.emit('competitor', block, entry);

      if (!initial)
        this.emit('competitor resolved', block, entry);
    } else {
      // Attempt to add block to the chain index.
      yield this.setBestChain(entry, block, prev);

      // Emit our block (and potentially resolved
      // orphan) only if it is on the main chain.
      this.emit('block', block, entry);
      this.emit('connect', entry, block);

      if (!initial)
        this.emit('resolved', block, entry);
    }

    // Keep track of stats.
    this.finish(block, entry);

    // No orphan chain.
    if (!this.orphan.map[hash])
      break;

    // An orphan chain was found, start resolving.
    initial = false;
    block = this.orphan.map[hash];
    delete this.orphan.bmap[block.hash('hex')];
    delete this.orphan.map[hash];
    this.orphan.count--;
    this.orphan.size -= block.getSize();
  }

  // Failsafe for large orphan chains. Do not
  // allow more than 20mb stored in memory.
  if (this.orphan.size > this.orphanLimit)
    this.pruneOrphans();

  yield co.wait();

  if (!this.synced && this.isFull()) {
    this.synced = true;
    this.emit('full');
  }
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
  this._time = util.hrtime();
};

/**
 * Calculate the time difference from
 * start time and log block.
 * @private
 * @param {Block} block
 * @param {ChainEntry} entry
 */

Chain.prototype.finish = function finish(block, entry) {
  var elapsed, time;

  // Keep track of total blocks handled.
  this.total += 1;

  if (!this.isSlow())
    return;

  // Report memory for debugging.
  util.gc();
  this.logger.memory();

  elapsed = util.hrtime(this._time);
  time = elapsed[0] * 1000 + elapsed[1] / 1e6;

  this.logger.info(
    'Block %s (%d) added to chain (size=%d txs=%d time=%d).',
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
  var count = this.orphan.count;
  var size = this.orphan.size;

  if (count === 0)
    return;

  this.orphan.map = {};
  this.orphan.bmap = {};
  this.orphan.count = 0;
  this.orphan.size = 0;

  this.emit('purge', count, size);
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
 * @returns {Promise} - Returns Boolean.
 */

Chain.prototype.has = co(function* has(hash) {
  if (this.hasOrphan(hash))
    return true;

  if (this.hasPending(hash))
    return true;

  if (hash === this.currentBlock)
    return true;

  return yield this.hasEntry(hash);
});

/**
 * Find a block entry by timestamp.
 * @param {Number} ts - Timestamp.
 * @returns {Promise} - Returns {@link ChainEntry}.
 */

Chain.prototype.byTime = co(function* byTime(ts) {
  var start = 0;
  var end = this.height;
  var pos, delta, entry;

  if (ts >= this.tip.ts)
    return this.tip;

  // Do a binary search for a block
  // mined within an hour of the
  // timestamp.
  while (start < end) {
    pos = (start + end) >>> 1;
    entry = yield this.db.getEntry(pos);

    if (!entry)
      return;

    delta = Math.abs(ts - entry.ts);

    if (delta <= 60 * 60)
      break;

    if (ts < entry.ts)
      end = pos - 1;
    else
      start = pos + 1;
  }

  return entry;
});

/**
 * Test the chain to see if it contains a block.
 * @param {Hash} hash
 * @returns {Promise} - Returns Boolean.
 */

Chain.prototype.hasEntry = function hasEntry(hash) {
  return this.db.hasEntry(hash);
};

/**
 * Test the chain to see if it contains an orphan.
 * @param {Hash} hash
 * @returns {Promise} - Returns Boolean.
 */

Chain.prototype.hasOrphan = function hasOrphan(hash) {
  return !!this.getOrphan(hash);
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
 * Find the corresponding block entry by hash or height.
 * @param {Hash|Number} hash/height
 * @returns {Promise} - Returns {@link ChainEntry}.
 */

Chain.prototype.getEntry = function getEntry(hash, callback) {
  return this.db.getEntry(hash);
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

Chain.prototype.isFull = function isFull(force) {
  return !this.isInitial(force);
};

/**
 * Test the chain to see if it is still in the initial
 * syncing phase. Mimic's bitcoind's `IsInitialBlockDownload()`
 * function.
 * @see IsInitalBlockDownload()
 * @returns {Boolean}
 */

Chain.prototype.isInitial = function isInitial(force) {
  if (!force && this.synced)
    return false;

  if (this.height < this.network.checkpoints.lastHeight)
    return true;

  if (this.height < this.bestHeight - 24 * 6)
    return true;

  if (this.tip.ts < util.now() - this.network.block.maxTipAge)
    return true;

  return false;
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
 * @param {(Number|Hash)?} start - Height or hash to treat as the tip.
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
 * @private
 * @param {(Number|Hash)?} start
 * @returns {Promise}
 */

Chain.prototype._getLocator = co(function* getLocator(start) {
  var hashes = [];
  var step = 1;
  var height, entry, main, hash;

  if (start == null)
    start = this.tip.hash;

  entry = yield this.db.getEntry(start);

  if (!entry) {
    // We could simply return `start` here,
    // but there is no required "spacing"
    // for locator hashes. Pretend this hash
    // is our tip. This is useful for
    // getheaders.
    if (typeof start === 'string')
      hashes.push(start);
    entry = this.tip;
  }

  height = entry.height;
  main = yield entry.isMainChain();
  hash = entry.hash;

  while (hash) {
    hashes.push(hash);

    if (height === 0)
      break;

    height = Math.max(height - step, 0);

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
 * Will also calculate "orphan soil" -- the block needed
 * in * order to resolve the orphan root.
 * @param {Hash} hash
 * @returns {Hash}
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
 * @returns {Promise} - returns Number
 * (target is in compact/mantissa form).
 */

Chain.prototype.getCurrentTarget = co(function* getCurrentTarget() {
  return yield this.getTargetAsync(null, this.tip);
});

/**
 * Calculate the target based on the passed-in chain entry.
 * @param {ChainEntry} prev - Previous entry.
 * @param {Block|MerkleBlock|null} - Current block.
 * @returns {Promise} - returns Number
 * (target is in compact/mantissa form).
 */

Chain.prototype.getTargetAsync = co(function* getTargetAsync(block, prev) {
  var pow = this.network.pow;
  var ancestors;

  if ((prev.height + 1) % pow.retargetInterval !== 0) {
    if (!pow.difficultyReset)
      return this.getTarget(block, prev);
  }

  ancestors = yield prev.getAncestors(pow.retargetInterval);

  return this.getTarget(block, prev, ancestors);
});

/**
 * Calculate the target synchronously. _Must_
 * have ancestors pre-allocated.
 * @param {Block|MerkleBlock|null} - Current block.
 * @param {ChainEntry} prev - Previous entry.
 * @returns {Promise} - returns Number
 * (target is in compact/mantissa form).
 */

Chain.prototype.getTarget = function getTarget(block, prev, ancestors) {
  var pow = this.network.pow;
  var ts, first, i;

  // Genesis
  if (!prev)
    return pow.bits;

  // Do not retarget
  if ((prev.height + 1) % pow.retargetInterval !== 0) {
    if (pow.difficultyReset) {
      // Special behavior for testnet:
      ts = block ? (block.ts || block) : this.network.now();
      if (ts > prev.ts + pow.targetSpacing * 2)
        return pow.bits;

      i = 1;
      while (ancestors[i]
        && prev.height % pow.retargetInterval !== 0
        && prev.bits === pow.bits) {
        prev = ancestors[i++];
      }
    }
    return prev.bits;
  }

  // Back 2 weeks
  first = ancestors[pow.retargetInterval - 1];

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
  var pow = this.network.pow;
  var targetTimespan = pow.targetTimespan;
  var actualTimespan, target;

  if (pow.noRetargeting)
    return prev.bits;

  actualTimespan = prev.ts - first.ts;
  target = btcutils.fromCompact(prev.bits);

  if (actualTimespan < targetTimespan / 4 | 0)
    actualTimespan = targetTimespan / 4 | 0;

  if (actualTimespan > targetTimespan * 4)
    actualTimespan = targetTimespan * 4;

  target.imuln(actualTimespan);
  target.idivn(targetTimespan);

  if (target.cmp(pow.limit) > 0)
    return pow.bits;

  return btcutils.toCompact(target);
};

/**
 * Find a locator. Analagous to bitcoind's `FindForkInGlobalIndex()`.
 * @param {Hash[]} locator - Hashes.
 * @returns {Promise} - Returns {@link Hash} (the
 * hash of the latest known block).
 */

Chain.prototype.findLocator = co(function* findLocator(locator) {
  var i, hash, main;

  for (i = 0; i < locator.length; i++) {
    hash = locator[i];
    main = yield this.db.isMainChain(hash);

    if (main)
      return hash;
  }

  return this.network.genesis.hash;
});

/**
 * Check whether a versionbits deployment is active (BIP9: versionbits).
 * @example
 * chain.isActive(entry, 'witness', callback);
 * @see https://github.com/bitcoin/bips/blob/master/bip-0009.mediawiki
 * @param {ChainEntry} prev - Previous chain entry.
 * @param {String} id - Deployment id.
 * @returns {Promise} - Returns Number.
 */

Chain.prototype.isActive = co(function* isActive(prev, deployment) {
  var state;

  if (!this.options.witness) {
    if (prev.isHistorical())
      return false;
  }

  state = yield this.getState(prev, deployment);

  return state === constants.thresholdStates.ACTIVE;
});

/**
 * Get chain entry state for a deployment (BIP9: versionbits).
 * @example
 * chain.getState(entry, 'witness', callback);
 * @see https://github.com/bitcoin/bips/blob/master/bip-0009.mediawiki
 * @param {ChainEntry} prev - Previous chain entry.
 * @param {String} id - Deployment id.
 * @returns {Promise} - Returns Number.
 */

Chain.prototype.getState = co(function* getState(prev, deployment) {
  var period = this.network.minerWindow;
  var threshold = this.network.activationThreshold;
  var thresholdStates = constants.thresholdStates;
  var bit = deployment.bit;
  var compute = [];
  var i, entry, count, state, cached;
  var block, time, height;

  if (!prev)
    return thresholdStates.DEFINED;

  if (((prev.height + 1) % period) !== 0) {
    height = prev.height - ((prev.height + 1) % period);
    prev = yield prev.getAncestor(height);

    if (prev) {
      assert(prev.height === height);
      assert(((prev.height + 1) % period) === 0);
    }
  }

  entry = prev;
  state = thresholdStates.DEFINED;

  while (entry) {
    cached = this.db.stateCache.get(bit, entry);

    if (cached !== -1) {
      state = cached;
      break;
    }

    time = yield entry.getMedianTimeAsync();

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
        time = yield entry.getMedianTimeAsync();

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
        time = yield entry.getMedianTimeAsync();

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

    if (state === constants.thresholdStates.LOCKED_IN
        || state === constants.thresholdStates.STARTED) {
      version |= 1 << deployment.bit;
    }
  }

  version |= constants.versionbits.TOP_BITS;
  version >>>= 0;

  return version;
});

/**
 * Get the current deployment state of the chain. Called on load.
 * @private
 * @returns {Promise} - Returns {@link DeploymentState}.
 */

Chain.prototype.getDeploymentState = co(function* getDeploymentState() {
  var prev = yield this.tip.getPrevious();

  if (!prev) {
    assert(this.tip.isGenesis());
    return this.state;
  }

  return yield this.getDeployments(this.tip.toHeaders(), prev);
});

/**
 * Check transaction finality, taking into account MEDIAN_TIME_PAST
 * if it is present in the lock flags.
 * @param {ChainEntry} prev - Previous chain entry.
 * @param {TX} tx
 * @param {LockFlags} flags
 * @returns {Promise} - Returns Boolean.
 */

Chain.prototype.checkFinal = co(function* checkFinal(prev, tx, flags) {
  var height = prev.height + 1;
  var ts;

  // We can skip MTP if the locktime is height.
  if (tx.locktime < constants.LOCKTIME_THRESHOLD)
    return tx.isFinal(height, -1);

  if (flags & constants.flags.MEDIAN_TIME_PAST) {
    ts = yield prev.getMedianTimeAsync();
    return tx.isFinal(height, ts);
  }

  return tx.isFinal(height, this.network.now());
});

/**
 * Get the necessary minimum time and height sequence locks for a transaction.
 * @param {TX} tx
 * @param {LockFlags} flags
 * @param {ChainEntry} prev
 * @returns {Promise}
 * [Error, Number(minTime), Number(minHeight)].
 */

Chain.prototype.getLocks = co(function* getLocks(prev, tx, flags) {
  var mask = constants.sequence.MASK;
  var granularity = constants.sequence.GRANULARITY;
  var disableFlag = constants.sequence.DISABLE_FLAG;
  var typeFlag = constants.sequence.TYPE_FLAG;
  var hasFlag = flags & constants.flags.VERIFY_SEQUENCE;
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

    coinHeight = input.coin.height !== -1
      ? input.coin.height
      : this.height + 1;

    if ((input.sequence & typeFlag) === 0) {
      coinHeight += (input.sequence & mask) - 1;
      minHeight = Math.max(minHeight, coinHeight);
      continue;
    }

    entry = yield prev.getAncestor(Math.max(coinHeight - 1, 0));
    assert(entry, 'Database is corrupt.');

    coinTime = yield entry.getMedianTimeAsync();
    coinTime += ((input.sequence & mask) << granularity) - 1;
    minTime = Math.max(minTime, coinTime);
  }

  return new LockTimes(minHeight, minTime);
});

/**
 * Verify sequence locks.
 * @param {TX} tx
 * @param {LockFlags} flags
 * @param {ChainEntry} prev
 * @returns {Promise} - Returns Boolean.
 */

Chain.prototype.verifyLocks = co(function* verifyLocks(prev, tx, flags) {
  var locks = yield this.getLocks(prev, tx, flags);
  var medianTime;

  if (locks.height >= prev.height + 1)
    return false;

  if (locks.time === -1)
    return true;

  medianTime = yield prev.getMedianTimeAsync();

  if (locks.time >= medianTime)
    return false;

  return true;
});

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

/**
 * LockTimes
 * @constructor
 */

function LockTimes(height, time) {
  this.height = height;
  this.time = time;
}

/**
 * ContextResult
 * @constructor
 */

function ContextResult(view, state) {
  this.view = view;
  this.state = state;
}

/*
 * Expose
 */

module.exports = Chain;
