/*!
 * chain.js - blockchain management for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('bsert');
const path = require('path');
const AsyncEmitter = require('bevent');
const Logger = require('blgr');
const {Lock} = require('bmutex');
const {BufferMap} = require('buffer-map');
const BN = require('bcrypto/lib/bn.js');
const Network = require('../protocol/network');
const ChainDB = require('./chaindb');
const common = require('./common');
const consensus = require('../protocol/consensus');
const util = require('../utils/util');
const ChainEntry = require('./chainentry');
const CoinView = require('../coins/coinview');
const Script = require('../script/script');
const {VerifyError} = require('../protocol/errors');
const thresholdStates = common.thresholdStates;

/**
 * Blockchain
 * @alias module:blockchain.Chain
 * @property {ChainDB} db
 * @property {ChainEntry?} tip
 * @property {Number} height
 * @property {DeploymentState} state
 */

class Chain extends AsyncEmitter {
  /**
   * Create a blockchain.
   * @constructor
   * @param {Object} options
   */

  constructor(options) {
    super();

    this.opened = false;
    this.closing = false;
    this.options = new ChainOptions(options);

    this.network = this.options.network;
    this.logger = this.options.logger.context('chain');
    this.blocks = this.options.blocks;
    this.workers = this.options.workers;

    this.db = new ChainDB(this.options);

    this.locker = new Lock(true, BufferMap);
    this.state = new DeploymentState();

    this.tip = new ChainEntry();
    this.height = -1;
    this.synced = false;

    this.ids = new BufferMap();
  }

  /**
   * Open the chain, wait for the database to load.
   * @returns {Promise}
   */

  async open() {
    assert(!this.opened, 'Chain is already open.');
    this.opened = true;

    this.logger.info('Chain is loading.');

    if (this.options.checkpoints)
      this.logger.info('Checkpoints are enabled.');

    if (this.options.bip91)
      this.logger.warning('BIP91 enabled. Segsignal will be enforced.');

    if (this.options.bip148)
      this.logger.warning('BIP148 enabled. UASF will be enforced.');

    await this.db.open();

    const tip = await this.db.getTip();

    assert(tip);

    this.tip = tip;
    this.height = tip.height;

    this.logger.info('Chain Height: %d', tip.height);

    this.logger.memory();

    const state = await this.getDeploymentState();

    this.setDeploymentState(state);

    this.logger.memory();

    this.emit('tip', tip);

    this.maybeSync();
  }

  /**
   * Preclose actions.
   * @returns {Promise}
   */

  async preclose() {
    this.closing = true;
  }

  /**
   * Close the chain, wait for the database to close.
   * @returns {Promise}
   */

  async close() {
    assert(this.opened, 'Chain is not open.');
    this.closing = true;
    this.opened = false;
    await this.db.close();
    this.closing = false;
  }

  /**
   * Perform all necessary contextual verification on a block.
   * @private
   * @param {Block} block
   * @param {ChainEntry} prev
   * @returns {Promise} - Returns {@link ContextResult}.
   */

  async verifyContext(block, prev) {
    // Get the new deployment state.
    const state = await this.getDeployments(block.time, prev);

    // Skip everything if we're in SPV mode.
    if (this.options.spv) {
      const view = new CoinView();
      return [view, state];
    }

    // Skip everything if we're using checkpoints.
    if (this.isHistorical(prev)) {
      const view = await this.updateInputs(block, prev);
      return [view, state];
    }

    // BIP30 - Verify there are no duplicate txids.
    // Note that BIP34 made it impossible to create
    // duplicate txids.
    if (!state.hasBIP34())
      await this.verifyDuplicates(block, prev);

    // Verify scripts, spend and add coins.
    const view = await this.verifyInputs(block, prev, state);

    return [view, state];
  }

  /**
   * Perform all necessary contextual verification
   * on a block, without POW check.
   * @param {Block} block
   * @returns {Promise}
   */

  async verifyBlock(block) {
    const unlock = await this.locker.lock();
    try {
      return await this._verifyBlock(block);
    } finally {
      unlock();
    }
  }

  /**
   * Perform all necessary contextual verification
   * on a block, without POW check (no lock).
   * @private
   * @param {Block} block
   * @returns {Promise}
   */

  async _verifyBlock(block) {
    const flags = common.flags.DEFAULT_FLAGS & ~common.flags.VERIFY_POW;
    await this.verify(block, this.tip, flags);
    return this.verifyContext(block, this.tip);
  }

  /**
   * Test whether the hash is in the main chain.
   * @param {Hash} hash
   * @returns {Promise} - Returns Boolean.
   */

  isMainHash(hash) {
    return this.db.isMainHash(hash);
  }

  /**
   * Test whether the entry is in the main chain.
   * @param {ChainEntry} entry
   * @returns {Promise} - Returns Boolean.
   */

  isMainChain(entry) {
    return this.db.isMainChain(entry);
  }

  /**
   * Find the last common ancestor between
   * two blocks.
   * @param {ChainEntry} a
   * @param {ChainEntry} b
   * @returns {Promise} - Returns {@link ChainEntry}[].
   */

  async commonAncestor(a, b) {
    if (a.height > b.height) {
      a = await this.getAncestor(a, b.height);
    } else if (b.height > a.height) {
      b = await this.getAncestor(b, a.height);
    }

    while (a && b && !a.hash.equals(b.hash)) {
      a = await this.getPrevious(a);
      b = await this.getPrevious(b);
    }

    if (a && b)
      return a;

    return null;
  }

  /**
   * Get ancestor by `height`.
   * @param {ChainEntry} entry
   * @param {Number} height
   * @returns {Promise} - Returns ChainEntry.
   */

  getAncestor(entry, height) {
    return this.db.getAncestor(entry, height);
  }

  /**
   * Get previous entry.
   * @param {ChainEntry} entry
   * @returns {Promise} - Returns ChainEntry.
   */

  getPrevious(entry) {
    return this.db.getPrevious(entry);
  }

  /**
   * Get previous cached entry.
   * @param {ChainEntry} entry
   * @returns {ChainEntry|null}
   */

  getPrevCache(entry) {
    return this.db.getPrevCache(entry);
  }

  /**
   * Get next entry.
   * @param {ChainEntry} entry
   * @returns {Promise} - Returns ChainEntry.
   */

  getNext(entry) {
    return this.db.getNext(entry);
  }

  /**
   * Get next entry.
   * @param {ChainEntry} entry
   * @returns {Promise} - Returns ChainEntry.
   */

  getNextEntry(entry) {
    return this.db.getNextEntry(entry);
  }

  /**
   * Calculate median time past.
   * @param {ChainEntry} prev
   * @param {Number?} time
   * @returns {Promise} - Returns Number.
   */

  async getMedianTime(prev, time) {
    let timespan = consensus.MEDIAN_TIMESPAN;

    const median = [];

    // In case we ever want to check
    // the MTP of the _current_ block
    // (necessary for BIP148).
    if (time != null) {
      median.push(time);
      timespan -= 1;
    }

    let entry = prev;

    for (let i = 0; i < timespan && entry; i++) {
      median.push(entry.time);

      const cache = this.getPrevCache(entry);

      if (cache)
        entry = cache;
      else
        entry = await this.getPrevious(entry);
    }

    median.sort((a, b) => {
      return a - b;
    });

    return median[median.length >>> 1];
  }

  /**
   * Test whether the entry is potentially
   * an ancestor of a checkpoint.
   * @param {ChainEntry} prev
   * @returns {Boolean}
   */

  isHistorical(prev) {
    if (this.options.checkpoints) {
      if (prev.height + 1 <= this.network.lastCheckpoint)
        return true;
    }
    return false;
  }

  /**
   * Verify the block header.
   * @param {Block} header
   * @param {ChainEntry} prev
   * @returns {Promise}
   */

  async verifyHeader(header, prev) {
    // Verify header connects to the chain.
    if (!prev || !header.prevBlock.equals(prev.hash))
      throw new VerifyError(header, 'invalid', 'bad-prevblk', 0, true);

    // Verify a checkpoint if there is one.
    const hash = header.hash();
    if (!this.verifyCheckpoint(prev, hash)) {
      throw new VerifyError(header,
        'checkpoint',
        'checkpoint mismatch',
        100);
    }

    // Ensure the POW is what we expect.
    const bits = await this.getTarget(header.time, prev);

    if (header.bits !== bits) {
      throw new VerifyError(header,
        'invalid',
        'bad-diffbits',
        100);
    }

    // Ensure the timestamp is correct.
    const mtp = await this.getMedianTime(prev);

    if (header.time <= mtp) {
      throw new VerifyError(header,
        'invalid',
        'time-too-old',
        0);
    }

    // Check timestamp against adj-time+2hours.
    // If this fails we may be able to accept
    // the block header later.
    if (header.time > this.network.now() + 2 * 60 * 60) {
      throw new VerifyError(header,
        'invalid',
        'time-too-new',
        0,
        true);
    }

    // Calculate height of current block header.
    const height = prev.height + 1;

    // Only allow version 2 blocks (coinbase height)
    // once the majority of blocks are using it.
    if (header.version < 2 && height >= this.network.block.bip34height)
      throw new VerifyError(header, 'obsolete', 'bad-version', 0);

    // Only allow version 3 blocks (sig validation)
    // once the majority of blocks are using it.
    if (header.version < 3 && height >= this.network.block.bip66height)
      throw new VerifyError(header, 'obsolete', 'bad-version', 0);

    // Only allow version 4 blocks (checklocktimeverify)
    // once the majority of blocks are using it.
    if (header.version < 4 && height >= this.network.block.bip65height)
      throw new VerifyError(header, 'obsolete', 'bad-version', 0);
  }

  /**
   * Verify the block with the exception of coins and duplicates.
   * @private
   * @param {Block} block
   * @param {ChainEntry} prev
   * @param {Number} flags
   * @returns {Promise} - Returns {@link DeploymentState}.
   */

  async verify(block, prev, flags) {
    assert(typeof flags === 'number');

    // Extra sanity check.
    if (!prev || !block.prevBlock.equals(prev.hash))
      throw new VerifyError(block, 'invalid', 'bad-prevblk', 0, true);

    // Skip everything when using checkpoints.
    // We can do this safely because every
    // block in between each checkpoint was
    // validated outside in the header chain.
    if (this.isHistorical(prev)) {
      if (this.options.spv)
        return this.state;

      // Check merkle root.
      if (flags & common.flags.VERIFY_BODY) {
        assert(typeof block.createMerkleRoot === 'function');

        const root = block.createMerkleRoot();

        if (!root || !block.merkleRoot.equals(root)) {
          throw new VerifyError(block,
            'invalid',
            'bad-txnmrklroot',
            100,
            true);
        }

        flags &= ~common.flags.VERIFY_BODY;
      }

      // Once segwit is active, we will still
      // need to check for block mutability.
      if (!block.hasWitness() && !block.getCommitmentHash())
        return new DeploymentState();
    }

    // Non-contextual checks.
    if (flags & common.flags.VERIFY_BODY) {
      const [valid, reason, score] = block.checkBody();

      if (!valid)
        throw new VerifyError(block, 'invalid', reason, score, true);
    }

    // Skip all blocks in spv mode once
    // we've verified the network target.
    if (this.options.spv)
      return this.state;

    // Calculate height of current block.
    const height = prev.height + 1;

    // Get the new deployment state.
    const state = await this.getDeployments(block.time, prev);

    // Enforce BIP91/BIP148.
    if (state.hasBIP91() || state.hasBIP148()) {
      const {segwit} = this.network.deployments;
      if (!consensus.hasBit(block.version, segwit.bit))
        throw new VerifyError(block, 'invalid', 'bad-no-segwit', 0);
    }

    // Get timestamp for tx.isFinal().
    const mtp = await this.getMedianTime(prev);
    const time = state.hasMTP() ? mtp : block.time;

    // Transactions must be finalized with
    // regards to nSequence and nLockTime.
    for (const tx of block.txs) {
      if (!tx.isFinal(height, time)) {
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
    let commit = null;
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

        if (!commit.equals(block.createCommitmentHash())) {
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
  }

  /**
   * Check all deployments on a chain, ranging from p2sh to segwit.
   * @param {Number} time
   * @param {ChainEntry} prev
   * @returns {Promise} - Returns {@link DeploymentState}.
   */

  async getDeployments(time, prev) {
    const deployments = this.network.deployments;
    const height = prev.height + 1;
    const state = new DeploymentState();

    // For some reason bitcoind has p2sh in the
    // mandatory flags by default, when in reality
    // it wasn't activated until march 30th 2012.
    // The first p2sh output and redeem script
    // appeared on march 7th 2012, only it did
    // not have a signature. See:
    // 6a26d2ecb67f27d1fa5524763b49029d7106e91e3cc05743073461a719776192
    // 9c08a4d78931342b37fd5f72900fb9983087e6f46c4a097d8a1f52c74e28eaf6
    if (time >= consensus.BIP16_TIME)
      state.flags |= Script.flags.VERIFY_P2SH;

    // Coinbase heights are now enforced (bip34).
    if (height >= this.network.block.bip34height)
      state.bip34 = true;

    // Signature validation is now enforced (bip66).
    if (height >= this.network.block.bip66height)
      state.flags |= Script.flags.VERIFY_DERSIG;

    // CHECKLOCKTIMEVERIFY is now usable (bip65).
    if (height >= this.network.block.bip65height)
      state.flags |= Script.flags.VERIFY_CHECKLOCKTIMEVERIFY;

    // CHECKSEQUENCEVERIFY and median time
    // past locktimes are now usable (bip9 & bip113).
    if (await this.isActive(prev, deployments.csv)) {
      state.flags |= Script.flags.VERIFY_CHECKSEQUENCEVERIFY;
      state.lockFlags |= common.lockFlags.VERIFY_SEQUENCE;
      state.lockFlags |= common.lockFlags.MEDIAN_TIME_PAST;
    }

    // Check the state of the segwit deployment.
    const witness = await this.getState(prev, deployments.segwit);

    // Segregrated witness (bip141) is now usable
    // along with SCRIPT_VERIFY_NULLDUMMY (bip147).
    if (witness === thresholdStates.ACTIVE) {
      state.flags |= Script.flags.VERIFY_WITNESS;
      state.flags |= Script.flags.VERIFY_NULLDUMMY;
    }

    // Segsignal is now enforced (bip91).
    if (this.options.bip91) {
      if (witness === thresholdStates.STARTED) {
        if (await this.isActive(prev, deployments.segsignal))
          state.bip91 = true;
      }
    }

    // UASF is now enforced (bip148) (mainnet-only).
    if (this.options.bip148 && this.network === Network.main) {
      if (witness !== thresholdStates.LOCKED_IN
          && witness !== thresholdStates.ACTIVE) {
        // The BIP148 MTP check is nonsensical in
        // that it includes the _current_ entry's
        // timestamp. This requires some hackery,
        // since bcoin only operates on the sane
        // assumption that deployment checks should
        // only ever examine the values of the
        // previous block (necessary for mining).
        const mtp = await this.getMedianTime(prev, time);
        if (mtp >= 1501545600 && mtp <= 1510704000)
          state.bip148 = true;
      }
    }

    return state;
  }

  /**
   * Set a new deployment state.
   * @param {DeploymentState} state
   */

  setDeploymentState(state) {
    if (this.options.checkpoints && this.height < this.network.lastCheckpoint) {
      this.state = state;
      return;
    }

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

    if (!this.state.hasBIP91() && state.hasBIP91())
      this.logger.warning('BIP91 has been activated.');

    if (!this.state.hasBIP148() && state.hasBIP148())
      this.logger.warning('BIP148 has been activated.');

    this.state = state;
  }

  /**
   * Determine whether to check block for duplicate txids in blockchain
   * history (BIP30). If we're on a chain that has bip34 activated, we
   * can skip this.
   * @private
   * @see https://github.com/bitcoin/bips/blob/master/bip-0030.mediawiki
   * @param {Block} block
   * @param {ChainEntry} prev
   * @returns {Promise}
   */

  async verifyDuplicates(block, prev) {
    for (const tx of block.txs) {
      if (!await this.hasCoins(tx))
        continue;

      const height = prev.height + 1;
      const hash = this.network.bip30[height];

      // Blocks 91842 and 91880 created duplicate
      // txids by using the same exact output script
      // and extraNonce.
      if (!hash || !block.hash().equals(hash))
        throw new VerifyError(block, 'invalid', 'bad-txns-BIP30', 100);
    }
  }

  /**
   * Spend and update inputs (checkpoints only).
   * @private
   * @param {Block} block
   * @param {ChainEntry} prev
   * @returns {Promise} - Returns {@link CoinView}.
   */

  async updateInputs(block, prev) {
    const view = new CoinView();
    const height = prev.height + 1;
    const cb = block.txs[0];

    view.addTX(cb, height);

    for (let i = 1; i < block.txs.length; i++) {
      const tx = block.txs[i];

      assert(await view.spendInputs(this.db, tx),
        'BUG: Spent inputs in historical data!');

      view.addTX(tx, height);
    }

    return view;
  }

  /**
   * Check block transactions for all things pertaining
   * to inputs. This function is important because it is
   * what actually fills the coins into the block. This
   * function will check the block reward, the sigops,
   * the tx values, and execute and verify the scripts (it
   * will attempt to do this on the worker pool). If
   * `checkpoints` is enabled, it will skip verification
   * for historical data.
   * @private
   * @see TX#verifyInputs
   * @see TX#verify
   * @param {Block} block
   * @param {ChainEntry} prev
   * @param {DeploymentState} state
   * @returns {Promise} - Returns {@link CoinView}.
   */

  async verifyInputs(block, prev, state) {
    const view = new CoinView();
    const height = prev.height + 1;
    const interval = this.network.halvingInterval;

    let sigops = 0;
    let reward = 0;

    // Check all transactions
    for (let i = 0; i < block.txs.length; i++) {
      const tx = block.txs[i];

      // Ensure tx is not double spending an output.
      if (i > 0) {
        if (!await view.spendInputs(this.db, tx)) {
          throw new VerifyError(block,
            'invalid',
            'bad-txns-inputs-missingorspent',
            100);
        }
      }

      // Verify sequence locks.
      if (i > 0 && tx.version >= 2) {
        const valid = await this.verifyLocks(prev, tx, view, state.lockFlags);

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
        const [fee, reason, score] = tx.checkInputs(view, height);

        if (fee === -1) {
          throw new VerifyError(block,
            'invalid',
            reason,
            score);
        }

        reward += fee;

        if (reward > consensus.MAX_MONEY) {
          throw new VerifyError(block,
            'invalid',
            'bad-txns-accumulated-fee-outofrange',
            100);
        }
      }

      // Add new coins.
      view.addTX(tx, height);
    }

    // Make sure the miner isn't trying to conjure more coins.
    reward += consensus.getReward(height, interval);

    if (block.getClaimed() > reward) {
      throw new VerifyError(block,
        'invalid',
        'bad-cb-amount',
        100);
    }

    // Push onto verification queue.
    const jobs = [];
    for (let i = 1; i < block.txs.length; i++) {
      const tx = block.txs[i];
      jobs.push(tx.verifyAsync(view, state.flags, this.workers));
    }

    // Verify all txs in parallel.
    const results = await Promise.all(jobs);

    for (const result of results) {
      if (!result) {
        throw new VerifyError(block,
          'invalid',
          'mandatory-script-verify-flag-failed',
          100);
      }
    }

    return view;
  }

  /**
   * Disconnect an entry from the chain (updates the tip).
   * @param {ChainEntry} entry
   * @returns {Promise}
   */

  async disconnect(entry) {
    let block = await this.getBlock(entry.hash);

    // Sanity check.
    assert(entry.height !== 0);

    if (!block) {
      if (!this.options.spv)
        throw new Error('Block not found.');
      block = entry.toHeaders();
    }

    const prev = await this.getPrevious(entry);
    const view = await this.db.disconnect(entry, block);

    assert(prev);

    this.tip = prev;
    this.height = prev.height;

    this.emit('tip', prev);

    return this.emitAsync('disconnect', entry, block, view);
  }

  /**
   * Connect an entry to the chain (updates the tip).
   * This will do contextual-verification on the block.
   * @param {Block} block
   * @param {ChainEntry} entry
   * @param {ChainEntry} prev
   * @returns {Promise} - Returns {@link ChainEntry}.
   */

  async connect(block, entry, prev) {
    const start = util.bench();

    // Sanity check.
    assert(block.prevBlock.equals(prev.hash));
    assert(prev.hash.equals(this.tip.hash));

    const hash = block.hash();

    let view, state;
    try {
      [view, state] = await this.verifyContext(block, prev);
    } catch (err) {
      if (err.type === 'VerifyError') {
        await this.setInvalid(hash);

        // Let networking, or other listeners, know
        // about the bad block to ban the peer.
        const id = this.ids.get(hash);
        this.emit('bad block', err, id);

        this.logger.warning(
          'Tried to connect invalid block: %h (%d).',
          entry.hash, entry.height);
      }
      throw err;
    } finally {
      this.ids.delete(hash);
    }

    // Connect entry to main chain.
    await this.db.connect(entry, block, view);

    // Expose the new state.
    this.tip = entry;
    this.height = entry.height;
    this.setDeploymentState(state);

    this.emit('tip', entry);

    // We only emit block events for verified blocks.
    this.emit('block', block, entry);

    await this.emitAsync('connect', entry, block, view);

    // Check sync state.
    this.maybeSync();

    // Keep track of stats.
    this.logStatus(start, block, entry);

    return entry;
  }

  /**
   * Reset the chain to the desired block. This
   * is useful for replaying the blockchain download
   * for SPV.
   * @param {Hash|Number} block
   * @returns {Promise}
   */

  async reset(block) {
    const unlock = await this.locker.lock();
    try {
      return await this._reset(block, false);
    } finally {
      unlock();
    }
  }

  /**
   * Reset the chain to the desired block without a lock.
   * @private
   * @param {Hash|Number} block
   * @returns {Promise}
   */

  async _reset(block, silent) {
    const tip = await this.db.reset(block);

    // Reset state.
    this.tip = tip;
    this.height = tip.height;
    this.synced = false;

    const state = await this.getDeploymentState();

    this.setDeploymentState(state);

    this.emit('tip', tip);

    if (!silent)
      await this.emitAsync('reset', tip);

    this.maybeSync();
  }

  /**
   * Reset the chain to a height or hash. Useful for replaying
   * the blockchain download for SPV.
   * @param {Hash|Number} block - hash/height
   * @returns {Promise}
   */

  async replay(block) {
    const unlock = await this.locker.lock();
    try {
      return await this._replay(block, true);
    } finally {
      unlock();
    }
  }

  /**
   * Reset the chain without a lock.
   * @private
   * @param {Hash|Number} block - hash/height
   * @param {Boolean?} silent
   * @returns {Promise}
   */

  async _replay(block, silent) {
    const entry = await this.getEntry(block);

    if (!entry)
      throw new Error('Block not found.');

    if (!await this.isMainChain(entry))
      throw new Error('Cannot reset on alternate chain.');

    if (entry.isGenesis()) {
      await this._reset(entry.hash, silent);
      return;
    }

    await this._reset(entry.prevBlock, silent);
  }

  /**
   * Invalidate block.
   * @param {Hash} hash
   * @returns {Promise}
   */

  async invalidate(hash) {
    const unlock = await this.locker.lock();
    try {
      return await this._invalidate(hash);
    } finally {
      unlock();
    }
  }

  /**
   * Invalidate block (no lock).
   * @param {Hash} hash
   * @returns {Promise}
   */

  async _invalidate(hash) {
    await this._replay(hash, false);
    return this.setInvalid(hash);
  }

  /**
   * Retroactively prune the database.
   * @returns {Promise}
   */

  async prune() {
    const unlock = await this.locker.lock();
    try {
      return await this.db.prune();
    } finally {
      unlock();
    }
  }

  /**
   * Scan the blockchain for transactions containing specified address hashes.
   * @param {Hash} start - Block hash to start at.
   * @param {Bloom} filter - Bloom filter containing tx and address hashes.
   * @param {Function} iter - Iterator.
   * @returns {Promise}
   */

  async scan(start, filter, iter) {
    const unlock = await this.locker.lock();
    try {
      return await this.db.scan(start, filter, iter);
    } finally {
      unlock();
    }
  }

  /**
   * This will add a header to the chain.
   * @param {Block} header
   * @param {Number?} flags
   * @returns {Promise}
   */

  async addHeader(header, flags) {
    const hash = header.hash();
    const unlock = await this.locker.lock(hash);
    try {
      return await this._addHeader(header, flags);
    } finally {
      unlock();
    }
  }

  /**
   * This will add a header to the possible chain tips to be
   * consider as the best. It must connect to an existing chain
   * and have sufficient chainwork.
   * @param {Headers} header
   * @param {Number?} flags
   * @private
   * @returns {Promise}
   */

  async _addHeader(header, flags = common.flags.DEFAULT_FLAGS) {
    // Check the POW before doing anything.
    if (flags & common.flags.VERIFY_POW) {
      if (!header.verifyPOW())
        throw new VerifyError(header, 'invalid', 'high-hash', 50);
    }

    const hash = header.hash();

    // Do not revalidate known invalid blocks.
    if (await this.hasInvalid(header)) {
      this.logger.debug('Invalid ancestors for header: %h.', hash);
      throw new VerifyError(header, 'duplicate', 'duplicate', 100);
    }

    // Do we already have this header?
    if (await this.hasHeader(hash)) {
      this.logger.debug('Already have header: %h.', hash);
      throw new VerifyError(header, 'duplicate', 'duplicate', 0);
    }

    // Find the previous header entry.
    const prev = await this.getEntry(header.prevBlock);

    // Create a new chain entry.
    const entry = ChainEntry.fromBlock(header, prev);

    // Verify the header, and possibly mark as invalid.
    // and not to be tried again.
    try {
      await this.verifyHeader(header, prev);
    } catch (err) {
      if (err.type === 'VerifyError') {
        if (!err.malleated)
          this.setInvalid(entry.hash);
        this.logger.warning(
          'Invalid header: %h (%d).',
          entry.hash, entry.height);
      }
      throw err;
    }

    // Save the chain entry for the header
    // adding a new tip.
    await this.db.saveEntry(entry, prev);

    // Log status of headers.
    this.logHeaders(header, entry);

    return {entry, prev};
  }

  /**
   * Add block data to the chain. Headers need to add first
   * to show that it has enough chainwork and is valid.
   * @param {Block} block
   * @param {Object?} options
   * @param {ChainEntry?} options.entry
   * @param {ChainEntry?} options.prev
   * @param {Number?} options.flags
   * @param {Number?} options.id
   * @private
   * @returns {Promise}
   */

  async _addBlock(block, options) {
    let {entry, prev, flags, id} = options;

    const hash = block.hash();

    if (!entry)
      entry = await this.getEntryByHash(hash);

    if (!prev)
      prev = await this.getEntryByHash(block.prevBlock);

    if (flags == null)
      flags = common.flags.DEFAULT_FLAGS;

    // Verify that the block has not already been added.
    if (await this.db.hasBlock(block.hash()))
      throw new VerifyError(block, 'duplicate', 'duplicate', 0);

    try {
      // Do as much verification as we can before saving.
      await this.verify(block, prev, flags);
    } catch (err) {
      if (err.type === 'VerifyError') {
        if (!err.malleated)
          await this.setInvalid(entry.hash);
        this.logger.warning(
          'Invalid block on alternate chain: %h (%d).',
          entry.hash, entry.height);
      }
      throw err;
    }

    // Write the block to disk.
    await this.db.writeBlock(block);

    // Track the id for each block.
    if (id != null)
      this.ids.set(hash, id);

    // Emit as a "competitor" block if the block has been added
    // as is on a fork less than or equal to our current tip.
    if (entry.chainwork.lte(this.tip.chainwork)) {
      this.logger.warning('Heads up: Competing chain at height %d:'
        + ' tip-height=%d competitor-height=%d'
        + ' tip-hash=%h competitor-hash=%h'
        + ' tip-chainwork=%s competitor-chainwork=%s'
        + ' chainwork-diff=%s',
        entry.height,
        this.tip.height,
        entry.height,
        this.tip.hash,
        entry.hash,
        this.tip.chainwork.toString(),
        entry.chainwork.toString(),
        this.tip.chainwork.sub(entry.chainwork).toString());

      this.emit('competitor', block, entry);
    }
  }

  /**
   * Disconnect blocks to the given height and then attach the blocks
   * again. This is necessary when the wallet bloom filter is updated
   * and merkle blocks need to be downloaded again for an SPV node and
   * blocks need to be sent to the wallet again if it's running as a
   * separate process. This will disconnect blocks without removing
   * headers, full block data or alternative chains.
   * @param {Number} height
   * @returns {Promise}
   */

  async detach(height) {
    this.logger.debug('Detaching blocks to %d.', height);

    const tip = this.tip;

    const unlock = await this.locker.lock();
    try {
      while (this.tip.height > height) {
        const hash = this.tip.hash;

        // Only disconnect the block from the chain, headers
        // for the block remain, as well as the block data.
        await this.disconnect(this.tip);

        // For SPV, also remove merkle block as the filters are
        // now considered to be incomplete.
        if (this.options.spv)
          await this.blocks.pruneMerkle(hash);
      }
    } finally {
      unlock();
    }

    // A full node does not need to re-download blocks, however
    // the blocks need to be sent to the separate wallet process
    // again using the updated filter.
    await this.attach(tip);

    // An SPV node will need to re-download blocks using the updated
    // filter. Networking listens for the event and will resolve
    // headers to re-download blocks.
    this.emit('detach');
  }

  /**
   * Add a block to the chain from an existing saved header
   * entry and block.
   * @param {ChainEntry} entry
   * @returns {Promise}
   */

  async attach(entry) {
    // Verify that the entry is not already a part of
    // the main chain.
    if (await this.isMainChain(entry))
      return;

    const unlock = await this.locker.lock(entry.hash);
    const prev = await this.getPrevious(entry);
    try {
      await this._connectBest(entry, prev);
    } finally {
      unlock();
    }
  }

  /**
   * Add a block to the chain, perform all necessary verification.
   * @param {Block} block
   * @param {Number?} flags
   * @param {Number?} id
   * @returns {Promise}
   */

  async add(block, flags, id) {
    const hash = block.hash();
    const unlock = await this.locker.lock(hash);
    try {
      return await this._add(block, flags, id);
    } finally {
      unlock();
    }
  }

  /**
   * Add a block to the chain without a lock.
   * @private
   * @param {Block} block
   * @param {Number?} flags
   * @param {Number?} id
   * @returns {Promise}
   */

  async _add(block, flags, id) {
    // Perform all verification for the header
    // and save to disk if it hasn't already been added.
    let entry = await this.getEntryByHash(block.hash());
    let prev = null;
    if (!entry) {
      const header = block.toHeaders();
      const result = await this._addHeader(header, flags);
      entry = result.entry;
      prev = result.prev;
    } else {
      prev = await this.getEntryByHash(block.prevBlock);
    }

    // Explanation: we try to keep as much data
    // off the javascript heap as possible. Blocks
    // in the future may be 8mb or 20mb, who knows.
    // In fullnode-mode we store the blocks in
    // "compact" form (the headers plus the raw
    // Buffer object) until they're ready to be
    // fully validated here. They are deserialized,
    // validated, and connected. Hopefully the
    // deserialized blocks get cleaned up by the
    // GC quickly.
    if (block.isMemory()) {
      try {
        block = block.toBlock();
      } catch (e) {
        this.logger.error(e);
        throw new VerifyError(block,
          'malformed',
          'error parsing message',
          10,
          true);
      }
    }

    // Perform all possible verification for
    // the block (with the exception of coins)
    // and save to disk.
    await this._addBlock(block, {entry, prev, flags, id});

    // Try and verify and connect the block to the chain
    // and any blocks that follow.
    await this._connectBest(entry, prev, block);

    // Clean up the least work alternative chains.
    await this.pruneTips();

    return entry;
  }

  /**
   * This will prune the headers and tips to keep a maximum
   * number of the current best chain tips.
   * @returns {Promise}
   */

  async pruneTips() {
    await this.db.pruneTips(this.options.maxTips);
  }

  /**
   * Test if a block is ready to be connected.
   * @param {ChainEntry} entry
   * @returns {Promise} - Returns Boolean.
   */

  async isBlockReady(entry) {
    // Do not connect if we've already tried
    // to connect this block and it was invalid.
    if (await this.db.hasInvalid(entry.hash))
      return false;

    // Do not connect if we do not already have
    // the block data to verify.
    if (!await this.db.hasBlock(entry.hash))
      return false;

    return true;
  }

  /**
   * Will return the most work available path
   * from an entry (exclusive).
   * @param {ChainEntry} entry
   * @returns {Promise} - Returns {@link ChainEntry}[].
   */

  async getNextBest(entry) {
    const _getNextBest = async (entry) => {
      let maxWork = new BN(0);
      let maxPath = [];

      if (!await this.isBlockReady(entry))
        return maxPath;

      const entries = await this.db.getNextEntries(entry.hash);

      for (const next of entries) {
        const path = await _getNextBest(next);

        if (path.length > 0) {
          const chainwork = path[path.length - 1].chainwork;
          if (chainwork.gt(maxWork)) {
            maxWork = chainwork;
            maxPath = path;
          }
        }
      }

      maxPath.unshift(entry);

      return maxPath;
    };

    let path = await _getNextBest(entry);
    if (path.length > 0)
      path = path.slice(1, path.length);

    return path;
  }

  /**
   * Will try to connect the entry and any following blocks
   * to the current chain, if it has greater work.
   * @param {ChainEntry} entry
   * @param {ChainEntry} prev
   * @param {Block?} block
   * @returns {Promise} - Returns Boolean.
   */

  async _connectBest(entry, prev, block) {
    const tip = this.tip;

    // Sanity check.
    assert(entry.prevBlock.equals(prev.hash));

    let queue = [];

    // Check if this block should be connected.
    if (await this.isBlockReady(entry)) {
      queue.push({entry, prev, block});

      // See if there are any previous blocks
      // that are waiting to be connected.
      let head = entry;
      let headPrev = prev;
      while (!await this.isMainChain(headPrev)) {
        if (await this.isBlockReady(headPrev)) {
          head = headPrev;
          headPrev = await this.getPrevious(head);
          queue.unshift({entry: head, prev: headPrev});
        } else {
          return false;
        }
      }

      // See if there are any blocks following
      // that are waiting to be connected.
      const nexts = await this.getNextBest(entry);
      for (const next of nexts) {
        prev = entry;
        entry = next;
        queue.push({entry, prev});
      }

      // Verify that this new set of entries has greater
      // work than the current chain.
      const last = queue[queue.length - 1];
      if (!last.entry.chainwork.gt(this.tip.chainwork))
        queue = [];
    }

    // Nothing to be connected.
    if (!queue.length)
      return false;

    // In the case of a reorganization, disconnect blocks
    // until the best chain can be connected.
    const adjacent = () => this.tip.hash.equals(queue[0].entry.prevBlock);
    const reorg = !adjacent();
    while (!adjacent())
      await this.disconnect(this.tip);

    // Keep track of the common entry in case there
    // needs to be another attempt to connect.
    const common = this.tip;
    let error = false;

    // Try to connect blocks in the queue.
    for (let {block, entry, prev} of queue) {
      // Stop if closing.
      if (this.closing)
        break;

      if (!block)
        block = await this.getBlock(entry.hash);

      assert(block);

      try {
        await this.connect(block, entry, prev);
      } catch (err) {
        if (err.type === 'VerifyError') {
          error = err;
          break;
        } else {
          throw err;
        }
      }
    }

    // Let any listeners know about a reorganization, should
    // any blocks have been disconnected.
    if (reorg) {
      this.logger.warning(
        'Chain reorganization: old=%h(%d) new=%h(%d)',
        tip.hash,
        tip.height,
        this.tip.hash,
        this.tip.height
      );

      await this.emitAsync('reorganize', tip, this.tip);
    }

    // In the case of failure, there could be another valid best path.
    // The same path should not be tried again, as blocks are marked as
    // invalid with connect failure.
    if (error) {
      let entries = await this.db.getNextEntries(this.tip.hash);

      // Include entries from the common fork point that will
      // include the original chain, should it remain the best.
      entries = entries.concat(await this.db.getNextEntries(common.hash));

      for (const entry of entries) {
        const prev = await this.getPrevious(entry);
        try {
          await this._connectBest(entry, prev);
        } catch (err) {
          if (err.type !== 'VerifyError')
            throw err;
        }
      }

      // Only throw an error if it was for the
      // entry supplied, other verify errors are
      // emitted from connect.
      if (error.hash.equals(entry.hash))
        throw error;
    }

    return true;
  }

  /**
   * Test whether the chain has reached its slow height.
   * @private
   * @returns {Boolean}
   */

  isSlow() {
    if (this.options.spv)
      return false;

    if (this.synced)
      return true;

    if (this.height === 1 || this.height % 20 === 0)
      return true;

    if (this.height >= this.network.block.slowHeight)
      return true;

    return false;
  }

  /**
   * Log the status of headers.
   * @private
   * @param {Array} start
   * @param {Block} block
   * @param {ChainEntry} entry
   */

  logHeaders(header, entry) {
    if (entry.height % 6000 === 0) {
      this.logger.info('Headers Status: hash=%h time=%s height=%d target=%s',
        entry.hash,
        util.date(header.time),
        entry.height,
        header.bits);
    }
  }

  /**
   * Calculate the time difference from
   * start time and log block.
   * @private
   * @param {Array} start
   * @param {Block} block
   * @param {ChainEntry} entry
   */

  logStatus(start, block, entry) {
    if (this.height % 20 === 0) {
      this.logger.info('Status:'
        + ' time=%s height=%d progress=%s'
        + ' target=%s',
        util.date(block.time),
        this.height,
        (this.getProgress() * 100).toFixed(2) + '%',
        block.bits);
    }

    if (!this.isSlow())
      return;

    // Report memory for debugging.
    this.logger.memory();

    const elapsed = util.bench(start);

    this.logger.info(
      'Block %h (%d) added to chain (size=%d txs=%d elapsed=%d).',
      entry.hash,
      entry.height,
      block.getSize(),
      block.txs.length,
      elapsed);
  }

  /**
   * Verify a block hash and height against the checkpoints.
   * @private
   * @param {ChainEntry} prev
   * @param {Hash} hash
   * @returns {Boolean}
   */

  verifyCheckpoint(prev, hash) {
    if (!this.options.checkpoints)
      return true;

    const height = prev.height + 1;
    const checkpoint = this.network.checkpointMap[height];

    if (!checkpoint)
      return true;

    if (hash.equals(checkpoint)) {
      this.logger.debug('Hit checkpoint block %h (%d).',
        hash, height);
      this.emit('checkpoint', hash, height);
      return true;
    }

    // Someone is either mining on top of
    // an old block for no reason, or the
    // consensus protocol is broken and
    // there was a 20k+ block reorg.
    this.logger.warning(
      'Checkpoint mismatch at height %d: expected=%h received=%h',
      height,
      checkpoint,
      hash
    );

    return false;
  }

  /**
   * Test whether an invalid block hash has been seen.
   * @private
   * @param {Block} block
   * @returns {Promise} - Returns Boolean.
   */

  async hasInvalid(block) {
    const hash = block.hash();

    if (await this.db.hasInvalid(hash))
      return true;

    if (await this.db.hasInvalid(block.prevBlock)) {
      await this.db.setInvalid(hash);
      return true;
    }

    return false;
  }

  /**
   * Mark a block as invalid.
   * @private
   * @param {Hash} hash
   * @returns {Promise}
   */

  async setInvalid(hash) {
    return this.db.setInvalid(hash);
  }

  /**
   * Forget an invalid block hash.
   * @private
   * @param {Hash} hash
   * @returns {Promise}
   */

  async removeInvalid(hash) {
    return this.db.removeInvalid(hash);
  }

  /**
   * Test the chain to see if it contains a block header,
   * or has recently seen a block header.
   * @param {Hash} hash
   * @returns {Promise} - Returns Boolean.
   */

  async hasSeenHeader(hash) {
    if (await this.db.hasInvalid(hash))
      return true;

    if (this.locker.has(hash))
      return true;

    if (await this.hasHeader(hash))
      return true;

    return false;
  }

  /**
   * Find the corresponding block entry by hash or height.
   * @param {Hash|Number} hash/height
   * @returns {Promise} - Returns {@link ChainEntry}.
   */

  getEntry(hash) {
    return this.db.getEntry(hash);
  }

  /**
   * Retrieve a chain entry by height.
   * @param {Number} height
   * @returns {Promise} - Returns {@link ChainEntry}.
   */

  getEntryByHeight(height) {
    return this.db.getEntryByHeight(height);
  }

  /**
   * Retrieve a chain entry by hash.
   * @param {Hash} hash
   * @returns {Promise} - Returns {@link ChainEntry}.
   */

  getEntryByHash(hash) {
    return this.db.getEntryByHash(hash);
  }

  /**
   * Get the hash of a block by height. Note that this
   * will only return hashes in the main chain.
   * @param {Number} height
   * @returns {Promise} - Returns {@link Hash}.
   */

  getHash(height) {
    return this.db.getHash(height);
  }

  /**
   * Get the height of a block by hash.
   * @param {Hash} hash
   * @returns {Promise} - Returns Number.
   */

  getHeight(hash) {
    return this.db.getHeight(hash);
  }

  /**
   * Test the chain to see if it contains a header.
   * @param {Hash} hash
   * @returns {Promise} - Returns Boolean.
   */

  hasHeader(hash) {
    return this.db.hasHeader(hash);
  }

  /**
   * Get the _next_ block hash (does not work by height).
   * @param {Hash} hash
   * @returns {Promise} - Returns {@link Hash}.
   */

  getNextHash(hash) {
    return this.db.getNextHash(hash);
  }

  /**
   * Check whether coins are still unspent. Necessary for bip30.
   * @see https://bitcointalk.org/index.php?topic=67738.0
   * @param {TX} tx
   * @returns {Promise} - Returns Boolean.
   */

  hasCoins(tx) {
    return this.db.hasCoins(tx);
  }

  /**
   * Get all tip hashes.
   * @returns {Promise} - Returns {@link Hash}[].
   */

  getTipEntries() {
    return this.db.getTipEntries();
  }

  /**
   * Get the most chainwork entry.
   * @returns {ChainEntry}
   */

  mostWork() {
    assert(this.db.mostWork);
    return this.db.mostWork;
  }

  /**
   * Get range of hashes.
   * @param {Number} [start=-1]
   * @param {Number} [end=-1]
   * @returns {Promise}
   */

  getHashes(start = -1, end = -1) {
    return this.db.getHashes(start, end);
  }

  /**
   * Get a coin (unspents only).
   * @private
   * @param {Outpoint} prevout
   * @returns {Promise} - Returns {@link CoinEntry}.
   */

  readCoin(prevout) {
    return this.db.readCoin(prevout);
  }

  /**
   * Get a coin (unspents only).
   * @param {Hash} hash
   * @param {Number} index
   * @returns {Promise} - Returns {@link Coin}.
   */

  getCoin(hash, index) {
    return this.db.getCoin(hash, index);
  }

  /**
   * Retrieve a block from the database (not filled with coins).
   * @param {Hash} hash
   * @returns {Promise} - Returns {@link Block}.
   */

  getBlock(hash) {
    return this.db.getBlock(hash);
  }

  /**
   * Retrieve a block from the database (not filled with coins).
   * @param {Hash} hash
   * @returns {Promise} - Returns {@link Block}.
   */

  getRawBlock(block) {
    return this.db.getRawBlock(block);
  }

  /**
   * Get a historical block coin viewpoint.
   * @param {Block} hash
   * @returns {Promise} - Returns {@link CoinView}.
   */

  getBlockView(block) {
    return this.db.getBlockView(block);
  }

  /**
   * Get coin viewpoint.
   * @param {TX} tx
   * @returns {Promise} - Returns {@link CoinView}.
   */

  getCoinView(tx) {
    return this.db.getCoinView(tx);
  }

  /**
   * Test the chain to see if it is synced.
   * @returns {Boolean}
   */

  isFull() {
    return this.synced;
  }

  /**
   * Test the chain for recent headers that are
   * close to today.
   * @returns {Promise} - Returns Boolean.
   */

  isRecent() {
    const best = this.mostWork();
    const time = this.network.time.now() - this.network.block.maxTipAge;

    if (best.time > time)
      return true;

    return false;
  }

  /**
   * Potentially emit a `full` event.
   * @private
   */

  maybeSync() {
    if (this.synced)
      return;

    if (this.options.checkpoints) {
      if (this.height < this.network.lastCheckpoint)
        return;
    }

    if (this.tip.time < util.now() - this.network.block.maxTipAge)
      return;

    if (!this.hasChainwork())
      return;

    this.synced = true;
    this.emit('full');
  }

  /**
   * Test the chain to see if it has the
   * minimum required chainwork for the
   * network.
   * @returns {Boolean}
   */

  hasChainwork() {
    return this.tip.chainwork.gte(this.network.pow.chainwork);
  }

  /**
   * Get the fill percentage.
   * @returns {Number} percent - Ranges from 0.0 to 1.0.
   */

  getProgress() {
    const start = this.network.genesis.time;
    const current = this.tip.time - start;
    const end = util.now() - start - 40 * 60;
    return Math.min(1, current / end);
  }

  /**
   * Calculate chain locator (an array of hashes).
   * @param {Hash?} start - Height or hash to treat as the tip.
   * The current tip will be used if not present. Note that this can be a
   * non-existent hash, which is useful for headers-first locators.
   * @returns {Promise} - Returns {@link Hash}[].
   */

  async getLocator(start) {
    const unlock = await this.locker.lock();
    try {
      return await this._getLocator(start);
    } finally {
      unlock();
    }
  }

  /**
   * Calculate chain locator without a lock.
   * @private
   * @param {Hash?} start
   * @returns {Promise}
   */

  async _getLocator(start) {
    // Check if closing.
    if (this.closing)
      return [];

    if (start == null)
      start = this.tip.hash;

    assert(Buffer.isBuffer(start));

    let entry = await this.getEntry(start);

    const hashes = [];

    if (!entry) {
      entry = this.tip;
      hashes.push(start);
    }

    let main = await this.isMainChain(entry);
    let hash = entry.hash;
    let height = entry.height;
    let step = 1;

    hashes.push(hash);

    while (height > 0) {
      height -= step;

      if (height < 0)
        height = 0;

      if (hashes.length > 10)
        step *= 2;

      if (main) {
        // If we're on the main chain, we can
        // do a fast lookup of the hash.
        hash = await this.getHash(height);
        assert(hash);
      } else {
        const ancestor = await this.getAncestor(entry, height);
        assert(ancestor);
        main = await this.isMainChain(ancestor);
        hash = ancestor.hash;
      }

      hashes.push(hash);
    }

    return hashes;
  }

  /**
   * Calculate the time difference (in seconds)
   * between two blocks by examining chainworks.
   * @param {ChainEntry} to
   * @param {ChainEntry} from
   * @returns {Number}
   */

  getProofTime(to, from) {
    const pow = this.network.pow;
    let sign, work;

    if (to.chainwork.gt(from.chainwork)) {
      work = to.chainwork.sub(from.chainwork);
      sign = 1;
    } else {
      work = from.chainwork.sub(to.chainwork);
      sign = -1;
    }

    work = work.imuln(pow.targetSpacing);
    work = work.div(this.tip.getProof());

    if (work.bitLength() > 53)
      return sign * Number.MAX_SAFE_INTEGER;

    return sign * work.toNumber();
  }

  /**
   * Calculate the next target based on the chain tip.
   * @returns {Promise} - returns Number
   * (target is in compact/mantissa form).
   */

  async getCurrentTarget() {
    return this.getTarget(this.network.now(), this.tip);
  }

  /**
   * Calculate the next target.
   * @param {Number} time - Next block timestamp.
   * @param {ChainEntry} prev - Previous entry.
   * @returns {Promise} - returns Number
   * (target is in compact/mantissa form).
   */

  async getTarget(time, prev) {
    const pow = this.network.pow;

    // Genesis
    if (!prev) {
      assert(time === this.network.genesis.time);
      return pow.bits;
    }

    // Do not retarget
    if ((prev.height + 1) % pow.retargetInterval !== 0) {
      if (pow.targetReset) {
        // Special behavior for testnet:
        if (time > prev.time + pow.targetSpacing * 2)
          return pow.bits;

        while (prev.height !== 0
          && prev.height % pow.retargetInterval !== 0
          && prev.bits === pow.bits) {
          const cache = this.getPrevCache(prev);

          if (cache)
            prev = cache;
          else
            prev = await this.getPrevious(prev);

          assert(prev);
        }
      }
      return prev.bits;
    }

    // Back 2 weeks
    const height = prev.height - (pow.retargetInterval - 1);
    assert(height >= 0);

    const first = await this.getAncestor(prev, height);
    assert(first);

    return this.retarget(prev, first);
  }

  /**
   * Retarget. This is called when the chain height
   * hits a retarget diff interval.
   * @param {ChainEntry} prev - Previous entry.
   * @param {ChainEntry} first - Chain entry from 2 weeks prior.
   * @returns {Number} target - Target in compact/mantissa form.
   */

  retarget(prev, first) {
    const pow = this.network.pow;
    const targetTimespan = pow.targetTimespan;

    if (pow.noRetargeting)
      return prev.bits;

    const target = consensus.fromCompact(prev.bits);

    let actualTimespan = prev.time - first.time;

    if (actualTimespan < targetTimespan / 4 | 0)
      actualTimespan = targetTimespan / 4 | 0;

    if (actualTimespan > targetTimespan * 4)
      actualTimespan = targetTimespan * 4;

    target.imuln(actualTimespan);
    target.idivn(targetTimespan);

    if (target.gt(pow.limit))
      return pow.bits;

    return consensus.toCompact(target);
  }

  /**
   * Find a locator. Analagous to bitcoind's `FindForkInGlobalIndex()`.
   * @param {Hash[]} locator - Hashes.
   * @returns {Promise} - Returns {@link Hash} (the
   * hash of the latest known block).
   */

  async findLocator(locator) {
    for (const hash of locator) {
      if (await this.isMainHash(hash))
        return hash;
    }

    return this.network.genesis.hash;
  }

  /**
   * Check whether a versionbits deployment is active (BIP9: versionbits).
   * @example
   * await chain.isActive(tip, deployments.segwit);
   * @see https://github.com/bitcoin/bips/blob/master/bip-0009.mediawiki
   * @param {ChainEntry} prev - Previous chain entry.
   * @param {String} id - Deployment id.
   * @returns {Promise} - Returns Number.
   */

  async isActive(prev, deployment) {
    const state = await this.getState(prev, deployment);
    return state === thresholdStates.ACTIVE;
  }

  /**
   * Get chain entry state for a deployment (BIP9: versionbits).
   * @example
   * await chain.getState(tip, deployments.segwit);
   * @see https://github.com/bitcoin/bips/blob/master/bip-0009.mediawiki
   * @param {ChainEntry} prev - Previous chain entry.
   * @param {String} id - Deployment id.
   * @returns {Promise} - Returns Number.
   */

  async getState(prev, deployment) {
    const bit = deployment.bit;

    if (deployment.startTime === -1)
      return thresholdStates.ACTIVE;

    let window = this.network.minerWindow;
    let threshold = this.network.activationThreshold;

    if (deployment.threshold !== -1)
      threshold = deployment.threshold;

    if (deployment.window !== -1)
      window = deployment.window;

    if (((prev.height + 1) % window) !== 0) {
      const height = prev.height - ((prev.height + 1) % window);

      prev = await this.getAncestor(prev, height);

      if (!prev)
        return thresholdStates.DEFINED;

      assert(prev.height === height);
      assert(((prev.height + 1) % window) === 0);
    }

    let entry = prev;
    let state = thresholdStates.DEFINED;

    const compute = [];

    while (entry) {
      const cached = this.db.stateCache.get(bit, entry);

      if (cached !== -1) {
        state = cached;
        break;
      }

      const time = await this.getMedianTime(entry);

      if (time < deployment.startTime) {
        state = thresholdStates.DEFINED;
        this.db.stateCache.set(bit, entry, state);
        break;
      }

      compute.push(entry);

      const height = entry.height - window;

      entry = await this.getAncestor(entry, height);
    }

    while (compute.length) {
      const entry = compute.pop();

      switch (state) {
        case thresholdStates.DEFINED: {
          const time = await this.getMedianTime(entry);

          if (time >= deployment.timeout) {
            state = thresholdStates.FAILED;
            break;
          }

          if (time >= deployment.startTime) {
            state = thresholdStates.STARTED;
            break;
          }

          break;
        }
        case thresholdStates.STARTED: {
          const time = await this.getMedianTime(entry);

          if (time >= deployment.timeout) {
            state = thresholdStates.FAILED;
            break;
          }

          let block = entry;
          let count = 0;

          for (let i = 0; i < window; i++) {
            if (block.hasBit(bit))
              count++;

            if (count >= threshold) {
              state = thresholdStates.LOCKED_IN;
              break;
            }

            block = await this.getPrevious(block);
            assert(block);
          }

          break;
        }
        case thresholdStates.LOCKED_IN: {
          state = thresholdStates.ACTIVE;
          break;
        }
        case thresholdStates.FAILED:
        case thresholdStates.ACTIVE: {
          break;
        }
        default: {
          assert(false, 'Bad state.');
          break;
        }
      }

      this.db.stateCache.set(bit, entry, state);
    }

    return state;
  }

  /**
   * Compute the version for a new block (BIP9: versionbits).
   * @see https://github.com/bitcoin/bips/blob/master/bip-0009.mediawiki
   * @param {ChainEntry} prev - Previous chain entry (usually the tip).
   * @returns {Promise} - Returns Number.
   */

  async computeBlockVersion(prev) {
    let version = 0;

    for (const deployment of this.network.deploys) {
      const state = await this.getState(prev, deployment);

      if (state === thresholdStates.LOCKED_IN
          || state === thresholdStates.STARTED) {
        version |= 1 << deployment.bit;
      }
    }

    version |= consensus.VERSION_TOP_BITS;
    version >>>= 0;

    return version;
  }

  /**
   * Get the current deployment state of the chain. Called on load.
   * @private
   * @returns {Promise} - Returns {@link DeploymentState}.
   */

  async getDeploymentState() {
    const prev = await this.getPrevious(this.tip);

    if (!prev) {
      assert(this.tip.isGenesis());
      return this.state;
    }

    if (this.options.spv)
      return this.state;

    return this.getDeployments(this.tip.time, prev);
  }

  /**
   * Check transaction finality, taking into account MEDIAN_TIME_PAST
   * if it is present in the lock flags.
   * @param {ChainEntry} prev - Previous chain entry.
   * @param {TX} tx
   * @param {LockFlags} flags
   * @returns {Promise} - Returns Boolean.
   */

  async verifyFinal(prev, tx, flags) {
    const height = prev.height + 1;

    // We can skip MTP if the locktime is height.
    if (tx.locktime < consensus.LOCKTIME_THRESHOLD)
      return tx.isFinal(height, -1);

    if (flags & common.lockFlags.MEDIAN_TIME_PAST) {
      const time = await this.getMedianTime(prev);
      return tx.isFinal(height, time);
    }

    return tx.isFinal(height, this.network.now());
  }

  /**
   * Get the necessary minimum time and height sequence locks for a transaction.
   * @param {ChainEntry} prev
   * @param {TX} tx
   * @param {CoinView} view
   * @param {LockFlags} flags
   * @returns {Promise}
   */

  async getLocks(prev, tx, view, flags) {
    const GRANULARITY = consensus.SEQUENCE_GRANULARITY;
    const DISABLE_FLAG = consensus.SEQUENCE_DISABLE_FLAG;
    const TYPE_FLAG = consensus.SEQUENCE_TYPE_FLAG;
    const MASK = consensus.SEQUENCE_MASK;

    if (!(flags & common.lockFlags.VERIFY_SEQUENCE))
      return [-1, -1];

    if (tx.isCoinbase() || tx.version < 2)
      return [-1, -1];

    let minHeight = -1;
    let minTime = -1;

    for (const {prevout, sequence} of tx.inputs) {
      if (sequence & DISABLE_FLAG)
        continue;

      let height = view.getHeight(prevout);

      if (height === -1)
        height = this.height + 1;

      if (!(sequence & TYPE_FLAG)) {
        height += (sequence & MASK) - 1;
        minHeight = Math.max(minHeight, height);
        continue;
      }

      height = Math.max(height - 1, 0);

      const entry = await this.getAncestor(prev, height);
      assert(entry, 'Database is corrupt.');

      let time = await this.getMedianTime(entry);
      time += ((sequence & MASK) << GRANULARITY) - 1;
      minTime = Math.max(minTime, time);
    }

    return [minHeight, minTime];
  }

  /**
   * Verify sequence locks.
   * @param {ChainEntry} prev
   * @param {TX} tx
   * @param {CoinView} view
   * @param {LockFlags} flags
   * @returns {Promise} - Returns Boolean.
   */

  async verifyLocks(prev, tx, view, flags) {
    const [height, time] = await this.getLocks(prev, tx, view, flags);

    if (height !== -1) {
      if (height >= prev.height + 1)
        return false;
    }

    if (time !== -1) {
      const mtp = await this.getMedianTime(prev);

      if (time >= mtp)
        return false;
    }

    return true;
  }
}

/**
 * ChainOptions
 * @alias module:blockchain.ChainOptions
 */

class ChainOptions {
  /**
   * Create chain options.
   * @constructor
   * @param {Object} options
   */

  constructor(options) {
    this.network = Network.primary;
    this.logger = Logger.global;
    this.blocks = null;
    this.workers = null;

    this.prefix = null;
    this.location = null;
    this.memory = true;
    this.maxFiles = 64;
    this.cacheSize = 32 << 20;
    this.compression = true;

    this.spv = false;
    this.bip91 = false;
    this.bip148 = false;
    this.prune = false;
    this.forceFlags = false;

    this.entryCache = 5000;
    this.checkpoints = true;
    this.maxTips = 100;

    if (options)
      this.fromOptions(options);
  }

  /**
   * Inject properties from object.
   * @private
   * @param {Object} options
   * @returns {ChainOptions}
   */

  fromOptions(options) {
    assert(options.blocks && typeof options.blocks === 'object',
           'Chain requires a blockstore.');

    this.blocks = options.blocks;

    if (options.network != null)
      this.network = Network.get(options.network);

    if (options.logger != null) {
      assert(typeof options.logger === 'object');
      this.logger = options.logger;
    }

    if (options.workers != null) {
      assert(typeof options.workers === 'object');
      this.workers = options.workers;
    }

    if (options.spv != null) {
      assert(typeof options.spv === 'boolean');
      this.spv = options.spv;
      this.prune = true;
    }

    if (options.prefix != null) {
      assert(typeof options.prefix === 'string');
      this.prefix = options.prefix;
      this.location = this.spv
        ? path.join(this.prefix, 'spvchain')
        : path.join(this.prefix, 'chain');
    }

    if (options.location != null) {
      assert(typeof options.location === 'string');
      this.location = options.location;
    }

    if (options.memory != null) {
      assert(typeof options.memory === 'boolean');
      this.memory = options.memory;
    }

    if (options.maxFiles != null) {
      assert((options.maxFiles >>> 0) === options.maxFiles);
      this.maxFiles = options.maxFiles;
    }

    if (options.cacheSize != null) {
      assert(Number.isSafeInteger(options.cacheSize));
      assert(options.cacheSize >= 0);
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

    if (options.forceFlags != null) {
      assert(typeof options.forceFlags === 'boolean');
      this.forceFlags = options.forceFlags;
    }

    if (options.bip91 != null) {
      assert(typeof options.bip91 === 'boolean');
      this.bip91 = options.bip91;
    }

    if (options.bip148 != null) {
      assert(typeof options.bip148 === 'boolean');
      this.bip148 = options.bip148;
    }

    if (options.entryCache != null) {
      assert((options.entryCache >>> 0) === options.entryCache);
      this.entryCache = options.entryCache;
    }

    if (options.checkpoints != null) {
      assert(typeof options.checkpoints === 'boolean');
      this.checkpoints = options.checkpoints;
    }

    if (options.maxTips != null) {
      assert(Number.isSafeInteger(options.maxTips));
      assert(options.maxTips <= 0xffff);
      this.maxTips = options.maxTips;
    }

    return this;
  }

  /**
   * Instantiate chain options from object.
   * @param {Object} options
   * @returns {ChainOptions}
   */

  static fromOptions(options) {
    return new ChainOptions().fromOptions(options);
  }
}

/**
 * Deployment State
 * @alias module:blockchain.DeploymentState
 * @property {VerifyFlags} flags
 * @property {LockFlags} lockFlags
 * @property {Boolean} bip34
 */

class DeploymentState {
  /**
   * Create a deployment state.
   * @constructor
   */

  constructor() {
    this.flags = Script.flags.MANDATORY_VERIFY_FLAGS;
    this.flags &= ~Script.flags.VERIFY_P2SH;
    this.lockFlags = common.lockFlags.MANDATORY_LOCKTIME_FLAGS;
    this.bip34 = false;
    this.bip91 = false;
    this.bip148 = false;
  }

  /**
   * Test whether p2sh is active.
   * @returns {Boolean}
   */

  hasP2SH() {
    return (this.flags & Script.flags.VERIFY_P2SH) !== 0;
  }

  /**
   * Test whether bip34 (coinbase height) is active.
   * @returns {Boolean}
   */

  hasBIP34() {
    return this.bip34;
  }

  /**
   * Test whether bip66 (VERIFY_DERSIG) is active.
   * @returns {Boolean}
   */

  hasBIP66() {
    return (this.flags & Script.flags.VERIFY_DERSIG) !== 0;
  }

  /**
   * Test whether cltv is active.
   * @returns {Boolean}
   */

  hasCLTV() {
    return (this.flags & Script.flags.VERIFY_CHECKLOCKTIMEVERIFY) !== 0;
  }

  /**
   * Test whether median time past locktime is active.
   * @returns {Boolean}
   */

  hasMTP() {
    return (this.lockFlags & common.lockFlags.MEDIAN_TIME_PAST) !== 0;
  }

  /**
   * Test whether csv is active.
   * @returns {Boolean}
   */

  hasCSV() {
    return (this.flags & Script.flags.VERIFY_CHECKSEQUENCEVERIFY) !== 0;
  }

  /**
   * Test whether segwit is active.
   * @returns {Boolean}
   */

  hasWitness() {
    return (this.flags & Script.flags.VERIFY_WITNESS) !== 0;
  }

  /**
   * Test whether bip91 is active.
   * @returns {Boolean}
   */

  hasBIP91() {
    return this.bip91;
  }

  /**
   * Test whether bip148 is active.
   * @returns {Boolean}
   */

  hasBIP148() {
    return this.bip148;
  }
}

/*
 * Expose
 */

module.exports = Chain;
