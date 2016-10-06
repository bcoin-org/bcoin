/*!
 * miner.js - inefficient miner for bcoin (because we can)
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var utils = require('../utils/utils');
var co = require('../utils/co');
var assert = require('assert');
var AsyncObject = require('../utils/async');
var MinerBlock = require('./minerblock');
var Address = require('../primitives/address');
var time = require('../net/timedata');

/**
 * A bitcoin miner (supports mining witness blocks).
 * @exports Miner
 * @constructor
 * @param {Object} options
 * @param {Base58Address} options.address - Payout address.
 * @param {String?} [options.coinbaseFlags="mined by bcoin"]
 * @property {Boolean} running
 * @property {MinerBlock} attempt
 * @emits Miner#block
 * @emits Miner#status
 */

function Miner(options) {
  if (!(this instanceof Miner))
    return new Miner(options);

  AsyncObject.call(this);

  assert(options, 'Miner requires options.');
  assert(options.chain, 'Miner requires a blockchain.');

  this.chain = options.chain;
  this.mempool = options.mempool;
  this.network = this.chain.network;
  this.logger = options.logger || this.chain.logger;

  this.running = false;
  this.stopping = false;
  this.attempt = null;
  this.since = 0;

  this.version = -1;
  this.address = Address(options.address);
  this.coinbaseFlags = options.coinbaseFlags || 'mined by bcoin';

  this._init();
}

utils.inherits(Miner, AsyncObject);

/**
 * Initialize the miner.
 * @private
 */

Miner.prototype._init = function _init() {
  var self = this;

  this.on('block', function(block) {
    // Emit the block hex as a failsafe (in case we can't send it)
    self.logger.info('Found block: %d (%s).', block.height, block.rhash);
    self.logger.debug('Raw: %s', block.toRaw().toString('hex'));
  });

  this.on('status', function(stat) {
    self.logger.info(
      'Miner: hashrate=%dkhs hashes=%d target=%d height=%d best=%s',
      stat.hashrate / 1000 | 0,
      stat.hashes,
      stat.target,
      stat.height,
      stat.best);
  });
};

/**
 * Open the miner, wait for the chain and mempool to load.
 * @alias Miner#open
 * @returns {Promise}
 */

Miner.prototype._open = co(function* open() {
  yield this.chain.open();

  if (this.mempool)
    yield this.mempool.open();

  this.logger.info('Miner loaded (flags=%s).',
    this.coinbaseFlags.toString('utf8'));
});

/**
 * Close the miner.
 * @alias Miner#close
 * @returns {Promise}
 */

Miner.prototype._close = co(function* close() {
  if (!this.running)
    return;

  if (this.stopping) {
    yield this._onStop();
    return;
  }

  yield this.stop();
});

/**
 * Start mining.
 * @param {Number?} version - Custom block version.
 */

Miner.prototype.start = co(function* start() {
  var block;

  assert(!this.running, 'Miner is already running.');

  this.running = true;
  this.stopping = false;

  for (;;) {
    this.attempt = null;

    try {
      this.attempt = yield this.createBlock();
    } catch (e) {
      if (this.stopping)
        break;
      this.emit('error', e);
      continue;
    }

    if (this.stopping)
      break;

    try {
      block = yield this.attempt.mineAsync();
    } catch (e) {
      if (this.stopping)
        break;
      this.emit('error', e);
      continue;
    }

    if (this.stopping)
      break;

    if (!block)
      continue;

    try {
      yield this.chain.add(block);
    } catch (e) {
      if (this.stopping)
        break;
      this.emit('error', e);
      continue;
    }

    if (this.stopping)
      break;

    this.emit('block', block);
  }

  this.emit('done');
});

/**
 * Stop mining.
 */

Miner.prototype.stop = co(function* stop() {
  assert(this.running, 'Miner is not running.');
  assert(!this.stopping, 'Miner is already stopping.');

  this.stopping = true;

  if (this.attempt)
    this.attempt.destroy();

  yield this._onDone();

  this.running = false;
  this.stopping = false;
  this.attempt = null;

  this.emit('stop');
});

/**
 * Wait for `done` event.
 */

Miner.prototype._onDone = co(function* _onDone() {
  var self = this;
  return new Promise(function(resolve, reject) {
    self.once('done', resolve);
  });
});

/**
 * Wait for `stop` event.
 */

Miner.prototype._onStop = co(function* _onStop() {
  var self = this;
  return new Promise(function(resolve, reject) {
    self.once('stop', resolve);
  });
});

/**
 * Create a block "attempt".
 * @param {ChainEntry} tip
 * @returns {Promise} - Returns {@link MinerBlock}.
 */

Miner.prototype.createBlock = co(function* createBlock(tip) {
  var version = this.version;
  var ts, attempt, target, entries;

  if (!tip)
    tip = this.chain.tip;

  assert(tip);

  ts = Math.max(time.now(), tip.ts + 1);

  target = yield this.chain.getTargetAsync(ts, tip);

  if (version === -1)
    version = yield this.chain.computeBlockVersion(tip);

  attempt = new MinerBlock({
    tip: tip,
    version: version,
    bits: target,
    flags: this.chain.state.flags,
    address: this.address,
    coinbaseFlags: this.coinbaseFlags,
    witness: this.chain.state.hasWitness(),
    network: this.network
  });

  entries = this.getSorted();

  attempt.build(entries);

  return attempt;
});

/**
 * Mine a single block.
 * @param {ChainEntry} tip
 * @returns {Promise} - Returns [{@link Block}].
 */

Miner.prototype.mineBlock = co(function* mineBlock(tip) {
  var attempt = yield this.createBlock(tip);
  return yield attempt.mineAsync();
});

/**
 * Add a transaction to the current block.
 * @param {TX} tx
 */

Miner.prototype.addTX = function addTX(tx) {
  if (!this.running)
    return;

  if (!this.attempt)
    return;

  this.attempt.addTX(tx);
};

/**
 * Notify the miner that a new tx has entered the mempool.
 * @param {MempoolEntry} entry
 */

Miner.prototype.notifyEntry = function notifyEntry() {
  if (!this.running)
    return;

  if (!this.attempt)
    return;

  if (++this.since > 20) {
    this.since = 0;
    this.attempt.destroy();
  }
};

/**
 * Create a block "attempt".
 * @param {ChainEntry} tip
 * @returns {Promise} - Returns {@link MinerBlock}.
 */

Miner.prototype.getSorted = function getSorted() {
  var depMap = {};
  var count = {};
  var result = [];
  var top = [];
  var i, j, entry, tx, hash, input;
  var prev, hasDeps, deps, hashes;

  if (!this.mempool)
    return [];

  hashes = this.mempool.getSnapshot();

  for (i = 0; i < hashes.length; i++) {
    hash = hashes[i];
    entry = this.mempool.getEntry(hash);
    tx = entry.tx;

    count[hash] = 0;
    hasDeps = false;

    for (j = 0; j < tx.inputs.length; j++) {
      input = tx.inputs[j];
      prev = input.prevout.hash;

      if (!this.mempool.hasTX(prev))
        continue;

      hasDeps = true;

      if (!depMap[prev])
        depMap[prev] = [];

      depMap[prev].push(entry);
      count[hash]++;
    }

    if (hasDeps)
      continue;

    top.push(entry);
  }

  for (i = 0; i < top.length; i++) {
    entry = top[i];
    tx = entry.tx;
    hash = tx.hash('hex');

    result.push(entry);

    deps = depMap[hash];

    if (!deps)
      continue;

    for (j = 0; j < deps.length; j++) {
      entry = deps[j];
      tx = entry.tx;
      hash = tx.hash('hex');

      if (--count[hash] === 0)
        result.push(entry);
    }
  }

  return result;
};

/*
 * Expose
 */

module.exports = Miner;
