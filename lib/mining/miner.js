/*!
 * miner.js - inefficient miner for bcoin (because we can)
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var util = require('../utils/util');
var co = require('../utils/co');
var assert = require('assert');
var constants = require('../protocol/constants');
var AsyncObject = require('../utils/async');
var MinerBlock = require('./minerblock');
var Address = require('../primitives/address');

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
  this.addresses = [];
  this.coinbaseFlags = new Buffer('mined by bcoin', 'ascii');

  this.minWeight = 0;
  this.maxWeight = 750000 * constants.WITNESS_SCALE_FACTOR;
  this.maxSigops = constants.block.MAX_SIGOPS_WEIGHT;
  this.priorityWeight = 50000 * constants.WITNESS_SCALE_FACTOR;
  this.minPriority = constants.tx.FREE_THRESHOLD;

  this._initOptions(options);
  this._init();
}

util.inherits(Miner, AsyncObject);

/**
 * Initialize the miner options.
 * @private
 */

Miner.prototype._initOptions = function _initOptions(options) {
  var i, flags;

  if (options.version != null) {
    assert(util.isNumber(options.version));
    this.version = options.version;
  }

  if (options.address)
    this.addAddress(options.address);

  if (options.addresses) {
    assert(Array.isArray(options.addresses));
    for (i = 0; i < options.addresses.length; i++)
      this.addAddress(options.addresses[i]);
  }

  if (options.coinbaseFlags) {
    flags = options.coinbaseFlags;
    if (typeof flags === 'string')
      flags = new Buffer(flags, 'utf8');
    assert(Buffer.isBuffer(flags));
    this.coinbaseFlags = flags;
  }

  if (options.minWeight != null) {
    assert(util.isNumber(options.minWeight));
    this.minWeight = options.minWeight;
  }

  if (options.maxWeight != null) {
    assert(util.isNumber(options.maxWeight));
    this.maxWeight = options.maxWeight;
  }

  if (options.maxSigops != null) {
    assert(util.isNumber(options.maxSigops));
    assert(options.maxSigops <= constants.block.MAX_SIGOPS_WEIGHT);
    this.maxSigops = options.maxSigops;
  }

  if (options.priorityWeight != null) {
    assert(util.isNumber(options.priorityWeight));
    this.priorityWeight = options.priorityWeight;
  }

  if (options.minPriority != null) {
    assert(util.isNumber(options.minPriority));
    this.minPriority = options.minPriority;
  }
};

/**
 * Initialize the miner.
 * @private
 */

Miner.prototype._init = function _init() {
  var self = this;

  this.chain.on('tip', function(tip) {
    if (!self.attempt)
      return;

    if (self.attempt.block.prevBlock === tip.prevBlock)
      self.attempt.destroy();
  });

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
  var self = this;
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

    this.attempt.on('status', function(status) {
      self.emit('status', status);
    });

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

Miner.prototype._onDone = function _onDone() {
  var self = this;
  return new Promise(function(resolve, reject) {
    self.once('done', resolve);
  });
};

/**
 * Wait for `stop` event.
 */

Miner.prototype._onStop = function _onStop() {
  var self = this;
  return new Promise(function(resolve, reject) {
    self.once('stop', resolve);
  });
};

/**
 * Create a block "attempt".
 * @param {ChainEntry} tip
 * @returns {Promise} - Returns {@link MinerBlock}.
 */

Miner.prototype.createBlock = co(function* createBlock(tip, address) {
  var version = this.version;
  var ts, attempt, target, locktime;

  if (!tip)
    tip = this.chain.tip;

  assert(tip);

  ts = Math.max(this.network.now(), tip.ts + 1);
  locktime = ts;

  target = yield this.chain.getTargetAsync(ts, tip);

  if (version === -1)
    version = yield this.chain.computeBlockVersion(tip);

  if (this.chain.state.hasMTP())
    locktime = yield tip.getMedianTimeAsync();

  if (!address)
    address = this.getAddress();

  attempt = new MinerBlock({
    tip: tip,
    version: version,
    bits: target,
    locktime: locktime,
    flags: this.chain.state.flags,
    address: address,
    coinbaseFlags: this.coinbaseFlags,
    witness: this.chain.state.hasWitness(),
    network: this.network
  });

  this.build(attempt);

  return attempt;
});

/**
 * Mine a single block.
 * @param {ChainEntry} tip
 * @returns {Promise} - Returns [{@link Block}].
 */

Miner.prototype.mineBlock = co(function* mineBlock(tip, address) {
  var attempt = yield this.createBlock(tip, address);
  return yield attempt.mineAsync();
});

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
 * Add an address to the address list.
 * @param {Address} address
 */

Miner.prototype.addAddress = function addAddress(address) {
  this.addresses.push(Address(address));
};

/**
 * Get a random address from the address list.
 * @returns {Address}
 */

Miner.prototype.getAddress = function getAddress() {
  assert(this.addresses.length !== 0, 'No address passed in for miner.');
  return this.addresses[Math.random() * this.addresses.length | 0];
};

/**
 * Get mempool entries, sort by dependency order.
 * Prioritize by priority and fee rates.
 * @returns {MempoolEntry[]}
 */

Miner.prototype.build = function build(attempt) {
  var depMap = {};
  var block = attempt.block;
  var queue = new Queue(cmpPriority);
  var priority = true;
  var i, j, entry, item, tx, hash, input;
  var prev, deps, hashes, weight, sigops;

  if (!this.mempool)
    return [];

  hashes = this.mempool.getSnapshot();

  for (i = 0; i < hashes.length; i++) {
    hash = hashes[i];
    entry = this.mempool.getEntry(hash);
    item = new QueueItem(entry, attempt);
    tx = item.tx;

    if (tx.isCoinbase())
      throw new Error('Cannot add coinbase to block.');

    if (!tx.hasCoins())
      throw new Error('Cannot add empty tx to block.');

    if (!tx.isFinal(attempt.height, attempt.locktime))
      continue;

    for (j = 0; j < tx.inputs.length; j++) {
      input = tx.inputs[j];
      prev = input.prevout.hash;

      if (!this.mempool.hasTX(prev))
        continue;

      item.depCount += 1;

      if (!depMap[prev])
        depMap[prev] = [];

      depMap[prev].push(item);
    }

    if (item.depCount > 0)
      continue;

    queue.push(item);
  }

  while (queue.size() > 0) {
    item = queue.pop();
    tx = item.tx;
    hash = item.hash;
    weight = attempt.weight;
    sigops = attempt.sigops;

    if (!attempt.witness && tx.hasWitness())
      continue;

    weight += tx.getWeight();

    if (weight > this.maxWeight)
      continue;

    sigops += tx.getSigopsWeight(attempt.flags);

    if (sigops > this.maxSigops)
      continue;

    if (priority) {
      if (weight > this.priorityWeight || item.priority < this.minPriority) {
        // Todo: Compare descendant rate with
        // cumulative fees and cumulative vsize.
        queue.cmp = cmpRate;
        priority = false;
        queue.push(item);
        continue;
      }
    } else {
      if (item.free && weight >= this.minWeight)
        continue;
    }

    attempt.weight = weight;
    attempt.sigops = sigops;
    attempt.fees += item.fee;

    block.txs.push(tx.clone());

    deps = depMap[hash];

    if (!deps)
      continue;

    for (j = 0; j < deps.length; j++) {
      item = deps[j];
      if (--item.depCount === 0)
        queue.push(item);
    }
  }

  attempt.updateCoinbase();
  attempt.updateMerkle();

  assert(block.getWeight() <= attempt.weight);
};

/**
 * QueueItem
 * @constructor
 */

function QueueItem(entry, attempt) {
  this.tx = entry.tx;
  this.hash = entry.tx.hash('hex');
  this.fee = entry.getFee();
  this.rate = entry.getRate();
  this.priority = entry.getPriority(attempt.height);
  this.free = entry.isFree(attempt.height);
  this.depCount = 0;
}

/**
 * Queue
 * @constructor
 */

function Queue(cmp) {
  this.cmp = cmp;
  this.items = [];
}

Queue.prototype.size = function size() {
  return this.items.length;
};

Queue.prototype.push = function push(item) {
  util.binaryInsert(this.items, item, this.cmp);
};

Queue.prototype.pop = function pop() {
  return this.items.pop();
};

/*
 * Helpers
 */

function cmpPriority(a, b) {
  return a.priority - b.priority;
}

function cmpRate(a, b) {
  return a.rate - b.rate;
}

/*
 * Expose
 */

module.exports = Miner;
