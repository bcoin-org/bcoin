/*!
 * miner.js - inefficient miner for bcoin (because we can)
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var assert = require('assert');
var util = require('../utils/util');
var co = require('../utils/co');
var Heap = require('../utils/heap');
var AsyncObject = require('../utils/asyncobject');
var Amount = require('../btc/amount');
var Address = require('../primitives/address');
var MinerBlock = require('./minerblock');
var Network = require('../protocol/network');
var consensus = require('../protocol/consensus');
var policy = require('../protocol/policy');
var BlockEntry = MinerBlock.BlockEntry;

/**
 * A bitcoin miner (supports mining witness blocks).
 * @alias module:mining.Miner
 * @constructor
 * @param {Object} options
 * @param {Address} options.address - Payout address.
 * @param {String} [options.coinbaseFlags="mined by bcoin"]
 * @property {Boolean} running
 * @property {MinerBlock} attempt
 * @emits Miner#block
 * @emits Miner#status
 */

function Miner(options) {
  if (!(this instanceof Miner))
    return new Miner(options);

  AsyncObject.call(this);

  this.options = new MinerOptions(options);

  this.network = this.options.network;
  this.logger = this.options.logger;
  this.chain = this.options.chain;
  this.mempool = this.options.mempool;
  this.addresses = this.options.addresses;

  this.locker = this.chain.locker;

  this.running = false;
  this.stopping = false;
  this.attempt = null;
  this.since = 0;

  this._init();
}

util.inherits(Miner, AsyncObject);

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

  this.on('block', function(block, entry) {
    // Emit the block hex as a failsafe (in case we can't send it)
    self.logger.info('Found block: %d (%s).', entry.height, entry.rhash());
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
 * @method
 * @alias module:mining.Miner#open
 * @returns {Promise}
 */

Miner.prototype._open = co(function* open() {
  yield this.chain.open();

  if (this.mempool)
    yield this.mempool.open();

  this.logger.info('Miner loaded (flags=%s).',
    this.options.coinbaseFlags.toString('utf8'));
});

/**
 * Close the miner.
 * @method
 * @alias module:mining.Miner#close
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
 * @method
 * @param {Number?} version - Custom block version.
 * @returns {Promise}
 */

Miner.prototype.start = co(function* start() {
  var self = this;
  var block, entry;

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
      entry = yield this.chain.add(block);
    } catch (e) {
      if (this.stopping)
        break;
      this.emit('error', e);
      continue;
    }

    if (!entry) {
      this.logger.warning('Mined a bad-prevblk (race condition?)');
      continue;
    }

    if (this.stopping)
      break;

    this.emit('block', block, entry);
  }

  this.emit('done');
});

/**
 * Stop mining.
 * @method
 * @returns {Promise}
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
 * @private
 * @returns {Promise}
 */

Miner.prototype._onDone = function _onDone() {
  var self = this;
  return new Promise(function(resolve, reject) {
    self.once('done', resolve);
  });
};

/**
 * Wait for `stop` event.
 * @private
 * @returns {Promise}
 */

Miner.prototype._onStop = function _onStop() {
  var self = this;
  return new Promise(function(resolve, reject) {
    self.once('stop', resolve);
  });
};

/**
 * Create a block "attempt".
 * @method
 * @param {ChainEntry} tip
 * @returns {Promise} - Returns {@link MinerBlock}.
 */

Miner.prototype.createBlock = co(function* createBlock(tip, address) {
  var unlock = yield this.locker.lock();
  try {
    return yield this._createBlock(tip, address);
  } finally {
    unlock();
  }
});

/**
 * Create a block "attempt" (without a lock).
 * @method
 * @private
 * @param {ChainEntry} tip
 * @returns {Promise} - Returns {@link MinerBlock}.
 */

Miner.prototype._createBlock = co(function* createBlock(tip, address) {
  var version = this.options.version;
  var ts, locktime, target, attempt;

  if (!tip)
    tip = this.chain.tip;

  if (!address)
    address = this.getAddress();

  if (version === -1)
    version = yield this.chain.computeBlockVersion(tip);

  if (this.chain.state.hasMTP()) {
    locktime = yield tip.getMedianTime();
    ts = Math.max(this.network.now(), locktime + 1);
  } else {
    ts = Math.max(this.network.now(), tip.ts + 1);
    locktime = ts;
  }

  target = yield this.chain.getTarget(ts, tip);

  attempt = new MinerBlock({
    network: this.network,
    tip: tip,
    version: version,
    ts: ts,
    bits: target,
    locktime: locktime,
    flags: this.chain.state.flags,
    address: address,
    coinbaseFlags: this.options.coinbaseFlags,
    witness: this.chain.state.hasWitness(),
    weight: this.options.reservedWeight,
    sigops: this.options.reservedSigops
  });

  this.build(attempt);

  this.logger.debug(
    'Created miner block (height=%d, weight=%d, fees=%d, txs=%s).',
    attempt.height,
    attempt.weight,
    Amount.btc(attempt.fees),
    attempt.items.length + 1);

  return attempt;
});

/**
 * Mine a single block.
 * @method
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
  var queue = new Heap(cmpRate);
  var priority = this.options.priorityWeight > 0;
  var i, j, entry, item, tx, hash, input;
  var prev, deps, hashes, weight, sigops;

  if (priority)
    queue.set(cmpPriority);

  if (!this.mempool)
    return [];

  assert(this.mempool.tip === this.chain.tip.hash,
    'Mempool/chain tip mismatch! Unsafe to create block.');

  hashes = this.mempool.getSnapshot();

  for (i = 0; i < hashes.length; i++) {
    hash = hashes[i];
    entry = this.mempool.getEntry(hash);
    item = BlockEntry.fromEntry(entry, attempt);
    tx = item.tx;

    if (tx.isCoinbase())
      throw new Error('Cannot add coinbase to block.');

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

    queue.insert(item);
  }

  while (queue.size() > 0) {
    item = queue.shift();
    tx = item.tx;
    hash = item.hash;
    weight = attempt.weight;
    sigops = attempt.sigops;

    if (!tx.isFinal(attempt.height, attempt.locktime))
      continue;

    if (!attempt.witness && tx.hasWitness())
      continue;

    weight += tx.getWeight();

    if (weight > this.options.maxWeight)
      continue;

    sigops += item.sigops;

    if (sigops > this.options.maxSigops)
      continue;

    if (priority) {
      if (weight > this.options.priorityWeight
          || item.priority < this.options.priorityThreshold) {
        priority = false;
        queue.set(cmpRate);
        queue.init();
        queue.insert(item);
        continue;
      }
    } else {
      if (item.free && weight >= this.options.minWeight)
        continue;
    }

    attempt.weight = weight;
    attempt.sigops = sigops;
    attempt.fees += item.fee;
    attempt.items.push(item);

    block.txs.push(tx);

    deps = depMap[hash];

    if (!deps)
      continue;

    for (j = 0; j < deps.length; j++) {
      item = deps[j];
      if (--item.depCount === 0)
        queue.insert(item);
    }
  }

  attempt.refresh();

  assert(block.getWeight() <= attempt.weight,
    'Block exceeds reserved weight!');
  assert(block.getBaseSize() <= consensus.MAX_BLOCK_SIZE,
    'Block exceeds max block size.');
};

/**
 * MinerOptions
 * @alias module:mining.MinerOptions
 * @constructor
 * @param {Object}
 */

function MinerOptions(options) {
  if (!(this instanceof MinerOptions))
    return new MinerOptions(options);

  this.network = Network.primary;
  this.logger = null;
  this.chain = null;
  this.mempool = null;

  this.version = -1;
  this.addresses = [];
  this.coinbaseFlags = new Buffer('mined by bcoin', 'ascii');

  this.minWeight = policy.MIN_BLOCK_WEIGHT;
  this.maxWeight = policy.MAX_BLOCK_WEIGHT;
  this.priorityWeight = policy.BLOCK_PRIORITY_WEIGHT;
  this.priorityThreshold = policy.BLOCK_PRIORITY_THRESHOLD;
  this.maxSigops = consensus.MAX_BLOCK_SIGOPS_COST;
  this.reservedWeight = 4000;
  this.reservedSigops = 400;

  this.fromOptions(options);
}

/**
 * Inject properties from object.
 * @private
 * @param {Object} options
 * @returns {MinerOptions}
 */

MinerOptions.prototype.fromOptions = function fromOptions(options) {
  var i, flags;

  assert(options, 'Miner requires options.');
  assert(options.chain && typeof options.chain === 'object',
    'Miner requires a blockchain.');

  this.chain = options.chain;
  this.network = options.chain.network;
  this.logger = options.chain.logger;

  if (options.logger != null) {
    assert(typeof options.logger === 'object');
    this.logger = options.logger;
  }

  if (options.mempool != null) {
    assert(typeof options.mempool === 'object');
    this.mempool = options.mempool;
  }

  if (options.version != null) {
    assert(util.isNumber(options.version));
    this.version = options.version;
  }

  if (options.address) {
    if (Array.isArray(options.address)) {
      for (i = 0; i < options.address.length; i++)
        this.addresses.push(new Address(options.address[i]));
    } else {
      this.addresses.push(new Address(options.address));
    }
  }

  if (options.addresses) {
    assert(Array.isArray(options.addresses));
    for (i = 0; i < options.addresses.length; i++)
      this.addresses.push(new Address(options.addresses[i]));
  }

  if (options.coinbaseFlags) {
    flags = options.coinbaseFlags;
    if (typeof flags === 'string')
      flags = new Buffer(flags, 'utf8');
    assert(Buffer.isBuffer(flags));
    assert(flags.length <= 20, 'Coinbase flags > 20 bytes.');
    this.coinbaseFlags = flags;
  }

  if (options.minWeight != null) {
    assert(util.isNumber(options.minWeight));
    this.minWeight = options.minWeight;
  }

  if (options.maxWeight != null) {
    assert(util.isNumber(options.maxWeight));
    assert(options.maxWeight <= consensus.MAX_BLOCK_WEIGHT,
      'Max weight must be below MAX_BLOCK_WEIGHT');
    this.maxWeight = options.maxWeight;
  }

  if (options.maxSigops != null) {
    assert(util.isNumber(options.maxSigops));
    assert(options.maxSigops <= consensus.MAX_BLOCK_SIGOPS_COST,
      'Max sigops must be below MAX_BLOCK_SIGOPS_COST');
    this.maxSigops = options.maxSigops;
  }

  if (options.priorityWeight != null) {
    assert(util.isNumber(options.priorityWeight));
    this.priorityWeight = options.priorityWeight;
  }

  if (options.priorityThreshold != null) {
    assert(util.isNumber(options.priorityThreshold));
    this.priorityThreshold = options.priorityThreshold;
  }

  if (options.reservedWeight != null) {
    assert(util.isNumber(options.reservedWeight));
    this.reservedWeight = options.reservedWeight;
  }

  if (options.reservedSigops != null) {
    assert(util.isNumber(options.reservedSigops));
    this.reservedSigops = options.reservedSigops;
  }

  return this;
};

/**
 * Instantiate miner options from object.
 * @param {Object} options
 * @returns {MinerOptions}
 */

MinerOptions.fromOptions = function fromOptions(options) {
  return new MinerOptions().fromOptions(options);
};

/*
 * Helpers
 */

function cmpPriority(a, b) {
  if (a.priority === b.priority)
    return cmpRate(a, b);
  return b.priority - a.priority;
}

function cmpRate(a, b) {
  var x = a.rate;
  var y = b.rate;

  if (a.descRate > a.rate)
    x = a.descRate;

  if (b.descRate > b.rate)
    y = b.descRate;

  if (x === y) {
    x = a.priority;
    y = b.priority;
  }

  return y - x;
}

/*
 * Expose
 */

module.exports = Miner;
