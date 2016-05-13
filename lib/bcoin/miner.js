/*!
 * miner.js - inefficient miner for bcoin (because we can)
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/indutny/bcoin
 */

var bcoin = require('../bcoin');
var utils = require('./utils');
var assert = utils.assert;
var constants = bcoin.protocol.constants;
var bn = require('bn.js');
var EventEmitter = require('events').EventEmitter;

/**
 * A bitcoin miner (supports mining witness blocks).
 * @exports Miner
 * @constructor
 * @param {Object} options
 * @param {Base58Address} options.address - Payout address.
 * @param {String?} [options.coinbaseFlags="mined by bcoin"]
 * @param {Function?} dsha256 - Optional sha256 substitute
 * for faster linked code.
 * @property {Boolean} running
 * @property {Boolean} loaded
 * @emits Miner#block
 * @emits Miner#status
 */

function Miner(options) {
  if (!(this instanceof Miner))
    return new Miner(options);

  EventEmitter.call(this);

  if (!options)
    options = {};

  this.options = options;
  this.address = this.options.address;
  this.coinbaseFlags = this.options.coinbaseFlags || 'mined by bcoin';

  // Allow a dsha256 option in case someone
  // wants to pass in a faster linked in function.
  this.dsha256 = this.options.dsha256 || utils.dsha256;

  this.pool = options.pool;
  this.chain = options.chain;
  this.mempool = options.mempool;

  assert(this.chain, 'Miner requires a blockchain.');

  this.network = this.chain.network;
  this.running = false;
  this.timeout = null;
  this.loaded = false;

  this.block = null;

  this.workerPool = null;

  if (bcoin.useWorkers) {
    this.workerPool = new bcoin.workers({
      network: this.network,
      size: 1,
      timeout: -1
    });
  }

  this._init();
}

utils.inherits(Miner, EventEmitter);

/**
 * Open the miner, wait for the chain and mempool to load.
 * @param {Function} callback
 */

Miner.prototype.open = function open(callback) {
  if (this.loaded)
    return utils.nextTick(callback);

  return this.once('open', callback);
};

/**
 * Close the miner.
 * @method
 * @param {Function} callback
 */

Miner.prototype.close =
Miner.prototype.destroy = function destroy(callback) {
  return utils.nextTick(callback);
};

Miner.prototype._init = function _init() {
  var self = this;

  if (this.mempool) {
    this.mempool.on('tx', function(tx) {
      if (!self.running)
        return;
      self.attempt.addTX(tx);
    });
  } else if (this.pool) {
    this.pool.on('tx', function(tx) {
      if (!self.running)
        return;
      self.attempt.addTX(tx);
    });
  }

  this.chain.on('tip', function(tip) {
    if (!self.running)
      return;
    self.stop();
    setTimeout(function() {
      self.start();
    }, self.network.type === 'regtest' ? 100 : 5000);
  });

  this.on('block', function(block) {
    bcoin.debug(
      'Found block: %d (%s)',
      block.height,
      block.hash('hex'));
    // Emit the block hex as a failsafe (in case we can't send it)
    bcoin.debug('Raw: %s', block.render().toString('hex'));
  });

  this.on('status', function(stat) {
    bcoin.debug(
      'hashrate=%dkhs hashes=%d target=%d height=%d best=%s',
      stat.hashrate / 1000 | 0,
      stat.hashes,
      stat.target,
      stat.height,
      stat.best);
  });

  function done(err) {
    if (err)
      return self.emit('error', err);
    self.loaded = true;
    self.emit('open');
  }

  if (this.mempool)
    this.mempool.open(done);
  else
    this.chain.open(done);
};

/**
 * Start mining.
 * @param {Number?} version - Custom block version.
 */

Miner.prototype.start = function start(version) {
  var self = this;

  this.stop();

  this.running = true;

  // Create a new block and start hashing
  this.createBlock(version, function(err, attempt) {
    if (err)
      return self.emit('error', err);

    if (!self.running)
      return;

    self.attempt = attempt;

    attempt.on('status', function(status) {
      self.emit('status', status);
    });

    attempt.mineAsync(function(err, block) {
      if (err) {
        self.emit('error', err);
        return self.start();
      }

      // Add our block to the chain
      self.chain.add(block, function(err) {
        if (err) {
          if (err.type === 'VerifyError')
            bcoin.debug('%s could not be added to chain.', block.rhash);
          self.emit('error', err);
          return self.start();
        }

        // Emit our newly found block
        self.emit('block', block);

        // `tip` will now be emitted by chain
        // and the whole process starts over.
      });
    });
  });
};

/**
 * Stop mining.
 */

Miner.prototype.stop = function stop() {
  if (!this.running)
    return;

  this.running = false;

  if (this.attempt) {
    this.attempt.destroy();
    this.attempt = null;
  }
};

/**
 * Create a block "attempt".
 * @param {Number?} version - Custom block version.
 * @param {Function} callback - Returns [Error, {@link MinerBlock}].
 */

Miner.prototype.createBlock = function createBlock(version, callback) {
  var self = this;
  var ts = Math.max(bcoin.now(), this.chain.tip.ts + 1);
  var attempt;

  if (typeof version === 'function') {
    callback = version;
    version = null;
  }

  function computeVersion(callback) {
    if (version != null)
      return callback(null, version);
    self.chain.computeBlockVersion(self.chain.tip, callback);
  }

  if (!this.loaded) {
    this.open(function(err) {
      if (err)
        return callback(err);
      self.createBlock(version, callback);
    });
    return;
  }

  assert(this.chain.tip);

  // Find target
  this.chain.getTargetAsync(ts, this.chain.tip, function(err, target) {
    if (err)
      return callback(err);

    // Calculate version with versionbits
    computeVersion(function(err, version) {
      if (err)
        return callback(err);

      attempt = new MinerBlock({
        workerPool: self.workerPool,
        tip: self.chain.tip,
        version: version,
        target: target,
        address: self.address,
        coinbaseFlags: self.coinbaseFlags,
        witness: self.chain.segwitActive,
        dsha256: self.dsha256
      });

      if (!self.mempool)
        return callback(null, attempt);

      self.mempool.getSnapshot(function(err, hashes) {
        if (err)
          return callback(err);

        utils.forEachSerial(hashes, function(hash, next) {
          self.mempool.getTX(hash, function(err, tx) {
            if (err)
              return next(err);

            self.mempool.fillAllCoins(tx, function(err) {
              if (err)
                return next(err);

              attempt.addTX(tx);

              next();
            });
          });
        }, function(err) {
          if (err)
            return callback(err);

          return callback(null, attempt);
        });
      });
    });
  });
};

/**
 * Mine a single block.
 * @param {Number?} version - Custom block version.
 * @param {Function} callback - Returns [Error, [{@link Block}]].
 */

Miner.prototype.mineBlock = function mineBlock(version, callback) {
  var self = this;

  if (typeof version === 'function') {
    callback = version;
    version = null;
  }

  // Create a new block and start hashing
  this.createBlock(version, function(err, attempt) {
    if (err)
      return callback(err);

    attempt.mineAsync(callback);
  });
};

/**
 * MinerBlock
 * @exports MinerBlock
 * @constructor
 * @param {Object} options
 * @param {ChainBlock} options.tip
 * @param {Number} options.height
 * @param {Number} options.target - Compact form.
 * @param {Function} options.dsha256
 * @param {Base58Address} options.address - Payout address.
 * @param {Boolean} options.witness - Allow witness
 * transactions, mine a witness block.
 * @property {Block} block
 * @property {TX} coinbase
 * @property {BN} hashes - Number of hashes attempted.
 * @property {Number} rate - Hash rate.
 * @emits MinerBlock#status
 */

function MinerBlock(options) {
  if (!(this instanceof MinerBlock))
    return new MinerBlock(options);

  this.options = options;
  this.workerPool = options.workerPool;
  this.tip = options.tip;
  this.height = options.tip.height + 1;
  this.target = utils.fromCompact(options.target).toBuffer('le', 32);
  this.extraNonce = new bn(0);
  this.iterations = 0;
  this.dsha256 = options.dsha256;

  // Create a coinbase
  this.coinbase = new bcoin.mtx();

  this.coinbase.addInput({
    prevout: {
      hash: constants.NULL_HASH,
      index: 0xffffffff
    },
    coin: null,
    script: new bcoin.script([
      // Height (required in v2+ blocks)
      bcoin.script.array(this.height),
      // extraNonce - incremented when
      // the nonce overflows.
      bcoin.script.array(0),
      // Add a nonce to ensure we don't
      // collide with a previous coinbase
      // of ours. This isn't really
      // necessary nowdays due to bip34
      // (used above).
      bcoin.script.array(utils.nonce()),
      // Let the world know this little
      // miner succeeded.
      new Buffer(options.coinbaseFlags, 'ascii')
    ]),
    witness: new bcoin.witness(),
    sequence: 0xffffffff
  });

  this.coinbase.addOutput({
    address: options.address,
    value: new bn(0)
  });

  // Create our block
  this.block = new bcoin.block({
    version: options.version,
    prevBlock: this.tip.hash,
    merkleRoot: constants.NULL_HASH,
    ts: Math.max(bcoin.now(), this.tip.ts + 1),
    bits: options.target,
    nonce: 0,
    height: this.height
  });

  this.block.txs.push(this.coinbase);

  if (options.witness) {
    // Set up the witness nonce and
    // commitment output for segwit.
    this.witness = true;
    this.witnessNonce = utils.dsha256(new Buffer(this.tip.hash, 'hex'));
    this.coinbase.inputs[0].witness.items[0] = this.witnessNonce;
    this.coinbase.addOutput({
      script: new bcoin.script(),
      value: new bn(0)
    });
  }

  // Update coinbase since our coinbase was added.
  this.updateCoinbase();

  // Create our merkle root.
  this.updateMerkle();
}

utils.inherits(MinerBlock, EventEmitter);

/**
 * Update the commitment output for segwit.
 */

MinerBlock.prototype.updateCommitment = function updateCommitment() {
  var hash = this.block.getCommitmentHash();
  this.coinbase.outputs[1].script = bcoin.script.createCommitment(hash);
};

/**
 * Update the extranonce and coinbase reward.
 */

MinerBlock.prototype.updateCoinbase = function updateCoinbase() {
  this.coinbase.inputs[0].script[1] = bcoin.script.array(this.extraNonce);
  this.coinbase.outputs[0].value = this.block.getReward();
};

/**
 * Rebuild the merkle tree and update merkle root as well as the
 * timestamp (also calls {@link MinerBlock#updateCommitment}
 * if segwit is enabled).
 */

MinerBlock.prototype.updateMerkle = function updateMerkle() {
  // Always update commitment before updating merkle root.
  // The updated commitment output will change the merkle root.
  if (this.witness)
    this.updateCommitment();

  this.block.ts = Math.max(bcoin.now(), this.tip.ts + 1);
  this.block.merkleRoot = this.block.getMerkleRoot('hex');
};

/**
 * Add a transaction to the block. Rebuilds the merkle tree,
 * updates coinbase and commitment.
 * @param {TX} tx
 * @returns {Boolean} Whether the transaction was successfully added.
 */

MinerBlock.prototype.addTX = function addTX(tx) {
  var cost;

  if (tx.mutable)
    tx = tx.toTX();

  cost = this.block.getCost(true) + tx.getCost();

  if (cost > constants.block.MAX_COST)
    return false;

  if (this.block.hasTX(tx))
    return false;

  if (!this.witness && tx.hasWitness())
    return false;

  // Add the tx to our block
  this.block.txs.push(tx);

  // Update coinbase value
  this.updateCoinbase();

  // Update merkle root for new coinbase and new tx
  this.updateMerkle();

  return true;
};

/**
 * Hash until the nonce overflows, increment extraNonce, rebuild merkletree.
 * @returns {Boolean} Whether the nonce was found.
 */

MinerBlock.prototype.findNonce = function findNonce() {
  var tip = this.tip;
  var block = this.block;
  var target = this.target;
  var data = block.abbr();
  var now;

  // Track how long we've been at it.
  this.begin = utils.now();

  assert(block.ts > tip.ts);

  // The heart and soul of the miner: match the target.
  while (block.nonce <= 0xffffffff) {
    // Hash and test against the next target
    if (rcmp(this.dsha256(data), target) < 0)
      return true;

    // Increment the nonce to get a different hash
    block.nonce++;

    // Update the raw buffer (faster than
    // constantly serializing the block)
    utils.writeU32(data, block.nonce, 76);

    // Send progress report every so often
    if (block.nonce % 100000 === 0)
      this.sendStatus();
  }

  // Keep track of our iterations
  this.iterations++;

  // Send progress report
  this.sendStatus();

  // If we took more a second or more (likely),
  // skip incrementing the extra nonce and just
  // update the timestamp. This improves
  // performance because we do not have to
  // recalculate the merkle root.
  now = bcoin.now();
  if (now > block.ts && now > tip.ts) {
    block.ts = now;
    // Overflow the nonce
    block.nonce = 0;
    return false;
  }

  // Overflow the nonce and increment the extraNonce.
  block.nonce = 0;
  this.extraNonce.iaddn(1);

  // We incremented the extraNonce, need to update coinbase.
  this.updateCoinbase();

  // We changed the coinbase, need to update merkleRoot.
  this.updateMerkle();

  return false;
};

MinerBlock.prototype.__defineGetter__('hashes', function() {
  return new bn(this.iterations)
    .mul(utils.U32)
    .addn(this.block.nonce);
});

MinerBlock.prototype.__defineGetter__('rate', function() {
  if (!this.block.nonce)
    return 0;
  // Calculate our terrible hashrate
  return (this.block.nonce / (utils.now() - this.begin)) * 2 | 0;
});

/**
 * Send a progress report (emits `status`).
 */

MinerBlock.prototype.sendStatus = function sendStatus() {
  this.emit('status', {
    block: this.block,
    target: this.block.bits,
    hashes: this.hashes.toString(10),
    hashrate: this.rate,
    height: this.height,
    best: utils.revHex(this.tip.hash)
  });
};

/**
 * Mine until the block is found. Will take a breather
 * for 100ms every time the nonce overflows.
 * @param {Function} callback - Returns [Error, {@link Block}].
 */

MinerBlock.prototype.mine = function mine(callback) {
  var self = this;

  this.timeout = setTimeout(function() {
    // Try to find a block: do one iteration of extraNonce
    if (!self.findNonce())
      return self.mine(callback);

    self.block.txs[0] = self.block.txs[0].toTX();

    return callback(null, self.block);
  }, 100);
};

/**
 * Mine synchronously until the block is found.
 * @returns {Block}
 */

MinerBlock.prototype.mineSync = function mineSync() {
  while (!this.findNonce());
  this.block.txs[0] = this.block.txs[0].toTX();
  return this.block;
};

/**
 * Attempt to mine the block on the worker pool.
 * @param {Function} callback - Returns [Error, {@link Block}].
 */

MinerBlock.prototype.mineAsync = function mine(callback) {
  if (!this.workerPool)
    return this.mine(callback);

  this.workerPool.mine(this, callback);
};

/**
 * Destroy the minerblock. Stop mining. Clear timeout.
 */

MinerBlock.prototype.destroy = function destroy() {
  if (this.timeout) {
    clearTimeout(this.timeout);
    this.timeout = null;
  }
  this.block = null;
};

/**
 * "Reverse" comparison so we don't have
 * to waste time reversing the block hash.
 * @param {Buffer} a
 * @param {Buffer} b
 * @returns {Number}
 */

function rcmp(a, b) {
  var i;

  assert(a.length === b.length);

  for (i = a.length - 1; i >= 0; i--) {
    if (a[i] < b[i])
      return -1;
    if (a[i] > b[i])
      return 1;
  }

  return 0;
}

Miner.MinerBlock = MinerBlock;

module.exports = Miner;
