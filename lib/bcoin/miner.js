/*!
 * miner.js - inefficient miner for bcoin (because we can)
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var bcoin = require('./env');
var utils = require('./utils');
var assert = utils.assert;
var constants = bcoin.protocol.constants;
var bn = require('bn.js');
var EventEmitter = require('events').EventEmitter;
var AsyncObject = require('./async');
var BufferReader = require('./reader');
var BufferWriter = require('./writer');

/**
 * A bitcoin miner (supports mining witness blocks).
 * @exports Miner
 * @constructor
 * @param {Object} options
 * @param {Base58Address} options.address - Payout address.
 * @param {String?} [options.coinbaseFlags="mined by bcoin"]
 * @property {Boolean} running
 * @property {Boolean} loaded
 * @emits Miner#block
 * @emits Miner#status
 */

function Miner(options) {
  if (!(this instanceof Miner))
    return new Miner(options);

  AsyncObject.call(this);

  if (!options)
    options = {};

  this.options = options;
  this.address = bcoin.address(this.options.address);
  this.coinbaseFlags = this.options.coinbaseFlags || 'mined by bcoin';

  this.pool = options.pool;
  this.chain = options.chain;
  this.logger = options.logger || this.chain.logger;
  this.mempool = options.mempool;
  this.fees = this.mempool ? this.mempool.fees : options.fees;

  assert(this.chain, 'Miner requires a blockchain.');

  this.network = this.chain.network;
  this.running = false;
  this.timeout = null;
  this.attempt = null;
  this.workerPool = null;

  if (bcoin.useWorkers) {
    this.workerPool = new bcoin.workers({
      size: this.options.parallel ? 2 : 1,
      timeout: -1
    });
  }

  this._init();
}

utils.inherits(Miner, AsyncObject);

/**
 * Initialize the miner.
 * @private
 */

Miner.prototype._init = function _init() {
  var self = this;

  if (this.mempool) {
    this.mempool.on('tx', function(tx) {
      if (!self.running)
        return;
      if (self.attempt)
        self.attempt.addTX(tx.clone());
    });
  } else if (this.pool) {
    this.pool.on('tx', function(tx) {
      if (!self.running)
        return;
      if (self.attempt)
        self.attempt.addTX(tx.clone());
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
 * @param {Function} callback
 */

Miner.prototype._open = function open(callback) {
  if (this.mempool)
    this.mempool.open(callback);
  else
    this.chain.open(callback);
};

/**
 * Close the miner.
 * @alias Miner#close
 * @param {Function} callback
 */

Miner.prototype._close = function close(callback) {
  return utils.nextTick(callback);
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
            self.logger.warning('%s could not be added to chain.', block.rhash);
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

  if (this.workerPool)
    this.workerPool.destroy();
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
        parallel: self.options.parallel,
        network: self.network
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
 * @param {ChainEntry} options.tip
 * @param {Number} options.height
 * @param {Number} options.target - Compact form.
 * @param {Base58Address} options.address - Payout address.
 * @param {Boolean} options.witness - Allow witness
 * transactions, mine a witness block.
 * @param {String} options.coinbaseFlags
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
  this.bits = options.target;
  this.target = utils.fromCompact(this.bits).toArrayLike(Buffer, 'le', 32);
  this.extraNonce = new bn(0);
  this.iterations = 0;
  this.coinbaseFlags = options.coinbaseFlags;
  this.witness = options.witness;
  this.address = options.address;
  this.network = bcoin.network.get(options.network);

  this.coinbase = new bcoin.tx();
  this.coinbase.mutable = true;

  this.block = new bcoin.block();
  this.block.mutable = true;

  this._init();
}

/**
 * Initialize the block.
 * @private
 */

MinerBlock.prototype._init = function _init() {
  var options = this.options;
  var block = this.block;
  var cb = this.coinbase;
  var i, input, output, hash, witnessNonce;

  // Coinbase input.
  input = new bcoin.input();

  // Height (required in v2+ blocks)
  input.script.set(0, new bn(this.height));

  // extraNonce - incremented when
  // the nonce overflows.
  input.script.set(1, this.extraNonce);

  // Add a nonce to ensure we don't
  // collide with a previous coinbase
  // of ours. This isn't really
  // necessary nowdays due to bip34
  // (used above).
  input.script.set(2, utils.nonce());

  // Let the world know this little
  // miner succeeded.
  input.script.set(3, this.coinbaseFlags);

  input.script.compile();

  cb.inputs.push(input);

  // Reward output.
  output = new bcoin.output();
  output.script.fromAddress(this.address);

  cb.outputs.push(output);

  // If we're using segwit, we need to
  // set up the nonce and commitment.
  if (this.witness) {
    // Our witness nonce is the hash256
    // of the previous block hash.
    hash = new Buffer(this.tip.hash, 'hex');
    witnessNonce = utils.hash256(hash);

    // Set up the witness nonce.
    input.witness.set(0, witnessNonce);
    input.witness.compile();

    // Commitment output.
    cb.outputs.push(new bcoin.output());
  }

  // Setup our block.
  block.version = options.version;
  block.prevBlock = this.tip.hash;
  block.merkleRoot = constants.NULL_HASH;
  block.ts = Math.max(bcoin.now(), this.tip.ts + 1);
  block.bits = this.bits;
  block.nonce = 0;
  block.height = this.height;

  block.addTX(cb);

  if (options.txs) {
    for (i = 0; i < options.txs.length; i++)
      block.addTX(options.txs[i]);
  }

  // Update coinbase since our coinbase was added.
  this.updateCoinbase();

  // Create our merkle root.
  this.updateMerkle();
};

utils.inherits(MinerBlock, EventEmitter);

/**
 * Update the commitment output for segwit.
 */

MinerBlock.prototype.updateCommitment = function updateCommitment() {
  var output = this.coinbase.outputs[1];
  var flags = this.coinbaseFlags;
  var hash;

  // Recalculate witness merkle root.
  hash = this.block.getCommitmentHash();

  // Update commitment.
  output.script.clear();
  output.script.fromCommitment(hash, flags);
};

/**
 * Update the extra nonce and coinbase reward.
 */

MinerBlock.prototype.updateCoinbase = function updateCoinbase() {
  var input = this.coinbase.inputs[0];
  var output = this.coinbase.outputs[0];

  // Update extra nonce.
  input.script.set(1, this.extraNonce);
  input.script.compile();

  // Update reward.
  output.value = this.block.getReward(this.network);
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

  // Update timestamp.
  this.block.ts = Math.max(bcoin.now(), this.tip.ts + 1);

  // Recalculate merkle root.
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

  cost = this.block.getCost() + tx.getCost();

  if (cost > constants.block.MAX_COST)
    return false;

  if (this.block.hasTX(tx))
    return false;

  if (!this.witness && tx.hasWitness())
    return false;

  // Add the tx to our block
  this.block.addTX(tx);

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
    if (rcmp(utils.hash256(data), target) <= 0)
      return true;

    // Increment the nonce to get a different hash
    block.nonce++;

    // Update the raw buffer (faster than
    // constantly serializing the block)
    data.writeUInt32LE(block.nonce, 76, true);

    // Send progress report every so often
    if (block.nonce % 500000 === 0)
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
  return this.iterations * 0xffffffff + this.block.nonce;
});

MinerBlock.prototype.__defineGetter__('rate', function() {
  return (this.block.nonce / (utils.now() - this.begin)) | 0;
});

/**
 * Send a progress report (emits `status`).
 */

MinerBlock.prototype.sendStatus = function sendStatus() {
  this.emit('status', {
    block: this.block,
    target: this.block.bits,
    hashes: this.hashes,
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

    return callback(null, self.block);
  }, 100);
};

/**
 * Mine synchronously until the block is found.
 * @returns {Block}
 */

MinerBlock.prototype.mineSync = function mineSync() {
  while (!this.findNonce());
  return this.block;
};

/**
 * Attempt to mine the block on the worker pool.
 * @param {Function} callback - Returns [Error, {@link Block}].
 */

MinerBlock.prototype.mineAsync = function mine(callback) {
  var self = this;

  if (!this.workerPool)
    return this.mine(callback);

  function done(err, block) {
    self.workerPool.destroy();
    callback(err, block);
  }

  if (this.options.parallel) {
    done = utils.once(done);
    this.workerPool.mine(this, done);
    this.workerPool.mine(this, done);
    return;
  }

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
 * Serialize the miner block.
 * @returns {Buffer}
 */

MinerBlock.prototype.toRaw = function toRaw(writer) {
  var p = new BufferWriter(writer);
  var i;

  p.writeU32(this.network.magic);
  p.writeBytes(this.tip.toRaw());
  p.writeU32(this.block.version);
  p.writeU32(this.block.bits);
  p.writeVarBytes(this.address.toRaw());
  p.writeVarString(this.coinbaseFlags, 'utf8');
  p.writeU8(this.witness ? 1 : 0);
  p.writeVarint(this.block.txs.length - 1);

  for (i = 1; i < this.block.txs.length; i++)
    p.writeBytes(this.block.txs[i].toRaw());

  if (!writer)
    p = p.render();

  return p;
};

/**
 * Instantiate a miner block from serialized data.
 * @params {Buffer} data
 * @returns {MinerBlock}
 */

MinerBlock.fromRaw = function fromRaw(data) {
  var p = new BufferReader(data);
  var network = bcoin.network.fromMagic(p.readU32());
  var tip = bcoin.chainentry.fromRaw(null, p);
  var version = p.readU32();
  var bits = p.readU32();
  var address = bcoin.address.fromRaw(p.readVarBytes());
  var coinbaseFlags = p.readVarString('utf8');
  var witness = p.readU8() === 1;
  var count = p.readVarint();
  var txs = [];
  var i;

  for (i = 0; i < count; i++)
    txs.push(bcoin.tx.fromRaw(p));

  tip.network = network;

  return new MinerBlock({
    network: network,
    tip: tip,
    version: version,
    target: bits,
    address: address,
    coinbaseFlags: coinbaseFlags,
    witness: witness,
    txs: txs
  });
};

/**
 * "Reverse" comparison so we don't have
 * to waste time reversing the block hash.
 * @memberof Miner
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

/*
 * Expose
 */

module.exports = Miner;
