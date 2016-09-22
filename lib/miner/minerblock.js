/*!
 * miner.js - inefficient miner for bcoin (because we can)
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var bcoin = require('../env');
var utils = require('../utils/utils');
var spawn = require('../utils/spawn');
var crypto = require('../crypto/crypto');
var assert = utils.assert;
var constants = bcoin.constants;
var bn = require('bn.js');
var EventEmitter = require('events').EventEmitter;
var BufferReader = require('../utils/reader');
var BufferWriter = require('../utils/writer');

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

  EventEmitter.call(this);

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
  this.timeout = null;

  if (typeof this.coinbaseFlags === 'string')
    this.coinbaseFlags = new Buffer(this.coinbaseFlags, 'utf8');

  this.coinbase = new bcoin.tx();
  this.coinbase.mutable = true;

  this.block = new bcoin.block();
  this.block.mutable = true;

  this._init();
}

utils.inherits(MinerBlock, EventEmitter);

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
    witnessNonce = crypto.hash256(hash);

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
 * Increment the extraNonce.
 */

MinerBlock.prototype.updateNonce = function updateNonce() {
  this.block.ts = Math.max(bcoin.now(), this.tip.ts + 1);

  // Overflow the nonce and increment the extraNonce.
  this.block.nonce = 0;
  this.extraNonce.iaddn(1);

  // We incremented the extraNonce, need to update coinbase.
  this.updateCoinbase();

  // We changed the coinbase, need to update merkleRoot.
  this.updateMerkle();
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
  var weight;

  assert(!tx.mutable, 'Cannot add mutable TX to block.');

  weight = this.block.getWeight() + tx.getWeight();

  if (weight > constants.block.MAX_WEIGHT)
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
    // Hash and test against the next target.
    if (rcmp(crypto.hash256(data), target) <= 0) {
      this.coinbase.mutable = false;
      this.block.mutable = false;
      return true;
    }

    // Increment the nonce to get a different hash
    block.nonce++;

    // Update the raw buffer (faster than
    // constantly serializing the headers).
    data.writeUInt32LE(block.nonce, 76, true);

    // Send progress report every so often.
    if (block.nonce % 500000 === 0)
      this.sendStatus();
  }

  // Keep track of our iterations.
  this.iterations++;

  // Send progress report.
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
  this.updateNonce();

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

MinerBlock.prototype.mine = spawn.co(function* mine() {
  yield this.wait(100);

  // Try to find a block: do one iteration of extraNonce
  if (!this.findNonce()) {
    yield this.mine();
    return;
  }

  return this.block;
});

/**
 * Wait for a timeout.
 * @param {Number} time
 * @returns {Promise}
 */

MinerBlock.prototype.wait = function wait(time) {
  var self = this;
  return new Promise(function(resolve, reject) {
    self.timeout = setTimeout(function() {
      resolve();
    }, time);
  });
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

MinerBlock.prototype.mineAsync = spawn.co(function* mineAsync() {
  var block;

  if (!this.workerPool)
    return yield this.mine();

  block = yield this.workerPool.mine(this);

  this.workerPool.destroy();

  return block;
});

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
  p.writeVarBytes(this.coinbaseFlags);
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
  var coinbaseFlags = p.readVarBytes();
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

/*
 * Expose
 */

module.exports = MinerBlock;
