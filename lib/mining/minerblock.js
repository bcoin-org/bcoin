/*!
 * minerblock.js - miner block object for bcoin (because we can)
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var assert = require('assert');
var EventEmitter = require('events').EventEmitter;
var BN = require('bn.js');
var util = require('../utils/util');
var co = require('../utils/co');
var StaticWriter = require('../utils/staticwriter');
var Network = require('../protocol/network');
var TX = require('../primitives/tx');
var Block = require('../primitives/block');
var Input = require('../primitives/input');
var Output = require('../primitives/output');
var mine = require('./mine');
var workerPool = require('../workers/workerpool').pool;
var consensus = require('../protocol/consensus');
var encoding = require('../utils/encoding');

/**
 * MinerBlock (block attempt)
 * @alias module:mining.MinerBlock
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

  this.network = Network.get(options.network);
  this.tip = options.tip;
  this.version = options.version;
  this.height = options.tip.height + 1;
  this.bits = options.bits;
  this.target = consensus.fromCompact(this.bits).toArrayLike(Buffer, 'le', 32);
  this.locktime = options.locktime;
  this.flags = options.flags;
  this.nonce1 = 0;
  this.nonce2 = 0;
  this.iterations = 0;
  this.coinbaseFlags = options.coinbaseFlags;
  this.witness = options.witness;
  this.address = options.address;
  this.reward = consensus.getReward(this.height, this.network.halvingInterval);

  this.destroyed = false;
  this.committed = false;

  this.sigops = options.sigops;
  this.weight = options.weight;
  this.fees = 0;
  this.items = [];

  this.coinbase = new TX();
  this.coinbase.mutable = true;

  this.block = new Block();
  this.block.mutable = true;

  this._init();
}

util.inherits(MinerBlock, EventEmitter);

/**
 * Nonce range interval.
 * @const {Number}
 * @default
 */

MinerBlock.INTERVAL = 0xffffffff / 1500 | 0;

/**
 * Calculate number of hashes.
 * @returns {Number}
 */

MinerBlock.prototype.getHashes = function() {
  return this.iterations * 0xffffffff + this.block.nonce;
};

/**
 * Calculate hashrate.
 * @returns {Number}
 */

MinerBlock.prototype.getRate = function() {
  return (this.block.nonce / (util.now() - this.begin)) | 0;
};

/**
 * Initialize the block.
 * @private
 */

MinerBlock.prototype._init = function _init() {
  var scale = consensus.WITNESS_SCALE_FACTOR;
  var hash = encoding.ZERO_HASH;
  var block = this.block;
  var cb = this.coinbase;
  var weight = 0;
  var sigops = 0;
  var input, output, commit, padding;

  assert(this.coinbaseFlags.length <= 20);

  // Setup our block.
  block.version = this.version;
  block.prevBlock = this.tip.hash;
  block.merkleRoot = encoding.NULL_HASH;
  block.ts = Math.max(this.network.now(), this.tip.ts + 1);
  block.bits = this.bits;
  block.nonce = 0;

  // Coinbase input.
  input = new Input();

  // Height (required in v2+ blocks)
  input.script.set(0, new BN(this.height));

  // Let the world know this little
  // miner succeeded.
  input.script.set(1, encoding.ZERO_HASH160);

  // Smaller nonce for good measure.
  input.script.set(2, util.nonce().slice(0, 4));

  // extraNonce - incremented when
  // the nonce overflows.
  input.script.set(3, this.extraNonce());

  input.script.compile();

  // Set up the witness nonce.
  if (this.witness) {
    input.witness.set(0, block.createWitnessNonce());
    input.witness.compile();
  }

  cb.inputs.push(input);

  // Reward output.
  output = new Output();
  output.script.fromPubkeyhash(encoding.ZERO_HASH160);

  cb.outputs.push(output);

  // If we're using segwit, we
  // need to set up the commitment.
  if (this.witness) {
    // Commitment output.
    commit = new Output();
    commit.script.fromCommitment(hash);
    cb.outputs.push(commit);
  }

  block.txs.push(cb);

  // Initialize weight.
  weight = block.getWeight();

  // 4 extra bytes for varint tx count.
  weight += 4 * scale;

  // Padding for the CB height (constant size).
  padding = 5 - input.script.code[0].getSize();
  assert(padding >= 0);

  weight += padding * scale;

  // Reserved size.
  // Without segwit:
  //   Block weight = 840
  //   Block stripped size = 210
  //   Block size = 210
  //   CB weight = 500
  //   CB stripped size = 125
  //   CB size = 125
  //   Sigops cost = 4
  // With segwit:
  //   Block weight = 1064
  //   Block stripped size = 257
  //   Block size = 293
  //   CB weight = 724
  //   CB stripped size = 172
  //   CB size = 208
  //   Sigops cost = 4
  if (!this.witness) {
    assert.equal(weight, 840);
    assert.equal(block.getBaseSize() + 4 + padding, 210);
    assert.equal(block.getSize() + 4 + padding, 210);
    assert.equal(cb.getWeight() + padding * scale, 500);
    assert.equal(cb.getBaseSize() + padding, 125);
    assert.equal(cb.getSize() + padding, 125);
  } else {
    assert.equal(weight, 1064);
    assert.equal(block.getBaseSize() + 4 + padding, 257);
    assert.equal(block.getSize() + 4 + padding, 293);
    assert.equal(cb.getWeight() + padding * scale, 724);
    assert.equal(cb.getBaseSize() + padding, 172);
    assert.equal(cb.getSize() + padding, 208);
  }

  // Initialize sigops weight.
  sigops = 4;

  // Setup coinbase flags (variable size).
  input.script.set(1, this.coinbaseFlags);
  input.script.compile();

  // Setup output script (variable size).
  output.script.clear();
  output.script.fromAddress(this.address);

  // Update commitments.
  this.refresh();

  // Ensure the variable size
  // stuff didn't break anything.
  assert(block.getWeight() <= weight,
    'Coinbase exceeds reserved size!');

  assert(cb.getSigopsCost(null, this.flags) <= sigops,
    'Coinbase exceeds reserved sigops!');

  assert(this.weight >= weight,
    'Coinbase exceeds reserved size!');

  assert(this.sigops >= sigops,
    'Coinbase exceeds reserved sigops!');
};

/**
 * Update coinbase, witness
 * commitment, and merkle root.
 */

MinerBlock.prototype.refresh = function refresh() {
  // Update coinbase.
  this.updateCoinbase();

  // Witness commitment.
  if (this.witness)
    this.updateCommitment();

  // Create our merkle root.
  this.updateMerkle();
};

/**
 * Update the commitment output for segwit.
 */

MinerBlock.prototype.updateCommitment = function updateCommitment() {
  var output = this.coinbase.outputs[1];
  var hash;

  // Recalculate witness merkle root.
  hash = this.block.createCommitmentHash();

  // Update commitment.
  output.script.clear();
  output.script.fromCommitment(hash);
};

/**
 * Update the extra nonce and coinbase reward.
 */

MinerBlock.prototype.updateCoinbase = function updateCoinbase() {
  var input = this.coinbase.inputs[0];
  var output = this.coinbase.outputs[0];

  // Update extra nonce.
  input.script.set(3, this.extraNonce());
  input.script.compile();

  // Update reward.
  output.value = this.reward + this.fees;
};

/**
 * Increment the extraNonce.
 */

MinerBlock.prototype.updateNonce = function updateNonce() {
  // Overflow the nonce and increment the extraNonce.
  this.block.nonce = 0;
  this.nonce1++;

  // Wrap at 4 bytes.
  if (this.nonce1 === 0xffffffff) {
    this.nonce1 = 0;
    this.nonce2++;
  }

  // We incremented the extraNonce, need to update coinbase.
  this.updateCoinbase();

  // We changed the coinbase, need to update merkleRoot.
  this.updateMerkle();
};

/**
 * Rebuild the merkle tree and update merkle root.
 */

MinerBlock.prototype.updateMerkle = function updateMerkle() {
  // Recalculate merkle root.
  this.block.merkleRoot = this.block.createMerkleRoot('hex');
};

/**
 * Render extraNonce.
 * @returns {Buffer}
 */

MinerBlock.prototype.extraNonce = function extraNonce() {
  var bw = new StaticWriter(8);
  bw.writeU32BE(this.nonce1);
  bw.writeU32BE(this.nonce2);
  return bw.render();
};

/**
 * Add a transaction to the block. Rebuilds the merkle tree,
 * updates coinbase and commitment.
 * @param {TX} tx
 * @returns {Boolean} Whether the transaction was successfully added.
 */

MinerBlock.prototype.addTX = function addTX(tx, view) {
  var item, weight, sigops;

  assert(!tx.mutable, 'Cannot add mutable TX to block.');

  if (this.block.hasTX(tx))
    return false;

  item = BlockEntry.fromTX(tx, view, this);
  weight = item.tx.getWeight();
  sigops = item.sigops;

  if (!tx.isFinal(this.height, this.locktime))
    return false;

  if (this.weight + weight > consensus.MAX_BLOCK_WEIGHT)
    return false;

  if (this.sigops + sigops > consensus.MAX_BLOCK_SIGOPS_COST)
    return false;

  if (!this.witness && tx.hasWitness())
    return false;

  this.weight += weight;
  this.sigops += sigops;
  this.fees += item.fee;

  // Add the tx to our block
  this.block.txs.push(tx);
  this.items.push(item);

  // Update commitments.
  this.refresh();

  return true;
};

/**
 * Hash until the nonce overflows.
 * @returns {Boolean} Whether the nonce was found.
 */

MinerBlock.prototype.findNonce = function findNonce() {
  var block = this.block;
  var target = this.target;
  var data = block.abbr();
  var interval = MinerBlock.INTERVAL;
  var min = 0;
  var max = interval;
  var nonce;

  while (max <= 0xffffffff) {
    nonce = mine(data, target, min, max);

    if (nonce !== -1)
      break;

    block.nonce = max;

    min += interval;
    max += interval;

    this.sendStatus();
  }

  return nonce;
};

/**
 * Hash until the nonce overflows.
 * @method
 * @returns {Promise} - Returns Boolean.
 */

MinerBlock.prototype.findNonceAsync = co(function* findNonceAsync() {
  var block = this.block;
  var target = this.target;
  var interval = MinerBlock.INTERVAL;
  var min = 0;
  var max = interval;
  var data, nonce;

  while (max <= 0xffffffff) {
    data = block.abbr();
    nonce = yield workerPool.mine(data, target, min, max);

    if (nonce !== -1)
      break;

    if (this.destroyed)
      return nonce;

    block.nonce = max;

    min += interval;
    max += interval;

    this.sendStatus();
  }

  return nonce;
});

/**
 * Mine synchronously until the block is found.
 * @returns {Block}
 */

MinerBlock.prototype.mine = function mine() {
  var nonce;

  // Track how long we've been at it.
  this.begin = util.now();

  for (;;) {
    nonce = this.findNonce();

    if (nonce !== -1)
      break;

    this.iterate();
  }

  this.commit(nonce);

  return this.block;
};

/**
 * Mine asynchronously until the block is found.
 * @method
 * @returns {Promise} - Returns {@link Block}.
 */

MinerBlock.prototype.mineAsync = co(function* mineAsync() {
  var nonce;

  // Track how long we've been at it.
  this.begin = util.now();

  for (;;) {
    nonce = yield this.findNonceAsync();

    if (nonce !== -1)
      break;

    if (this.destroyed)
      return;

    this.iterate();
  }

  this.commit(nonce);

  return this.block;
});

/**
 * Increment extraNonce, rebuild merkletree.
 */

MinerBlock.prototype.iterate = function iterate() {
  // Keep track of our iterations.
  this.iterations++;

  // Send progress report.
  this.sendStatus();

  // Overflow the nonce and increment the extraNonce.
  this.updateNonce();
};

/**
 * Commit and finalize mined block.
 * @returns {Block}
 */

MinerBlock.prototype.commit = function commit(nonce) {
  assert(!this.committed, 'Block is already committed.');
  this.committed = true;
  this.block.nonce = nonce;
  this.block.mutable = false;
  this.coinbase.mutable = false;
  return this.block;
};

/**
 * Send a progress report (emits `status`).
 */

MinerBlock.prototype.sendStatus = function sendStatus() {
  this.emit('status', {
    block: this.block,
    target: this.block.bits,
    hashes: this.getHashes(),
    hashrate: this.getRate(),
    height: this.height,
    best: util.revHex(this.tip.hash)
  });
};

/**
 * Destroy the minerblock. Stop mining.
 */

MinerBlock.prototype.destroy = function destroy() {
  this.destroyed = true;
};

/**
 * BlockEntry
 * @alias module:mining.BlockEntry
 * @constructor
 * @param {TX} tx
 * @property {TX} tx
 * @property {Hash} hash
 * @property {Amount} fee
 * @property {Rate} rate
 * @property {Number} priority
 * @property {Boolean} free
 * @property {Sigops} sigops
 * @property {Number} depCount
 */

function BlockEntry(tx) {
  this.tx = tx;
  this.hash = tx.hash('hex');
  this.fee = 0;
  this.rate = 0;
  this.priority = 0;
  this.free = false;
  this.sigops = 0;
  this.depCount = 0;
  this.descRate = 0;
}

/**
 * Instantiate block entry from transaction.
 * @param {TX} tx
 * @param {CoinView} view
 * @param {MinerBlock} attempt
 * @returns {BlockEntry}
 */

BlockEntry.fromTX = function fromTX(tx, view, attempt) {
  var entry = new BlockEntry(tx);
  entry.fee = tx.getFee(view);
  entry.rate = tx.getRate(view);
  entry.priority = tx.getPriority(view, attempt.height);
  entry.free = false;
  entry.sigops = tx.getSigopsCost(view, attempt.flags);
  entry.descRate = entry.rate;
  return entry;
};

/**
 * Instantiate block entry from mempool entry.
 * @param {MempoolEntry} entry
 * @param {MinerBlock} attempt
 * @returns {BlockEntry}
 */

BlockEntry.fromEntry = function fromEntry(entry, attempt) {
  var item = new BlockEntry(entry.tx);
  item.fee = entry.getFee();
  item.rate = entry.getRate();
  item.priority = entry.getPriority(attempt.height);
  item.free = entry.isFree(attempt.height);
  item.sigops = entry.sigops;
  item.descRate = entry.getDescRate();
  return item;
};

/*
 * Expose
 */

exports = MinerBlock;
exports.MinerBlock = MinerBlock;
exports.BlockEntry = BlockEntry;

module.exports = exports;
