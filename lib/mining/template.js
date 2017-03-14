/*!
 * template.js - block template object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var assert = require('assert');
var BN = require('bn.js');
var util = require('../utils/util');
var crypto = require('../crypto/crypto');
var StaticWriter = require('../utils/staticwriter');
var Address = require('../primitives/address');
var TX = require('../primitives/tx');
var Block = require('../primitives/block');
var Input = require('../primitives/input');
var Output = require('../primitives/output');
var consensus = require('../protocol/consensus');
var policy = require('../protocol/policy');
var encoding = require('../utils/encoding');
var CoinView = require('../coins/coinview');
var Script = require('../script/script');
var common = require('./common');
var DUMMY = new Buffer(0);

/**
 * Block Template
 * @alias module:mining.BlockTemplate
 * @constructor
 * @param {Object} options
 */

function BlockTemplate(options) {
  if (!(this instanceof BlockTemplate))
    return new BlockTemplate(options);

  this.prevBlock = encoding.NULL_HASH;
  this.version = 1;
  this.height = 0;
  this.ts = 0;
  this.bits = 0;
  this.target = encoding.ZERO_HASH;
  this.locktime = 0;
  this.mtp = 0;
  this.flags = 0;
  this.coinbaseFlags = DUMMY;
  this.witness = false;
  this.address = new Address();
  this.sigops = 400;
  this.weight = 4000;
  this.interval = 210000;
  this.fees = 0;
  this.tree = new MerkleTree();
  this.commitment = DUMMY;
  this.left = DUMMY;
  this.right = DUMMY;
  this.items = [];

  if (options)
    this.fromOptions(options);
}

/**
 * Inject properties from options.
 * @private
 * @param {Object} options
 * @returns {BlockTemplate}
 */

BlockTemplate.prototype.fromOptions = function fromOptions(options) {
  assert(options);

  if (options.prevBlock != null) {
    assert(typeof options.prevBlock === 'string');
    this.prevBlock = options.prevBlock;
  }

  if (options.version != null) {
    assert(typeof options.version === 'number');
    this.version = options.version;
  }

  if (options.height != null) {
    assert(typeof options.height === 'number');
    this.height = options.height;
  }

  if (options.ts != null) {
    assert(typeof options.ts === 'number');
    this.ts = options.ts;
  }

  if (options.bits != null)
    this.setBits(options.bits);

  if (options.target != null)
    this.setTarget(options.target);

  if (options.locktime != null) {
    assert(typeof options.locktime === 'number');
    this.locktime = options.locktime;
  }

  if (options.mtp != null) {
    assert(typeof options.mtp === 'number');
    this.mtp = options.mtp;
  }

  if (options.flags != null) {
    assert(typeof options.flags === 'number');
    this.flags = options.flags;
  }

  if (options.coinbaseFlags != null) {
    assert(Buffer.isBuffer(options.coinbaseFlags));
    this.coinbaseFlags = options.coinbaseFlags;
  }

  if (options.witness != null) {
    assert(typeof options.witness === 'boolean');
    this.witness = options.witness;
  }

  if (options.address != null)
    this.address.fromOptions(options.address);

  if (options.sigops != null) {
    assert(typeof options.sigops === 'number');
    this.sigops = options.sigops;
  }

  if (options.weight != null) {
    assert(typeof options.weight === 'number');
    this.weight = options.weight;
  }

  if (options.interval != null) {
    assert(typeof options.interval === 'number');
    this.interval = options.interval;
  }

  if (options.fees != null) {
    assert(typeof options.fees === 'number');
    this.fees = options.fees;
  }

  if (options.items != null) {
    assert(Array.isArray(options.items));
    this.items = options.items;
  }

  return this;
};

/**
 * Instantiate block template from options.
 * @param {Object} options
 * @returns {BlockTemplate}
 */

BlockTemplate.fromOptions = function fromOptions(options) {
  return new BlockTemplate().fromOptions(options);
};

/**
 * Create witness commitment hash.
 * @returns {Buffer}
 */

BlockTemplate.prototype.getWitnessHash = function getWitnessHash() {
  var nonce = encoding.ZERO_HASH;
  var leaves = [];
  var i, item, root, data;

  leaves.push(encoding.ZERO_HASH);

  for (i = 0; i < this.items.length; i++) {
    item = this.items[i];
    leaves.push(item.tx.witnessHash());
  }

  root = crypto.createMerkleRoot(leaves);

  assert(!root.malleated);

  data = util.concat(root.hash, nonce);

  return crypto.hash256(data);
};

/**
 * Create witness commitment script.
 * @returns {Script}
 */

BlockTemplate.prototype.getWitnessScript = function getWitnessScript() {
  return Script.fromCommitment(this.commitment);
};

/**
 * Set the target (bits).
 * @param {Number} bits
 */

BlockTemplate.prototype.setBits = function setBits(bits) {
  assert(typeof bits === 'number');
  this.bits = bits;
  this.target = common.getTarget(bits);
};

/**
 * Set the target (uint256le).
 * @param {Buffer} target
 */

BlockTemplate.prototype.setTarget = function setTarget(target) {
  assert(Buffer.isBuffer(target));
  this.bits = common.getBits(target);
  this.target = target;
};

/**
 * Calculate the block reward.
 * @returns {Amount}
 */

BlockTemplate.prototype.getReward = function getReward() {
  var reward = consensus.getReward(this.height, this.interval);
  return reward + this.fees;
};

/**
 * Initialize the default coinbase.
 * @param {Buffer} hash - Witness commitment hash.
 * @returns {TX}
 */

BlockTemplate.prototype.createCoinbase = function createCoinbase(hash) {
  var scale = consensus.WITNESS_SCALE_FACTOR;
  var cb = new TX();
  var padding = 0;
  var input, output, commit;

  // Coinbase input.
  input = new Input();

  // Height (required in v2+ blocks)
  input.script.push(new BN(this.height));

  // Coinbase flags.
  input.script.push(encoding.ZERO_HASH160);

  // Smaller nonce for good measure.
  input.script.push(util.nonce(4));

  // Extra nonce: incremented when
  // the nonce overflows.
  input.script.push(encoding.ZERO_U64);

  input.script.compile();

  // Set up the witness nonce.
  if (this.witness) {
    input.witness.set(0, encoding.ZERO_HASH);
    input.witness.compile();
  }

  cb.inputs.push(input);

  // Reward output.
  output = new Output();
  output.script.fromPubkeyhash(encoding.ZERO_HASH160);
  output.value = this.getReward();

  cb.outputs.push(output);

  // If we're using segwit, we
  // need to set up the commitment.
  if (this.witness) {
    // Commitment output.
    commit = new Output();
    commit.script.fromCommitment(hash);
    cb.outputs.push(commit);
  }

  // Padding for the CB height (constant size).
  padding = 5 - input.script.code[0].getSize();
  assert(padding >= 0);

  // Reserved size.
  // Without segwit:
  //   CB weight = 500
  //   CB stripped size = 125
  //   CB size = 125
  //   Sigops cost = 4
  // With segwit:
  //   CB weight = 724
  //   CB stripped size = 172
  //   CB size = 208
  //   Sigops cost = 4
  if (!this.witness) {
    assert.equal(cb.getWeight() + padding * scale, 500);
    assert.equal(cb.getBaseSize() + padding, 125);
    assert.equal(cb.getSize() + padding, 125);
  } else {
    assert.equal(cb.getWeight() + padding * scale, 724);
    assert.equal(cb.getBaseSize() + padding, 172);
    assert.equal(cb.getSize() + padding, 208);
  }

  // Setup coinbase flags (variable size).
  input.script.set(1, this.coinbaseFlags);
  input.script.compile();

  // Setup output script (variable size).
  output.script.clear();
  output.script.fromAddress(this.address);

  cb.refresh();

  assert(input.script.getSize() <= 100,
    'Coinbase input script is too large!');

  return cb;
};

/**
 * Refresh the coinbase and merkle tree.
 */

BlockTemplate.prototype.refresh = function refresh() {
  var hash = this.getWitnessHash();
  var cb = this.createCoinbase(hash);
  var raw = cb.toNormal();
  var size = 0;
  var left, right;

  size += 4; // version
  size += 1; // varint inputs length
  size += cb.inputs[0].getSize(); // input size
  size -= 4 + 4 + 4; // -(nonce1 + nonce2 + sequence)

  // Cut off right after the nonce
  // push and before the sequence.
  left = raw.slice(0, size);

  // Include the sequence.
  size += 4 + 4; // nonce1 + nonce2
  right = raw.slice(size);

  this.commitment = hash;
  this.left = left;
  this.right = right;
  this.tree = MerkleTree.fromItems(this.items);
};

/**
 * Get raw coinbase with desired nonces.
 * @param {Number} nonce1
 * @param {Number} nonce2
 * @returns {Buffer}
 */

BlockTemplate.prototype.getRawCoinbase = function getRawCoinbase(nonce1, nonce2) {
  var size = 0;
  var bw;

  size += this.left.length;
  size += 4 + 4;
  size += this.right.length;

  bw = new StaticWriter(size);
  bw.writeBytes(this.left);
  bw.writeU32BE(nonce1);
  bw.writeU32BE(nonce2);
  bw.writeBytes(this.right);

  return bw.render();
};

/**
 * Calculate the merkle root with given nonces.
 * @param {Number} nonce1
 * @param {Number} nonce2
 * @returns {Buffer}
 */

BlockTemplate.prototype.getRoot = function getRoot(nonce1, nonce2) {
  var raw = this.getRawCoinbase(nonce1, nonce2);
  var hash = crypto.hash256(raw);
  return this.tree.withFirst(hash);
};

/**
 * Create raw block header with given parameters.
 * @param {Buffer} root
 * @param {Number} ts
 * @param {Number} nonce
 * @returns {Buffer}
 */

BlockTemplate.prototype.getHeader = function getHeader(root, ts, nonce) {
  var bw = new StaticWriter(80);

  bw.writeU32(this.version);
  bw.writeHash(this.prevBlock);
  bw.writeHash(root);
  bw.writeU32(ts);
  bw.writeU32(this.bits);
  bw.writeU32(nonce);

  return bw.render();
};

/**
 * Calculate proof with given parameters.
 * @param {Number} nonce1
 * @param {Number} nonce2
 * @param {Number} ts
 * @param {Number} nonce
 * @returns {BlockProof}
 */

BlockTemplate.prototype.getProof = function getProof(nonce1, nonce2, ts, nonce) {
  var root = this.getRoot(nonce1, nonce2);
  var data = this.getHeader(root, ts, nonce);
  var hash = crypto.hash256(data);
  return new BlockProof(hash, root, nonce1, nonce2, ts, nonce);
};

/**
 * Create coinbase from given parameters.
 * @param {Number} nonce1
 * @param {Number} nonce2
 * @returns {TX}
 */

BlockTemplate.prototype.getCoinbase = function getCoinbase(nonce1, nonce2) {
  var raw = this.getRawCoinbase(nonce1, nonce2);
  var tx = TX.fromRaw(raw);
  var input;

  if (this.witness) {
    input = tx.inputs[0];
    input.witness.push(encoding.ZERO_HASH);
    input.witness.compile();
    tx.refresh();
  }

  return tx;
};

/**
 * Create block from calculated proof.
 * @param {BlockProof} proof
 * @returns {Block}
 */

BlockTemplate.prototype.commit = function commit(proof) {
  var root = proof.root;
  var n1 = proof.nonce1;
  var n2 = proof.nonce2;
  var ts = proof.ts;
  var nonce = proof.nonce;
  var block = new Block();
  var i, tx, item;

  block.version = this.version;
  block.prevBlock = this.prevBlock;
  block.merkleRoot = root.toString('hex');
  block.ts = ts;
  block.bits = this.bits;
  block.nonce = nonce;

  tx = this.getCoinbase(n1, n2);

  block.txs.push(tx);

  for (i = 0; i < this.items.length; i++) {
    item = this.items[i];
    block.txs.push(item.tx);
  }

  return block;
};

/**
 * Quick and dirty way to
 * get a coinbase tx object.
 * @returns {TX}
 */

BlockTemplate.prototype.toCoinbase = function toCoinbase() {
  return this.getCoinbase(0, 0);
};

/**
 * Quick and dirty way to get a block
 * object (most likely to be an invalid one).
 * @returns {Block}
 */

BlockTemplate.prototype.toBlock = function toBlock() {
  var proof = this.getProof(0, 0, this.ts, 0);
  return this.commit(proof);
};

/**
 * Calculate the target difficulty.
 * @returns {Number}
 */

BlockTemplate.prototype.getDifficulty = function getDifficulty() {
  return common.getDifficulty(this.target);
};

/**
 * Set the reward output
 * address and refresh.
 * @param {Address} address
 */

BlockTemplate.prototype.setAddress = function setAddress(address) {
  this.address = Address(address);
  this.refresh();
};

/**
 * Add a transaction to the template.
 * @param {TX} tx
 * @param {CoinView} view
 */

BlockTemplate.prototype.addTX = function addTX(tx, view) {
  var item, weight, sigops;

  assert(!tx.mutable, 'Cannot add mutable TX to block.');

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
  this.items.push(item);

  return true;
};

/**
 * Add a transaction to the template
 * (less verification than addTX).
 * @param {TX} tx
 * @param {CoinView?} view
 */

BlockTemplate.prototype.pushTX = function pushTX(tx, view) {
  var item, weight, sigops;

  assert(!tx.mutable, 'Cannot add mutable TX to block.');

  if (!view)
    view = new CoinView();

  item = BlockEntry.fromTX(tx, view, this);
  weight = item.tx.getWeight();
  sigops = item.sigops;

  this.weight += weight;
  this.sigops += sigops;
  this.fees += item.fee;

  // Add the tx to our block
  this.items.push(item);

  return true;
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
  this.descRate = 0;
  this.depCount = 0;
}

/**
 * Instantiate block entry from transaction.
 * @param {TX} tx
 * @param {CoinView} view
 * @param {BlockTemplate} attempt
 * @returns {BlockEntry}
 */

BlockEntry.fromTX = function fromTX(tx, view, attempt) {
  var item = new BlockEntry(tx);
  item.fee = tx.getFee(view);
  item.rate = tx.getRate(view);
  item.priority = tx.getPriority(view, attempt.height);
  item.free = false;
  item.sigops = tx.getSigopsCost(view, attempt.flags);
  item.descRate = item.rate;
  return item;
};

/**
 * Instantiate block entry from mempool entry.
 * @param {MempoolEntry} entry
 * @param {BlockTemplate} attempt
 * @returns {BlockEntry}
 */

BlockEntry.fromEntry = function fromEntry(entry, attempt) {
  var item = new BlockEntry(entry.tx);
  item.fee = entry.getFee();
  item.rate = entry.getDeltaRate();
  item.priority = entry.getPriority(attempt.height);
  item.free = entry.getDeltaFee() < policy.getMinFee(entry.size);
  item.sigops = entry.sigops;
  item.descRate = entry.getDescRate();
  return item;
};

/*
 * BlockProof
 * @constructor
 * @param {Hash} hash
 * @param {Hash} root
 * @param {Number} nonce1
 * @param {Number} nonce2
 * @param {Number} ts
 * @param {Number} nonce
 */

function BlockProof(hash, root, nonce1, nonce2, ts, nonce) {
  this.hash = hash;
  this.root = root;
  this.nonce1 = nonce1;
  this.nonce2 = nonce2;
  this.ts = ts;
  this.nonce = nonce;
}

BlockProof.prototype.rhash = function rhash() {
  return util.revHex(this.hash.toString('hex'));
};

BlockProof.prototype.verify = function verify(target) {
  return common.rcmp(this.hash, target) <= 0;
};

BlockProof.prototype.getDifficulty = function getDifficulty() {
  return common.getDifficulty(this.hash);
};

/*
 * MerkleTree
 * @constructor
 * @property {Hash[]} steps
 */

function MerkleTree() {
  this.steps = [];
}

MerkleTree.prototype.withFirst = function withFirst(hash) {
  var i, step, data;

  for (i = 0; i < this.steps.length; i++) {
    step = this.steps[i];
    data = util.concat(hash, step);
    hash = crypto.hash256(data);
  }

  return hash;
};

MerkleTree.prototype.toJSON = function toJSON() {
  var steps = [];
  var i, step;

  for (i = 0; i < this.steps.length; i++) {
    step = this.steps[i];
    steps.push(step.toString('hex'));
  }

  return steps;
};

MerkleTree.prototype.fromItems = function fromItems(items) {
  var leaves = [];
  var i, item;

  leaves.push(encoding.ZERO_HASH);

  for (i = 0; i < items.length; i++) {
    item = items[i];
    leaves.push(item.tx.hash());
  }

  return this.fromLeaves(leaves);
};

MerkleTree.fromItems = function fromItems(items) {
  return new MerkleTree().fromItems(items);
};

MerkleTree.prototype.fromBlock = function fromBlock(txs) {
  var leaves = [];
  var i, tx;

  leaves.push(encoding.ZERO_HASH);

  for (i = 1; i < txs.length; i++) {
    tx = txs[i];
    leaves.push(tx.hash());
  }

  return this.fromLeaves(leaves);
};

MerkleTree.fromBlock = function fromBlock(txs) {
  return new MerkleTree().fromBlock(txs);
};

MerkleTree.prototype.fromLeaves = function fromLeaves(leaves) {
  var len = leaves.length;
  var i, hashes, data, hash;

  while (len > 1) {
    this.steps.push(leaves[1]);

    if (len % 2)
      leaves.push(leaves[len - 1]);

    hashes = [null];

    for (i = 2; i < len; i += 2) {
      data = util.concat(leaves[i], leaves[i + 1]);
      hash = crypto.hash256(data);
      hashes.push(hash);
    }

    leaves = hashes;
    len = leaves.length;
  }

  return this;
};

MerkleTree.fromLeaves = function fromLeaves(leaves) {
  return new MerkleTree().fromLeaves(leaves);
};

/*
 * Expose
 */

exports = BlockTemplate;
exports.BlockTemplate = BlockTemplate;
exports.BlockEntry = BlockEntry;

module.exports = exports;
