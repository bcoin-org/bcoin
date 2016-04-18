/*!
 * block.js - block object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/indutny/bcoin
 */

module.exports = function(bcoin) {

var bn = require('bn.js');
var utils = require('./utils');
var assert = utils.assert;
var constants = bcoin.protocol.constants;
var network = bcoin.protocol.network;
var BufferWriter = require('./writer');
var BufferReader = require('./reader');

/**
 * Represents a full block.
 * @exports Block
 * @constructor
 * @extends AbstractBlock
 * @param {NakedBlock} data
 * @property {String} type - "block" (inv type).
 * @property {Number} version - Block version. Note
 * that BCoin reads versions as unsigned despite
 * them being signed on the protocol level. This
 * number will never be negative.
 * @property {Hash} prevBlock - Previous block hash.
 * @property {Hash} merkleRoot - Merkle root hash.
 * @property {Number} ts - Timestamp.
 * @property {Number} bits
 * @property {Number} nonce
 * @property {Number} totalTX - Transaction count.
 * @property {Number} height - Block height (-1 if not in the chain).
 * @property {TX[]} txs - Transaction vector.
 * @property {Hash?} commitmentHash - Commitment hash for segwit.
 * @property {Buffer?} witnessNonce - Witness nonce for segwit.
 * @property {ReversedHash} rhash - Reversed block hash (uint256le).
 */

function Block(data) {
  var self = this;

  if (!(this instanceof Block))
    return new Block(data);

  bcoin.abstractblock.call(this, data);

  this.type = 'block';

  this._witnessSize = data._witnessSize || 0;

  this.txs = data.txs || [];

  this._cbHeight = null;

  this.txs = this.txs.map(function(data, i) {
    if (data instanceof bcoin.tx)
      return data;

    return bcoin.tx(data, self, i);
  });
}

utils.inherits(Block, bcoin.abstractblock);

/**
 * Serialize the block. Include witnesses if present.
 * @returns {Buffer}
 */

Block.prototype.render = function render() {
  return this.getRaw();
};

/**
 * Serialize the block, do not include witnesses.
 * @returns {Buffer}
 */

Block.prototype.renderNormal = function renderNormal() {
  return bcoin.protocol.framer.block(this);
};

/**
 * Serialize the block. Include witnesses if present.
 * @returns {Buffer}
 */

Block.prototype.renderWitness = function renderWitness() {
  return bcoin.protocol.framer.witnessBlock(this);
};

/**
 * Get the raw block serialization.
 * Include witnesses if present.
 * @returns {Buffer}
 */

Block.prototype.getRaw = function getRaw() {
  var raw;

  if (this.hasWitness())
    raw = bcoin.protocol.framer.witnessBlock(this);
  else
    raw = bcoin.protocol.framer.block(this);

  this._size = raw.length;
  this._witnessSize = raw._witnessSize;

  return raw;
};

Block.prototype._getSize = function _getSize() {
  var sizes = bcoin.protocol.framer.block.sizes(this);
  this._size = sizes.size;
  this._witnessSize = sizes.witnessSize;
};

/**
 * Calculate virtual block size.
 * @param {Boolean?} force - If true, always recalculate.
 * @returns {Number} Virtual size.
 */

Block.prototype.getVirtualSize = function getVirtualSize(force) {
  var size, witnessSize, base;

  size = this.getSize(force);
  witnessSize = this.getWitnessSize(force);
  base = size - witnessSize;

  return (base * 4 + witnessSize + 3) / 4 | 0;
};

/**
 * Get real block size.
 * @param {Boolean?} force - If true, always recalculate.
 * @returns {Number} size
 */

Block.prototype.getSize = function getSize(force) {
  if (force || this._size === 0)
    this._getSize();
  return this._size;
};

/**
 * Get the total size of the witnesses.
 * @param {Boolean?} force - If true, always recalculate.
 * @returns {Number} witness size
 */

Block.prototype.getWitnessSize = function getWitnessSize(force) {
  if (force || this._size === 0)
    this._getSize();
  return this._witnessSize;
};

/**
 * Test whether the block contains a
 * transaction with a non-empty witness.
 * @returns {Boolean}
 */

Block.prototype.hasWitness = function hasWitness() {
  for (var i = 0; i < this.txs.length; i++) {
    if (this.txs[i].hasWitness())
      return true;
  }
  return false;
};

/**
 * Test the block's transaction vector against a hash.
 * @param {Hash|TX} hash
 * @returns {Boolean}
 */

Block.prototype.hasTX = function hasTX(hash) {
  return this.indexOf(hash) !== -1;
};

/**
 * Find the index of a transaction in the block.
 * @param {Hash|TX} hash
 * @returns {Number} index (-1 if not present).
 */

Block.prototype.indexOf = function indexOf(hash) {
  var i;

  if (hash instanceof bcoin.tx)
    hash = hash.hash('hex');

  for (i = 0; i < this.txs.length; i++) {
    if (this.txs[i].hash('hex') === hash)
      return i;
  }

  return -1;
};

/**
 * Count sigops taking into account the cost vs. witness ops.
 * @param {Boolean?} scriptHash - Whether to count redeem script ops.
 * @param {Boolean?} accurate - Whether to use accurate counting
 * for CHECKMULTISIG(VERIFY).
 * @returns {Number} sigops
 */

Block.prototype.getSigops = function getSigops(scriptHash, accurate) {
  var total = 0;
  var i;

  for (i = 0; i < this.txs.length; i++)
    total += this.txs[i].getSigops(scriptHash, accurate);

  return total;
};

/**
 * Calculate merkle root.
 * @param {String?} enc - Encoding, can be `'hex'` or null.
 * @returns {Buffer|Hash} hash
 */

Block.prototype.getMerkleRoot = function getMerkleRoot(enc) {
  var leaves = [];
  var i, root;

  for (i = 0; i < this.txs.length; i++)
    leaves.push(this.txs[i].hash());

  root = utils.getMerkleRoot(leaves);

  if (!root)
    return;

  return enc === 'hex'
    ? utils.toHex(root)
    : root;
};

/**
 * Calculate commitment hash (the root of the
 * witness merkle tree hashed with the witnessNonce).
 * @param {String?} enc - Encoding, can be `'hex'` or null.
 * @returns {Buffer|Hash} hash
 */

Block.prototype.getCommitmentHash = function getCommitmentHash(enc) {
  var leaves = [];
  var witnessNonce = this.witnessNonce;
  var i, witnessRoot, commitmentHash;

  if (!witnessNonce)
    return;

  for (i = 0; i < this.txs.length; i++)
    leaves.push(this.txs[i].witnessHash());

  witnessRoot = utils.getMerkleRoot(leaves);

  if (!witnessRoot)
    return;

  commitmentHash = utils.dsha256(Buffer.concat([witnessRoot, witnessNonce]));

  return enc === 'hex'
    ? utils.toHex(commitmentHash)
    : commitmentHash;
};

Block.prototype.__defineGetter__('witnessNonce', function() {
  var coinbase = this.txs[0];

  if (!coinbase)
    return;

  if (coinbase.inputs.length !== 1)
    return;

  if (coinbase.inputs[0].witness.items.length !== 1)
    return;

  if (coinbase.inputs[0].witness.items[0].length !== 32)
    return;

  return coinbase.inputs[0].witness.items[0];
});

Block.prototype.__defineGetter__('commitmentHash', function() {
  var coinbase, i, commitment, commitmentHash;

  if (this._commitmentHash)
    return this._commitmentHash;

  coinbase = this.txs[0];

  if (!coinbase)
    return;

  for (i = 0; i < coinbase.outputs.length; i++) {
    commitment = coinbase.outputs[i].script;
    if (commitment.isCommitment()) {
      commitmentHash = commitment.getCommitmentHash();
      break;
    }
  }

  if (commitmentHash)
    this._commitmentHash = utils.toHex(commitmentHash);

  return this._commitmentHash;
});

/**
 * Do non-contextual verification on the block. Including checking the block
 * size, the coinbase and the merkle root. This is consensus-critical.
 * @alias verify
 * @param {Object?} ret - Return object, may be
 * set with properties `reason` and `score`.
 * @returns {Boolean}
 */

Block.prototype._verify = function _verify(ret) {
  var uniq = {};
  var i, tx, hash;

  if (!ret)
    ret = {};

  if (!this.verifyHeaders(ret))
    return false;

  // Size can't be bigger than MAX_BLOCK_SIZE
  if (this.txs.length > constants.block.MAX_SIZE
      || this.getVirtualSize() > constants.block.MAX_SIZE) {
    ret.reason = 'bad-blk-length';
    ret.score = 100;
    return false;
  }

  // First TX must be a coinbase
  if (this.txs.length === 0 || !this.txs[0].isCoinbase()) {
    ret.reason = 'bad-cb-missing';
    ret.score = 100;
    return false;
  }

  // Test all txs
  for (i = 0; i < this.txs.length; i++) {
    tx = this.txs[i];

    // The rest of the txs must not be coinbases
    if (i > 0 && tx.isCoinbase()) {
      ret.reason = 'bad-cb-multiple';
      ret.score = 100;
      return false;
    }

    // Check for duplicate txids
    hash = tx.hash('hex');
    if (uniq[hash]) {
      ret.reason = 'bad-txns-duplicate';
      ret.score = 100;
      return false;
    }
    uniq[hash] = true;
  }

  // Check merkle root
  if (this.merkleRoot !== this.getMerkleRoot('hex')) {
    ret.reason = 'bad-txnmrkleroot';
    ret.score = 100;
    return false;
  }

  return true;
};

/**
 * Retrieve the coinbase height from the coinbase input script.
 * @returns {Number} height (-1 if not present).
 */

Block.prototype.getCoinbaseHeight = function getCoinbaseHeight() {
  var coinbase, height;

  if (this.version < 2)
    return -1;

  if (this._cbHeight != null)
    return this._cbHeight;

  coinbase = this.txs[0];

  if (!coinbase || coinbase.inputs.length === 0)
    return -1;

  height = coinbase.inputs[0].script.getCoinbaseHeight();
  this._cbHeight = height;

  return height;
};

/**
 * Calculate the block reward.
 * @returns {BN} reward
 */

Block.prototype.getReward = function getReward() {
  var reward = Block.reward(this.height);
  var i;

  for (i = 1; i < this.txs.length; i++)
    reward.iadd(this.txs[i].getFee());

  return reward;
};

/**
 * Get the "claimed" reward by the coinbase.
 * @returns {BN} claimed
 */

Block.prototype.getClaimed = function getClaimed() {
  assert(this.txs[0]);
  assert(this.txs[0].isCoinbase());
  return this.txs[0].getOutputValue();
};

/**
 * Calculate block subsidy.
 * @param {Number} height - Reward era by height.
 * @returns {BN}
 */

Block.reward = function reward(height) {
  var halvings = height / network.halvingInterval | 0;
  var reward;

  if (height < 0)
    return new bn(0);

  if (halvings >= 64)
    return new bn(0);

  reward = new bn(5000000000);
  reward.iushrn(halvings);

  return reward;
};

/**
 * Get all unique outpoint hashes in the
 * block. Coinbases are ignored.
 * @returns {Hash[]} Outpoint hashes.
 */

Block.prototype.getPrevout = function getPrevout() {
  var prevout = {};
  var i, j, tx, input;

  for (i = 0; i < this.txs.length; i++) {
    tx = this.txs[i];

    if (tx.isCoinbase())
      continue;

    for (j = 0; j < tx.inputs.length; j++) {
      input = tx.inputs[j];
      prevout[input.prevout.hash] = true;
    }
  }

  return Object.keys(prevout);
};

/**
 * Inspect the block and return a more
 * user-friendly representation of the data.
 * @returns {Object}
 */

Block.prototype.inspect = function inspect() {
  return {
    type: this.type,
    height: this.height,
    hash: utils.revHex(this.hash('hex')),
    size: this.getSize(),
    virtualSize: this.getVirtualSize(),
    date: new Date(this.ts * 1000).toISOString(),
    version: this.version,
    prevBlock: utils.revHex(this.prevBlock),
    merkleRoot: utils.revHex(this.merkleRoot),
    commitmentHash: this.commitmentHash
      ? utils.revHex(this.commitmentHash)
      : null,
    ts: this.ts,
    bits: this.bits,
    nonce: this.nonce,
    totalTX: this.totalTX,
    txs: this.txs
  };
};

/**
 * Convert the block to an object suitable
 * for JSON serialization. Note that the hashes
 * will be reversed to abide by bitcoind's legacy
 * of little-endian uint256s.
 * @returns {Object}
 */

Block.prototype.toJSON = function toJSON() {
  return {
    type: 'block',
    height: this.height,
    hash: utils.revHex(this.hash('hex')),
    version: this.version,
    prevBlock: utils.revHex(this.prevBlock),
    merkleRoot: utils.revHex(this.merkleRoot),
    ts: this.ts,
    bits: this.bits,
    nonce: this.nonce,
    totalTX: this.totalTX,
    txs: this.txs.map(function(tx) {
      return tx.toJSON();
    })
  };
};

/**
 * Handle a deserialized JSON transaction object.
 * @returns {Object} A "naked" block (a
 * plain javascript object which is suitable
 * for passing to the Block constructor).
 */

Block._fromJSON = function _fromJSON(json) {
  assert.equal(json.type, 'block');
  json.prevBlock = utils.revHex(json.prevBlock);
  json.merkleRoot = utils.revHex(json.merkleRoot);
  json.txs = json.txs.map(function(tx) {
    return bcoin.tx._fromJSON(tx);
  });
  return json;
};

/**
 * Instantiate a block from a jsonified block object.
 * @param {Object} json - The jsonified block object.
 * @returns {Block}
 */

Block.fromJSON = function fromJSON(json) {
  return new Block(Block._fromJSON(json));
};

/**
 * Serialize the block.
 * @see {Block#render}
 * @param {String?} enc - Encoding, can be `'hex'` or null.
 * @returns {Buffer|String}
 */

Block.prototype.toRaw = function toRaw(enc) {
  var data = this.render();

  if (enc === 'hex')
    data = utils.toHex(data);

  return data;
};

/**
 * Parse a serialized block.
 * @param {Buffer} data
 * @param {String?} enc - Encoding, can be `'hex'` or null.
 * @param {String?} type - Can be `'block'`, `'merkleblock'`, or `'headers'`.
 * @returns {Object} A "naked" block object.
 */

Block._fromRaw = function _fromRaw(data, enc, type) {
  if (enc === 'hex')
    data = new Buffer(data, 'hex');

  if (type === 'merkleblock')
    return bcoin.merkleblock._fromRaw(data);

  if (type === 'headers')
    return bcoin.headers._fromRaw(data);

  return bcoin.protocol.parser.parseBlock(data);
};

/**
 * Instantiate a block from a serialized Buffer.
 * @param {Buffer} data
 * @param {String?} enc - Encoding, can be `'hex'` or null.
 * @param {String?} type - Can be `'block'`, `'merkleblock'`, or `'headers'`.
 * @returns {Block}
 */

Block.fromRaw = function fromRaw(data, enc, type) {
  if (type === 'merkleblock')
    return bcoin.merkleblock.fromRaw(data);

  if (type === 'headers')
    return bcoin.headers.fromRaw(data);

  return new Block(Block._fromRaw(data, enc));
};

/**
 * Serialize a block to BCoin "compact format".
 * This is the serialization format BCoin uses internally
 * to store blocks in the database. It includes the height,
 * but does not include transaction data, only transaction
 * hashes.
 * @returns {Buffer}
 */

Block.prototype.toCompact = function toCompact() {
  var p = new BufferWriter();
  var height = this.height;

  if (height === -1)
    height = 0x7fffffff;

  p.writeBytes(this.abbr());
  p.writeU32(height);
  p.writeVarint(this.txs.length);

  this.txs.forEach(function(tx) {
    p.writeHash(tx.hash());
  });

  return p.render();
};

/**
 * Parse a transaction in "compact" serialization format.
 * @param {Buffer} buf
 * @returns {NakedBlock} - A "naked" block object with a `hashes` vector.
 */

Block.fromCompact = function fromCompact(buf) {
  var p = new BufferReader(buf);
  var hashes = [];
  var version = p.readU32(); // Technically signed
  var prevBlock = p.readHash('hex');
  var merkleRoot = p.readHash('hex');
  var ts = p.readU32();
  var bits = p.readU32();
  var nonce = p.readU32();
  var height = p.readU32();
  var txCount = p.readVarint();
  var i;

  for (i = 0; i < txCount; i++)
    hashes.push(p.readHash('hex'));

  if (height === 0x7fffffff)
    height = -1;

  return {
    version: version,
    prevBlock: prevBlock,
    merkleRoot: merkleRoot,
    ts: ts,
    bits: bits,
    nonce: nonce,
    height: height,
    totalTX: txCount,
    hashes: hashes
  };
};

/**
 * Convert the Block to a MerkleBlock.
 * @param {Bloom} filter - Bloom filter for transactions
 * to match. The merkle block will contain only the
 * matched transactions.
 * @returns {MerkleBlock}
 */

Block.prototype.toMerkle = function toMerkle(filter) {
  return bcoin.merkleblock.fromBlock(this, filter);
};

/**
 * Test an object to see if it is a Block.
 * @param {Object} obj
 * @returns {Boolean}
 */

Block.isBlock = function isBlock(obj) {
  return obj
    && typeof obj.merkleRoot === 'string'
    && typeof obj.toCompact === 'function';
};

return Block;
};
