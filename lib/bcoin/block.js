/*!
 * block.js - block object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/indutny/bcoin
 */

var bcoin = require('./env');
var utils = require('./utils');
var assert = utils.assert;
var constants = bcoin.protocol.constants;

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
  var i;

  if (!(this instanceof Block))
    return new Block(data);

  bcoin.abstractblock.call(this, data);

  this.txs = [];

  this._cbHeight = null;
  this._commitmentHash = null;

  this._raw = data._raw || null;
  this._size = data._size || null;
  this._witnessSize = data._witnessSize != null ? data._witnessSize : null;

  if (data.txs) {
    for (i = 0; i < data.txs.length; i++)
      this.addTX(data.txs[i]);
  }
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
  if (!this.hasWitness())
    return this.getRaw();
  return bcoin.protocol.framer.block(this);
};

/**
 * Serialize the block. Include witnesses if present.
 * @returns {Buffer}
 */

Block.prototype.renderWitness = function renderWitness() {
  if (this.hasWitness())
    return this.getRaw();
  return bcoin.protocol.framer.witnessBlock(this);
};

/**
 * Get the raw block serialization.
 * Include witnesses if present.
 * @returns {Buffer}
 */

Block.prototype.getRaw = function getRaw() {
  var raw;

  if (this._raw) {
    assert(this._size > 0);
    assert(this._witnessSize >= 0);
    return this._raw;
  }

  if (this.hasWitness())
    raw = bcoin.protocol.framer.witnessBlock(this);
  else
    raw = bcoin.protocol.framer.block(this);

  if (!this.mutable) {
    this._size = raw.length;
    this._witnessSize = raw._witnessSize;
    this._raw = raw;
  }

  return raw;
};

/**
 * Calculate real size and size of the witness bytes.
 * @returns {Object} Contains `size` and `witnessSize`.
 */

Block.prototype.getSizes = function getSizes() {
  if (this._size != null) {
    return {
      size: this._size,
      witnessSize: this._witnessSize
    };
  }

  if (!this.mutable) {
    this.getRaw();
    return {
      size: this._size,
      witnessSize: this._witnessSize
    };
  }

  return bcoin.protocol.framer.block.sizes(this);
};

/**
 * Calculate virtual block size.
 * @returns {Number} Virtual size.
 */

Block.prototype.getVirtualSize = function getVirtualSize() {
  var scale = constants.WITNESS_SCALE_FACTOR;
  return (this.getCost() + scale - 1) / scale | 0;
};

/**
 * Calculate block cost.
 * @returns {Number} cost
 */

Block.prototype.getCost = function getCost() {
  var sizes = this.getSizes();
  var base = sizes.size - sizes.witnessSize;
  return base * (constants.WITNESS_SCALE_FACTOR - 1) + sizes.size;
};

/**
 * Get real block size.
 * @returns {Number} size
 */

Block.prototype.getSize = function getSize() {
  return this.getSizes().size;
};

/**
 * Get base block size (without witness).
 * @returns {Number} size
 */

Block.prototype.getBaseSize = function getBaseSize() {
  var sizes = this.getSizes();
  return sizes.size - sizes.witnessSize;
};

/**
 * Test whether the block contains a
 * transaction with a non-empty witness.
 * @returns {Boolean}
 */

Block.prototype.hasWitness = function hasWitness() {
  var i;

  if (this._witnessSize > 0)
    return true;

  for (i = 0; i < this.txs.length; i++) {
    if (this.txs[i].hasWitness())
      return true;
  }

  return false;
};

/**
 * Add a transaction to the block's tx vector.
 * @param {TX|NakedTX} tx
 * @returns {TX}
 */

Block.prototype.addTX = function addTX(tx) {
  var index;

  if (!(tx instanceof bcoin.tx))
    tx = new bcoin.tx(tx);

  index = this.txs.push(tx) - 1;

  tx.setBlock(this, index);

  return tx;
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
    ? root.toString('hex')
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
    ? commitmentHash.toString('hex')
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
      commitmentHash = commitmentHash.toString('hex');
      break;
    }
  }

  if (!this.mutable)
    this._commitmentHash = commitmentHash;

  return commitmentHash;
});

/**
 * Do non-contextual verification on the block. Including checking the block
 * size, the coinbase and the merkle root. This is consensus-critical.
 * @alias Block#verify
 * @param {Object?} ret - Return object, may be
 * set with properties `reason` and `score`.
 * @returns {Boolean}
 */

Block.prototype._verify = function _verify(ret) {
  var sigops = 0;
  var scale = constants.WITNESS_SCALE_FACTOR;
  var i, tx, merkle;

  if (!ret)
    ret = {};

  if (!this.verifyHeaders(ret))
    return false;

  // Size can't be bigger than MAX_BLOCK_SIZE
  if (this.txs.length > constants.block.MAX_SIZE
      || this.getBaseSize() > constants.block.MAX_SIZE) {
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

    // Sanity checks
    if (!tx.isSane(ret))
      return false;

    // Count legacy sigops (do not count scripthash or witness)
    sigops += tx.getLegacySigops();
    if (sigops * scale > constants.block.MAX_SIGOPS_COST) {
      ret.reason = 'bad-blk-sigops';
      ret.score = 100;
      return false;
    }
  }

  // Check merkle root
  merkle = this.getMerkleRoot('hex');

  // If the merkle is mutated,
  // we have duplicate txs.
  if (!merkle) {
    ret.reason = 'bad-txns-duplicate';
    ret.score = 100;
    return false;
  }

  if (this.merkleRoot !== merkle) {
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

  if (!this.mutable)
    this._cbHeight = height;

  return height;
};

/**
 * Calculate the block reward.
 * @returns {Amount} reward
 */

Block.prototype.getReward = function getReward(network) {
  var reward = Block.reward(this.height, network);
  var i, fee;

  for (i = 1; i < this.txs.length; i++) {
    fee = this.txs[i].getFee();

    if (fee < 0 || fee > constants.MAX_MONEY)
      return -1;

    reward += fee;

    // We don't want to go above 53 bits.
    // This is to make the getClaimed check
    // fail if the miner mined an evil block.
    // Note that this check ONLY works because
    // MAX_MONEY is 51 bits. The result of
    // (51 bits + 51 bits) is _never_ greater
    // than 52 bits.
    if (reward < 0 || reward > constants.MAX_MONEY)
      return -1;
  }

  return reward;
};

/**
 * Get the "claimed" reward by the coinbase.
 * @returns {Amount} claimed
 */

Block.prototype.getClaimed = function getClaimed() {
  assert(this.txs[0]);
  assert(this.txs[0].isCoinbase());
  return this.txs[0].getOutputValue();
};

/**
 * Calculate block subsidy.
 * @param {Number} height - Reward era by height.
 * @returns {Amount}
 */

Block.reward = function reward(height, network) {
  var halvings;

  assert(height >= 0, 'Bad height for reward.');

  network = bcoin.network.get(network);
  halvings = height / network.halvingInterval | 0;

  // BIP 42 (well, our own version of it,
  // since we can only handle 32 bit shifts).
  // https://github.com/bitcoin/bips/blob/master/bip-0042.mediawiki
  if (halvings >= 33)
    return 0;

  // We need to shift right by `halvings`,
  // but 50 btc is a 33 bit number, so we
  // cheat. We only start halving once the
  // halvings are at least 1.
  if (halvings === 0)
    return 5000000000;

  return 2500000000 >>> (halvings - 1);
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
    type: 'block',
    hash: this.rhash,
    height: this.height,
    size: this.getSize(),
    virtualSize: this.getVirtualSize(),
    date: utils.date(this.ts),
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
    hash: utils.revHex(this.hash('hex')),
    height: this.height,
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

Block.parseJSON = function parseJSON(json) {
  assert.equal(json.type, 'block');
  json.prevBlock = utils.revHex(json.prevBlock);
  json.merkleRoot = utils.revHex(json.merkleRoot);
  json.txs = json.txs.map(function(tx) {
    return bcoin.tx.parseJSON(tx);
  });
  return json;
};

/**
 * Instantiate a block from a jsonified block object.
 * @param {Object} json - The jsonified block object.
 * @returns {Block}
 */

Block.fromJSON = function fromJSON(json) {
  return new Block(Block.parseJSON(json));
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
    data = data.toString('hex');

  return data;
};

/**
 * Parse a serialized block.
 * @param {Buffer} data
 * @param {String?} enc - Encoding, can be `'hex'` or null.
 * @returns {Object} A "naked" block object.
 */

Block.parseRaw = function parseRaw(data, enc) {
  if (enc === 'hex')
    data = new Buffer(data, 'hex');

  return bcoin.protocol.parser.parseBlock(data);
};

/**
 * Instantiate a block from a serialized Buffer.
 * @param {Buffer} data
 * @param {String?} enc - Encoding, can be `'hex'` or null.
 * @returns {Block}
 */

Block.fromRaw = function fromRaw(data, enc) {
  return new Block(Block.parseRaw(data, enc));
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
 * Test whether an object is a Block.
 * @param {Object} obj
 * @returns {Boolean}
 */

Block.isBlock = function isBlock(obj) {
  return obj
    && typeof obj.merkleRoot === 'string'
    && typeof obj.getCommitmentHash === 'function';
};

/*
 * Expose
 */

module.exports = Block;
