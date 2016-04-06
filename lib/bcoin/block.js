/**
 * block.js - block object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

var bcoin = require('../bcoin');
var bn = require('bn.js');
var utils = require('./utils');
var assert = utils.assert;
var constants = bcoin.protocol.constants;
var network = bcoin.protocol.network;
var BufferWriter = require('./writer');
var BufferReader = require('./reader');

/**
 * Block
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

Block.prototype.render = function render() {
  return this.getRaw();
};

Block.prototype.renderNormal = function renderNormal() {
  return bcoin.protocol.framer.block(this);
};

Block.prototype.renderWitness = function renderWitness() {
  return bcoin.protocol.framer.witnessBlock(this);
};

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

Block.prototype.getVirtualSize = function getVirtualSize() {
  var size, witnessSize, base;

  size = this.getSize();
  witnessSize = this.getWitnessSize();
  base = size - witnessSize;

  return (base * 4 + witnessSize + 3) / 4 | 0;
};

Block.prototype.getSize = function getSize() {
  if (this._size == null)
    this.getRaw();
  return this._size;
};

Block.prototype.getWitnessSize = function getWitnessSize() {
  if (this._witnessSize == null)
    this.getRaw();
  return this._witnessSize;
};

Block.prototype.hasWitness = function hasWitness() {
  for (var i = 0; i < this.txs.length; i++) {
    if (this.txs[i].hasWitness())
      return true;
  }
  return false;
};

Block.prototype.hasTX = function hasTX(hash) {
  return this.indexOf(hash) !== -1;
};

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

Block.prototype.getSigops = function getSigops(scriptHash, accurate) {
  var total = 0;
  var i;

  for (i = 0; i < this.txs.length; i++)
    total += this.txs[i].getSigops(scriptHash, accurate);

  return total;
};

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

Block.prototype.getCommitmentHash = function getCommitmentHash(enc) {
  var leaves = [];
  var i, witnessNonce, witnessRoot, commitmentHash;

  witnessNonce = this.txs[0].inputs[0].witness.items[0];

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

Block.prototype.__defineGetter__('commitmentHash', function() {
  var coinbase, i, commitment, commitmentHash;

  if (this._commitmentHash)
    return this._commitmentHash;

  coinbase = this.txs[0];

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

Block.prototype._verify = function _verify(ret) {
  var uniq = {};
  var i, tx, hash;

  if (!ret)
    ret = {};

  if (!this.verifyHeaders(ret))
    return false;

  // Size can't be bigger than MAX_BLOCK_SIZE
  if (this.txs.length > constants.block.maxSize
      || this.getVirtualSize() > constants.block.maxSize) {
    ret.reason = 'bad-blk-length';
    ret.score = 100;
    return false;
  }

  // First TX must be a coinbase
  if (!this.txs.length || !this.txs[0].isCoinbase()) {
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

Block.prototype.getCoinbaseHeight = function getCoinbaseHeight() {
  var coinbase, code, height;

  if (this.version < 2)
    return -1;

  if (this._cbHeight != null)
    return this._cbHeight;

  coinbase = this.txs[0];

  if (!coinbase || coinbase.inputs.length === 0)
    return -1;

  code = coinbase.inputs[0].script.code;

  if (Buffer.isBuffer(code[0]) && code[0].length <= 6)
    height = new bn(code[0], 'le').toNumber();
  else
    height = -1;

  this._cbHeight = height;

  return height;
};

Block.prototype.getReward = function getReward() {
  var reward = Block.reward(this.height);
  var i;

  for (i = 1; i < this.txs.length; i++)
    reward.iadd(this.txs[i].getFee());

  return reward;
};

Block.prototype.getClaimed = function getClaimed() {
  assert(this.txs[0]);
  assert(this.txs[0].isCoinbase());
  return this.txs[0].getOutputValue();
};

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

Block._fromJSON = function _fromJSON(json) {
  assert.equal(json.type, 'block');
  json.prevBlock = utils.revHex(json.prevBlock);
  json.merkleRoot = utils.revHex(json.merkleRoot);
  json.txs = json.txs.map(function(tx) {
    return bcoin.tx._fromJSON(tx);
  });
  return json;
};

Block.fromJSON = function fromJSON(json) {
  return new Block(Block._fromJSON(json));
};

Block.prototype.toRaw = function toRaw(enc) {
  var data = this.render();

  if (enc === 'hex')
    data = utils.toHex(data);

  return data;
};

Block._fromRaw = function _fromRaw(data, enc, type) {
  if (enc === 'hex')
    data = new Buffer(data, 'hex');

  if (type === 'merkleblock')
    return bcoin.merkleblock._fromRaw(data);

  if (type === 'headers')
    return bcoin.headers._fromRaw(data);

  return bcoin.protocol.parser.parseBlock(data);
};

Block.fromRaw = function fromRaw(data, enc, type) {
  if (type === 'merkleblock')
    return bcoin.merkleblock.fromRaw(data);

  if (type === 'headers')
    return bcoin.headers.fromRaw(data);

  return new Block(Block._fromRaw(data, enc));
};

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

Block.prototype.toMerkle = function toMerkle(filter) {
  return bcoin.merkleblock.fromBlock(this, filter);
};

Block.isBlock = function isBlock(obj) {
  return obj
    && typeof obj.merkleRoot === 'string'
    && typeof obj.toCompact === 'function';
};

/**
 * Expose
 */

module.exports = Block;
