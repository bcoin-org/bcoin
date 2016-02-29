/**
 * block.js - block object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

var bcoin = require('../bcoin');
var bn = require('bn.js');
var utils = bcoin.utils;
var assert = utils.assert;
var constants = bcoin.protocol.constants;
var network = bcoin.protocol.network;

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
  this.getRaw();

  if (!this._witnessSize)
    return this._raw;

  return bcoin.protocol.framer.block(this);
};

Block.prototype.renderWitness = function renderWitness() {
  this.getRaw();

  if (this._witnessSize)
    return this._raw;

  return bcoin.protocol.framer.witnessBlock(this);
};

Block.prototype.getRaw = function getRaw() {
  if (this._raw) {
    assert(this._size > 0);
    assert(this._witnessSize >= 0);
    return this._raw;
  }

  if (this.hasWitness())
    raw = bcoin.protocol.framer.witnessBlock(this);
  else
    raw = bcoin.protocol.framer.block(this);

  this._raw = raw;
  this._size = raw.length;
  this._witnessSize = raw._witnessSize;

  return this._raw;
};

Block.prototype.getVirtualSize = function getVirtualSize() {
  var size, witnessSize, base;

  this.getRaw();

  size = this._size;
  witnessSize = this._witnessSize;
  base = size - witnessSize;

  return (base * 4 + witnessSize + 3) / 4 | 0;
};

Block.prototype.getSize = function getSize() {
  return this.getRaw().length;
};

Block.prototype.hasWitness = function hasWitness() {
  for (var i = 0; i < this.txs.length; i++) {
    if (this.txs[i].hasWitness())
      return true;
  }
  return false;
};

Block.prototype.getSigops = function getSigops(scriptHash, accurate) {
  var total = 0;
  var i;

  for (i = 0; i < this.txs.length; i++)
    total += this.txs[i].getSigops(scriptHash, accurate);

  return total;
};

Block.prototype.getMerkleRoot = function getMerkleRoot() {
  var leaves = [];
  var i, root;

  for (i = 0; i < this.txs.length; i++)
    leaves.push(this.txs[i].hash());

  root = utils.getMerkleRoot(leaves);

  if (!root)
    return;

  return utils.toHex(root);
};

Block.prototype.getCommitmentHash = function getCommitmentHash() {
  var leaves = [];
  var i, witnessNonce, witnessRoot, commitmentHash;

  witnessNonce = this.txs[0].inputs[0].witness[0];

  if (!witnessNonce)
    return;

  for (i = 0; i < this.txs.length; i++)
    leaves.push(this.txs[i].witnessHash());

  witnessRoot = utils.getMerkleRoot(leaves);

  if (!witnessRoot)
    return;

  commitmentHash = utils.dsha256(Buffer.concat([witnessRoot, witnessNonce]));

  return utils.toHex(commitmentHash);
};

Block.prototype.__defineGetter__('commitmentHash', function() {
  var coinbase, i, commitment, commitmentHash;

  if (this._commitmentHash)
    return this._commitmentHash;

  coinbase = this.txs[0];

  for (i = 0; i < coinbase.outputs.length; i++) {
    commitment = coinbase.outputs[i].script;
    if (bcoin.script.isCommitment(commitment)) {
      commitmentHash = bcoin.script.getCommitmentHash(commitment);
      break;
    }
  }

  if (commitmentHash)
    this._commitmentHash = utils.toHex(commitmentHash);

  return this._commitmentHash;
});

Block.prototype._verify = function _verify() {
  var uniq = {};
  var i, tx, hash;

  if (!this.verifyHeaders())
    return false;

  // Size can't be bigger than MAX_BLOCK_SIZE
  if (this.txs.length > constants.block.maxSize
      || this.getVirtualSize() > constants.block.maxSize) {
    utils.debug('Block is too large: %s', this.rhash);
    return false;
  }

  // First TX must be a coinbase
  if (!this.txs.length || !this.txs[0].isCoinbase()) {
    utils.debug('Block has no coinbase: %s', this.rhash);
    return false;
  }

  // Test all txs
  for (i = 0; i < this.txs.length; i++) {
    tx = this.txs[i];

    // The rest of the txs must not be coinbases
    if (i > 0 && tx.isCoinbase()) {
      utils.debug('Block more than one coinbase: %s', this.rhash);
      return false;
    }

    // Check for duplicate txids
    hash = tx.hash('hex');
    if (uniq[hash]) {
      utils.debug('Block has duplicate txids: %s', this.rhash);
      return false;
    }
    uniq[hash] = true;
  }

  // Check merkle root
  if (this.getMerkleRoot() !== this.merkleRoot) {
    utils.debug('Block failed merkleroot test: %s', this.rhash);
    return false;
  }

  return true;
};

Block.prototype.getCoinbaseHeight = function getCoinbaseHeight() {
  var coinbase, s, height;

  if (this.version < 2)
    return -1;

  if (this._cbHeight != null)
    return this._cbHeight;

  coinbase = this.txs[0];

  if (!coinbase || coinbase.inputs.length === 0)
    return -1;

  s = coinbase.inputs[0].script;

  if (Buffer.isBuffer(s[0]))
    height = bcoin.script.num(s[0], true);
  else
    height = -1;

  this._cbHeight = height;

  return height;
};

Block.reward = function reward(height) {
  var halvings = height / network.halvingInterval | 0;
  var reward;

  if (height < 0)
    return new bn(0);

  if (halvings >= 64)
    return new bn(0);

  reward = new bn(50).mul(constants.coin);
  reward.iushrn(halvings);

  return reward;
};

Block.prototype._getReward = function _getReward() {
  var reward, base, fee, height;

  if (this._reward)
    return this._reward;

  base = Block.reward(this.height);

  if (this.height === -1) {
    return this._reward = {
      fee: new bn(0),
      reward: base,
      base: base
    };
  }

  reward = this.txs[0].outputs.reduce(function(total, output) {
    total.iadd(output.value);
    return total;
  }, new bn(0));

  fee = reward.sub(base);

  return this._reward = {
    fee: fee,
    reward: reward,
    base: base
  };
};

Block.prototype.getBaseReward = function getBaseReward() {
  return this._getReward().base;
};

Block.prototype.getReward = function getReward() {
  return this._getReward().reward;
};

Block.prototype.getFee = function getFee() {
  return this._getReward().fee;
};

Block.prototype.getCoinbase = function getCoinbase() {
  var tx;

  tx = this.txs[0];
  if (!tx || !tx.isCoinbase())
    return;

  return tx;
};

Block.prototype.inspect = function inspect() {
  return {
    type: this.type,
    height: this.height,
    hash: utils.revHex(this.hash('hex')),
    reward: utils.btc(this.getReward()),
    fee: utils.btc(this.getFee()),
    date: new Date(this.ts * 1000).toISOString(),
    version: this.version,
    prevBlock: utils.revHex(this.prevBlock),
    merkleRoot: utils.revHex(this.merkleRoot),
    commitmentHash: this.commitmentHash ? utils.revHex(this.commitmentHash) : null,
    ts: this.ts,
    bits: this.bits,
    nonce: this.nonce,
    totalTX: this.totalTX,
    txs: this.txs
  };
};

Block.prototype.toJSON = function toJSON() {
  return {
    type: this.type,
    height: this.height,
    hash: utils.revHex(this.hash('hex')),
    version: this.version,
    prevBlock: utils.revHex(this.prevBlock),
    merkleRoot: utils.revHex(this.merkleRoot),
    commitmentHash: this.commitmentHash ? utils.revHex(this.commitmentHash) : null,
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

Block.prototype.toCompact = function toCompact() {
  return {
    type: this.type,
    hash: this.hash('hex'),
    prevBlock: this.prevBlock,
    ts: this.ts,
    height: this.height,
    block: utils.toHex(this.render())
  };
};

Block._fromCompact = function _fromCompact(json) {
  var raw, data;

  assert.equal(json.type, 'block');

  raw = new Buffer(json.block, 'hex');

  data = bcoin.protocol.parser.parseBlock(raw);

  data.height = json.height;

  return data;
};

Block.fromCompact = function fromCompact(json) {
  return new Block(Block._fromCompact(json));
};

Block.prototype.toRaw = function toRaw(enc) {
  var data;

  data = this.render();

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

/**
 * Expose
 */

module.exports = Block;
