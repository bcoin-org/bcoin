/**
 * block.js - block object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

var bcoin = require('../bcoin');
var bn = require('bn.js');
var utils = bcoin.utils;
var constants = bcoin.protocol.constants;
var network = bcoin.protocol.network;

/**
 * Block
 */

function Block(data, subtype) {
  var self = this;
  var tx, height;

  if (!(this instanceof Block))
    return new Block(data, subtype);

  this.type = 'block';
  this.subtype = subtype;
  this.version = data.version;
  this.prevBlock = utils.toHex(data.prevBlock);
  this.merkleRoot = utils.toHex(data.merkleRoot);
  this.ts = data.ts;
  this.bits = data.bits;
  this.nonce = data.nonce;
  this.totalTX = data.totalTX;
  this.hashes = (data.hashes || []).map(function(hash) {
    return utils.toHex(hash);
  });
  this.flags = data.flags || [];
  this.txs = data.txs || [];

  this._raw = data._raw || null;
  this._size = data._size || 0;

  this.network = data.network || false;
  this.relayedBy = data.relayedBy || '0.0.0.0';
  this._height = data._height != null ? data._height : -1;
  this._nextBlock = data._nextBlock || null;

  // List of matched TXs
  this.tx = [];
  this.invalid = false;

  if (this.subtype === 'merkleblock') {
    // Verify partial merkle tree and fill `ts` array
    this.invalid = !this._verifyMerkle();
  } else if (this.subtype === 'block') {
    this.txs = this.txs.map(function(tx) {
      tx.network = self.network;
      tx.relayedBy = self.relayedBy;
      tx = bcoin.tx(tx);
      tx.block = self.hash('hex');
      tx.ts = tx.ts || self.ts;
      return tx;
    });

    if (this.version >= 2 && this._height === -1) {
      tx = this.txs[0];
      if (tx && tx.inputs[0] && +tx.inputs[0].out.hash === 0) {
        height = bcoin.script.coinbaseHeight(tx.inputs[0].script, this);
        if (height > 0)
          this._height = height;
      }
    }

    this.invalid = !this._checkBlock();
  }

  this._hash = null;
}

Block.prototype.hash = function hash(enc) {
  // Hash it
  if (!this._hash)
    this._hash = utils.toHex(utils.dsha256(this.abbr()));
  return enc === 'hex' ? this._hash : utils.toArray(this._hash, 'hex');
};

Block.prototype.abbr = function abbr() {
  if (this.network && this._raw)
    return this._raw.slice();

  var res = new Array(80);
  utils.writeU32(res, this.version, 0);
  utils.copy(utils.toArray(this.prevBlock, 'hex'), res, 4);
  utils.copy(utils.toArray(this.merkleRoot, 'hex'), res, 36);
  utils.writeU32(res, this.ts, 68);
  utils.writeU32(res, this.bits, 72);
  utils.writeU32(res, this.nonce, 76);

  return res;
};

Block.prototype.verify = function verify() {
  return !this.invalid && utils.testTarget(this.bits, this.hash());
};

Block.prototype.render = function render() {
  return bcoin.protocol.framer.block(this, this.subtype);
};

Block.prototype.size = function size() {
  return this._size || this.render().length;
};

Block.prototype.hasTX = function hasTX(hash) {
  return this.tx.indexOf(hash) !== -1;
};

Block.prototype._verifyMerkle = function verifyMerkle() {
  var height = 0;
  var tx = [];
  var i = 0;
  var j = 0;
  var hashes = this.hashes;
  var flags = this.flags;
  var i, root;

  if (this.subtype === 'block')
    return;

  // Count leaves
  for (i = this.totalTX; i > 0; i >>= 1)
    height++;

  if (this.totalTX > (1 << (height - 1)))
    height++;

  function visit(depth) {
    var flag, left, right;

    if (i === flags.length * 8 || j === hashes.length)
      return null;

    flag = (flags[i >> 3] >>> (i & 7)) & 1;
    i++;

    if (flag === 0 || depth === height) {
      if (depth === height)
        tx.push(hashes[j]);
      return hashes[j++];
    }

    // Go deeper
    left = visit(depth + 1);
    if (!left)
      return null;

    right = visit(depth + 1);
    if (right === left)
      return null;

    if (!right)
      right = left;

    return utils.toHex(utils.dsha256(left + right, 'hex'));
  }

  root = visit(1);

  if (!root || root !== this.merkleRoot)
    return false;

  this.tx = tx;

  return true;
};

Block.prototype.getMerkleRoot = function getMerkleRoot() {
  var merkleTree = [];
  var i, j, size, i2, hash;

  for (i = 0; i < this.txs.length; i++) {
    merkleTree.push(this.txs[i].hash('hex'));
  }

  j = 0;
  size = this.txs.length;

  for (; size > 1; size = ((size + 1) / 2) | 0) {
    for (i = 0; i < size; i += 2) {
      i2 = Math.min(i + 1, size - 1);
      if (i2 === i + 1 && i2 + 1 === size
          && merkleTree[j + i] === merkleTree[j + i2]) {
        return utils.toHex(constants.zeroHash);
      }
      hash = utils.dsha256(merkleTree[j + i] + merkleTree[j + i2], 'hex');
      merkleTree.push(utils.toHex(hash));
    }
    j += size;
  }

  if (!merkleTree.length)
    return utils.toHex(constants.zeroHash);

  return merkleTree[merkleTree.length - 1];
};

// This mimics the behavior of CheckBlockHeader()
// and CheckBlock() in bitcoin/src/main.cpp.
Block.prototype._checkBlock = function checkBlock() {
  var i, unique, hash, merkleRoot;

  // Check proof of work matches claimed amount
  if (!utils.testTarget(this.bits, this.hash()))
    return false;

  // Check timestamp
  if (this.ts > (Date.now() / 1000) + 2 * 60 * 60)
    return false;

  // Size can't be bigger than MAX_BLOCK_SIZE
  if (this.txs.length > constants.block.maxSize
      || this.size() > constants.block.maxSize) {
    return false;
  }

  // First TX must be a coinbase
  if (!this.txs.length
      || this.txs[0].inputs.length !== 1
      || +this.txs[0].inputs[0].out.hash !== 0)
    return false;

  // The rest of the txs must not be coinbases
  for (i = 1; i < this.txs.length; i++) {
    if (this.txs[i].inputs.length === 1
        && +this.txs[i].inputs[0].out.hash === 0)
      return false;
  }

  // Check for duplicate tx ids
  unique = {};
  for (i = 0; i < this.txs.length; i++) {
    hash = this.txs[i].hash('hex');
    if (unique[hash])
      return false;
    unique[hash] = true;
  }

  // Build MerkleTree
  merkleRoot = this.getMerkleRoot();

  // Check merkle root
  if (merkleRoot !== this.merkleRoot)
    return false;

  return true;
};

Block.prototype.getHeight = function getHeight(chain) {
  if (this._height >= 0)
    return this._height;

  chain = chain || bcoin.chain.global;

  if (!chain)
    return -1;

  return this._height = chain.getHeight(this.hash('hex'));
};

Block.prototype.getNextBlock = function getNextBlock(chain) {
  var next;

  if (this._nextBlock)
    return this._nextBlock;

  chain = chain || bcoin.chain.global;

  if (!chain)
    return utils.toHex(constants.protocol.zeroHash);

  next = chain.getNextBlock(this.hash('hex'));

  if (!next)
    return utils.toHex(constants.zeroHash);

  return this._nextBlock = next;
};

Block.reward = function reward(height) {
  var halvings = height / network.halvingInterval | 0;
  var reward;

  if (height < 0)
    return new bn(0);

  if (halvings >= 64)
    return new bn(0);

  reward = utils.satoshi('50.0');
  reward.iushrn(halvings);

  return reward;
};

Block.prototype.getReward = function getReward() {
  var reward, base, fee, height;

  if (this._reward)
    return this._reward;

  base = Block.reward(this.height);

  if (this.txs.length === 0 || !this.txs[0].isCoinbase()) {
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

  // If height is not accurate, artificially increase
  // the reward era until base is smaller than the reward.
  height = 0;
  while (base.cmp(reward) > 0) {
    base = Block.reward(height);
    height += constants.halvingInterval;
  }

  fee = reward.sub(base);

  return this._reward = {
    fee: fee,
    reward: reward,
    base: base
  };
};

Block.prototype.__defineGetter__('rhash', function() {
  return utils.revHex(this.hash('hex'));
});

Block.prototype.__defineSetter__('height', function(height) {
  return this._height = height;
});

Block.prototype.__defineGetter__('height', function() {
  return this.getHeight(bcoin.chain.global);
});

Block.prototype.__defineGetter__('nextBlock', function() {
  return this.getNextBlock(bcoin.chain.global);
});

Block.prototype.__defineGetter__('reward', function() {
  return this.getReward().reward;
});

Block.prototype.__defineGetter__('fee', function() {
  return this.getReward().fee;
});

Block.prototype.inspect = function inspect() {
  var copy = bcoin.block(this, this.subtype);
  copy.__proto__ = null;
  delete copy._raw;
  copy.hash = this.hash('hex');
  copy.rhash = this.rhash;
  copy.height = this.height;
  copy.nextBlock = this.nextBlock;
  copy.reward = utils.btc(this.reward);
  copy.fee = utils.btc(this.fee);
  copy.date = new Date((copy.ts || 0) * 1000).toISOString();
  return copy;
};

Block.prototype.toJSON = function toJSON() {
  return {
    v: '1',
    type: 'block',
    subtype: this.subtype,
    hash: this.hash('hex'),
    prevBlock: this.prevBlock,
    ts: this.ts,
    network: this.network,
    relayedBy: this.relayedBy,
    _height: this._height,
    block: utils.toHex(bcoin.protocol.framer.block(this, this.subtype))
  };
};

Block.fromJSON = function fromJSON(json) {
  var raw, parser, data, block;

  utils.assert.equal(json.v, 1);
  utils.assert.equal(json.type, 'block');

  raw = utils.toArray(json.block, 'hex');

  parser = new bcoin.protocol.parser();

  data = json.subtype === 'merkleblock'
    ? parser.parseMerkleBlock(raw)
    : parser.parseBlock(raw);

  data.network = json.network;
  data.relayedBy = json.relayedBy;
  data._height = json._height;

  block = new Block(data, json.subtype);

  block._hash = json.hash;

  return block;
};

/**
 * Expose
 */

module.exports = Block;
