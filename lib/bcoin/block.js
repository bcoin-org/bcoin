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
  this.height = data.height != null ? data.height : -1;
  this.hashes = (data.hashes || []).map(function(hash) {
    return utils.toHex(hash);
  });
  this.flags = data.flags || [];
  this.txs = data.txs || [];

  this._raw = data._raw || null;
  this._size = data._size || 0;

  this.network = data.network || false;
  this.relayedBy = data.relayedBy || '0.0.0.0';

  this._chain = data.chain;

  this.valid = null;
  this._hash = null;
  this._cbHeight = null;

  // https://gist.github.com/sipa/bf69659f43e763540550
  // http://lists.linuxfoundation.org/pipermail/bitcoin-dev/2015-August/010396.html
  this.versionBits = (this.version >>> 29) & 7;
  this.realVersion = this.version & 0x1fffffff;
  this.highVersion = this.version & 0x1ffffff8;
  this.lowVersion = this.version & 7;

  // List of matched TXs
  this.tx = [];

  if (!this.subtype) {
    if (this.hashes.length)
      this.subtype = 'merkleblock';
    else if (this.txs.length)
      this.subtype = 'block';
    else
      this.subtype = 'header';
  }

  if (this.subtype === 'block') {
    this.txs = this.txs.map(function(data) {
      // assert(!(data instanceof bcoin.tx));
      if (data instanceof bcoin.tx) {
        // assert(data.ts === self.ts);
        return data;
      }
      return bcoin.tx(data, self);
    });
  }

  this.verify();

  if (this.subtype === 'block' && !this.valid) {
    this.txs = this.txs.map(function(tx) {
      tx.block = null;
      if (tx.ts === self.ts)
        tx.ts = 0;
      tx.height = -1;
      return tx;
    });
  }
}

Block.prototype.hash = function hash(enc) {
  // Hash it
  if (!this._hash)
    this._hash = utils.dsha256(this.abbr());
  return enc === 'hex' ? this._hash.toString('hex') : this._hash;
};

Block.prototype.abbr = function abbr() {
  if (this.network && this._raw)
    return this._raw.slice(0, 80);

  var res = new Buffer(80);
  utils.write32(res, this.version, 0);
  utils.copy(new Buffer(this.prevBlock, 'hex'), res, 4);
  utils.copy(new Buffer(this.merkleRoot, 'hex'), res, 36);
  utils.writeU32(res, this.ts, 68);
  utils.writeU32(res, this.bits, 72);
  utils.writeU32(res, this.nonce, 76);

  return res;
};

Block.prototype.verify = function verify() {
  if (this.valid == null)
    this.valid = this._verify();
  return this.valid;
};

Block.verify = function verify(data, subtype) {
  var block = new Block(data, subtype);
  return block.verify();
};

Block.prototype.render = function render() {
  if (this.network && this._raw && this._raw.length > 80)
    return this._raw;
  return bcoin.protocol.framer.block(this, this.subtype);
};

Block.prototype.getSize = function getSize() {
  return this._size || this.render().length;
};

// Legacy
Block.prototype.size = Block.prototype.getSize;

Block.prototype.hasTX = function hasTX(hash) {
  assert(this.subtype === 'merkleblock');
  return this.tx.indexOf(hash) !== -1;
};

Block.prototype._verifyPartial = function _verifyPartial() {
  var height = 0;
  var tx = [];
  var i = 0;
  var j = 0;
  var hashes = this.hashes;
  var flags = this.flags;
  var i, root;

  if (this.subtype !== 'merkleblock')
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

  assert(this.subtype === 'block');

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

Block.prototype._verify = function _verify() {
  var uniq = {};
  var i, tx, hash;

  // Check proof of work
  if (!utils.testTarget(this.bits, this.hash())) {
    utils.debug('Block failed POW test: %s', this.rhash);
    return false;
  }

  // Check timestamp against now + 2 hours
  if (this.ts > utils.now() + 2 * 60 * 60) {
    utils.debug('Block timestamp is too high: %s', this.rhash);
    return false;
  }

  // Verify the partial merkle tree if we are a merkleblock.
  if (this.subtype === 'merkleblock') {
    if (!this._verifyPartial()) {
      utils.debug('Block failed merkle test: %s', this.rhash);
      return false;
    }
  }

  // Merkleblock and headers cannot do anymore tests.
  if (this.subtype !== 'block')
    return true;

  // Size can't be bigger than MAX_BLOCK_SIZE
  if (this.txs.length > constants.block.maxSize
      || this.getSize() > constants.block.maxSize) {
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

Block.prototype.isGenesis = function isGenesis() {
  return this.hash('hex') === network.genesis.hash;
};

Block.prototype.getHeight = function getHeight() {
  if (this.height !== -1)
    return this.height;

  if (!this.chain)
    return -1;

  return this.chain.getHeight(this.hash('hex'));
};

Block.prototype.getCoinbaseHeight = function getCoinbaseHeight() {
  var coinbase, s, height;

  if (this.subtype !== 'block')
    return -1;

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

  reward = utils.satoshi('50.0');
  reward.iushrn(halvings);

  return reward;
};

Block.prototype._getReward = function _getReward() {
  var reward, base, fee, height;

  if (this._reward)
    return this._reward;

  base = Block.reward(this.height);

  if (this.subtype !== 'block'
      || this.txs.length === 0
      || !this.txs[0].isCoinbase()) {
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

Block.prototype.getBaseReward = function getBaseReward() {
  return this._getReward().base;
};

Block.prototype.getReward = function getReward() {
  return this._getReward().reward;
};

Block.prototype.getFee = function getFee() {
  return this._getReward().fee;
};

Block.prototype.getEntry = function getEntry() {
  if (!this.chain)
    return;
  return this.chain.getEntry(this);
};

Block.prototype.isOrphan = function isOrphan() {
  if (!this.chain)
    return true;
  return !this.chain.hasBlock(this.prevBlock);
};

Block.prototype.getCoinbase = function getCoinbase() {
  var tx;

  if (this.subtype !== 'block')
    return;

  tx = this.txs[0];
  if (!tx || !tx.isCoinbase())
    return;

  return tx;
};

Block.prototype.__defineGetter__('chain', function() {
  return this._chain || bcoin.chain.global;
});

Block.prototype.__defineGetter__('rhash', function() {
  return utils.revHex(this.hash('hex'));
});

Block.prototype.__defineGetter__('reward', function() {
  return this.getReward();
});

Block.prototype.__defineGetter__('fee', function() {
  return this.getFee();
});

Block.prototype.__defineGetter__('coinbase', function() {
  return this.getCoinbase();
});

Block.prototype.__defineGetter__('entry', function() {
  return this.getEntry();
});

Block.prototype.__defineGetter__('orphan', function() {
  return this.isOrphan();
});

Block.prototype.inspect = function inspect() {
  var copy = bcoin.block(this, this.subtype);
  copy.__proto__ = null;
  delete copy._raw;
  delete copy._chain;
  copy.hash = this.hash('hex');
  copy.rhash = this.rhash;
  copy.reward = utils.btc(this.getReward());
  copy.fee = utils.btc(this.getFee());
  copy.date = new Date((copy.ts || 0) * 1000).toISOString();
  return copy;
};

Block.prototype.toJSON = function toJSON() {
  return {
    v: 1,
    type: 'block',
    subtype: this.subtype,
    hash: this.hash('hex'),
    prevBlock: this.prevBlock,
    ts: this.ts,
    height: this.height,
    network: this.network,
    relayedBy: this.relayedBy,
    block: utils.toHex(this.render())
  };
};

Block.fromJSON = function fromJSON(json) {
  var raw, parser, data, block;

  assert.equal(json.v, 1);
  assert.equal(json.type, 'block');

  raw = new Buffer(json.block, 'hex');

  parser = new bcoin.protocol.parser();

  if (json.subtype === 'merkleblock')
    data = parser.parseMerkleBlock(raw);
  else if (json.subtype === 'block' || json.subtype === 'header')
    data = parser.parseBlock(raw);

  data.height = json.height;
  data.network = json.network;
  data.relayedBy = json.relayedBy;

  block = new Block(data, json.subtype);

  block._hash = json.hash;

  return block;
};

Block.prototype.toFullJSON = function toFullJSON() {
  return {
    v: 1,
    type: 'block',
    subtype: this.subtype,
    height: this.height,
    network: this.network,
    relayedBy: this.relayedBy,
    hash: utils.revHex(this.hash('hex')),
    version: this.version,
    prevBlock: utils.revHex(this.prevBlock),
    merkleRoot: utils.revHex(this.merkleRoot),
    ts: this.ts,
    bits: this.bits,
    nonce: this.nonce,
    txs: this.txs.map(function(tx) {
      return tx.toFullJSON();
    })
  };
};

Block.fromFullJSON = function fromFullJSON(json) {
  json.prevBlock = utils.revHex(json.prevBlock);
  json.merkleRoot = utils.revHex(json.merkleRoot);
  json.txs = json.txs.map(function(tx) {
    tx = bcoin.tx.fromFullJSON(tx);
    tx.ts = block.ts;
    tx.block = block.hash('hex');
    tx.height = block.height;
    return tx;
  });
  return new Block(json, json.subtype);
};

Block.prototype.toRaw = function toRaw(enc) {
  var data;

  assert(this.subtype === 'block');

  if (this.network && this._raw && this._raw.length > 80)
    data = this._raw;
  else
    data = new Buffer(this.render());

  if (enc === 'hex')
    data = utils.toHex(data);

  return data;
};

Block.fromRaw = function fromRaw(data, enc) {
  var parser = new bcoin.protocol.parser();

  if (enc === 'hex')
    data = new Buffer(data, 'hex');

  return new Block(parser.parseBlock(data), 'block');
};

/**
 * Expose
 */

module.exports = Block;
