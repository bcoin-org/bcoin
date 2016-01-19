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

  this._chain = data.chain;

  this.valid = null;
  this._hash = null;

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
    this.txs = this.txs.map(function(tx) {
      tx.network = self.network;
      tx.relayedBy = self.relayedBy;
      tx = bcoin.tx(tx);
      tx.block = self.hash('hex');
      tx.ts = tx.ts || self.ts;
      return tx;
    });
  }

  this.verify();

  if (this.subtype === 'block' && !this.valid) {
    this.txs = this.txs.map(function(tx) {
      tx.block = null;
      if (tx.ts === self.ts)
        tx.ts = 0;
      return tx;
    });
  }
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
  if (this.valid == null)
    this.valid = this._verify();
  return this.valid;
};

Block.verify = function verify(data, subtype) {
  var block = new Block(data, subtype);
  return block.verify();
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

Block.prototype._debug = function debug() {
  var args = Array.prototype.slice.call(arguments);

  if (!this.chain)
    return;

  args.unshift('debug');

  return this.chain.emit.apply(this.chain, args);
};

Block.prototype._verify = function _verify() {
  var uniq = {};
  var i, tx, hash;

  // Check proof of work
  if (!utils.testTarget(this.bits, this.hash())) {
    this._debug('Block failed POW test: %s', this.rhash);
    return false;
  }

  // Check timestamp against now + 2 hours
  if (this.ts > utils.now() + 2 * 60 * 60) {
    this._debug('Block timestamp is too high: %s', this.rhash);
    return false;
  }

  // Verify the partial merkle tree if we are a merkleblock.
  if (this.subtype === 'merkleblock') {
    if (!this._verifyPartial()) {
      this._debug('Block failed merkle test: %s', this.rhash);
      return false;
    }
  }

  // Merkleblock and headers cannot do anymore tests.
  if (this.subtype !== 'block')
    return true;

  // Size can't be bigger than MAX_BLOCK_SIZE
  if (this.txs.length > constants.block.maxSize
      || this.size() > constants.block.maxSize) {
    this._debug('Block is too large: %s', this.rhash);
    return false;
  }

  // First TX must be a coinbase
  if (!this.txs.length || !this.txs[0].isCoinbase()) {
    this._debug('Block has no coinbase: %s', this.rhash);
    return false;
  }

  // Test all txs
  for (i = 0; i < this.txs.length; i++) {
    tx = this.txs[i];

    // The rest of the txs must not be coinbases
    if (i > 0 && tx.isCoinbase()) {
      this._debug('Block more than one coinbase: %s', this.rhash);
      return false;
    }

    // Check for duplicate txids
    hash = tx.hash('hex');
    if (uniq[hash]) {
      this._debug('Block has duplicate txids: %s', this.rhash);
      return false;
    }
    uniq[hash] = true;
  }

  // Check merkle root
  if (this.getMerkleRoot() !== this.merkleRoot) {
    this._debug('Block failed merkleroot test: %s', this.rhash);
    return false;
  }

  return true;
};

Block.prototype.verifyContext = function verifyContext() {
  var flags = {};
  var sigops = 0;
  var prev, height, ts, i, j, tx, cb, input;

  if (this.subtype !== 'block')
    return true;

  if (this.isGenesis())
    return true;

  if (!this.chain)
    return true;

  prev = this.chain.getBlock(this.prevBlock);

  // Ensure it's not an orphan
  if (!prev) {
    this._debug('Block has no previous entry: %s', this.rhash);
    return false;
  }

  height = prev.height + 1;

  // Ensure the timestamp is correct
  if (this.ts <= prev.getMedianTime()) {
    this._debug('Block time is lower than median: %s', this.rhash);
    return false;
  }

  // Ensure the miner's target is equal to what we expect
  if (this.bits !== this.chain.target(prev, this)) {
    this._debug('Block is using wrong target: %s', this.rhash);
    return false;
  }

  // Only allow version 2 blocks (coinbase height)
  // once the majority of blocks are using it.
  if (this.version < 2 && prev.isOutdated(2)) {
    this._debug('Block is outdated (v2): %s', this.rhash);
    return false;
  }

  // Only allow version 3 blocks (sig validation)
  // once the majority of blocks are using it.
  if (this.version < 3 && prev.isOutdated(3)) {
    this._debug('Block is outdated (v3): %s', this.rhash);
    return false;
  }

  // Only allow version 4 blocks (checklocktimeverify)
  // once the majority of blocks are using it.
  if (this.version < 4 && prev.isOutdated(4)) {
    this._debug('Block is outdated (v4): %s', this.rhash);
    return false;
  }

  // Only allow version 8 blocks (locktime median past)
  // once the majority of blocks are using it.
  // if (this.version < 8 && prev.isOutdated(8)) {
  //   this._debug('Block is outdated (v8): %s', this.rhash);
  //   return false;
  // }

  // Make sure the height contained in the coinbase is correct.
  if (this.version >= 2 && prev.isUpgraded(2)) {
    cb = bcoin.script.isCoinbase(this.txs[0].inputs[0].script, this);

    // Make sure the coinbase is parseable.
    if (!cb) {
      this._debug('Block has malformed coinbase: %s', this.rhash);
      return false;
    }

    // Make sure coinbase height is equal to the actual height.
    if (cb.height !== height) {
      this._debug('Block has bad coinbase height: %s', this.rhash);
      return false;
    }
  }

  // Signature validation is now enforced (bip66)
  if (!(this.version >= 3 && prev.isUpgraded(3)))
    flags.dersig = false;

  // CHECKLOCKTIMEVERIFY is now usable (bip65)
  if (!(this.version >= 4 && prev.isUpgraded(4)))
    flags.checklocktimeverify = false;

  // Use nLockTime median past (bip113)
  // https://github.com/btcdrak/bips/blob/d4c9a236ecb947866c61aefb868b284498489c2b/bip-0113.mediawiki
  // Support version bits:
  // https://gist.github.com/sipa/bf69659f43e763540550
  // http://lists.linuxfoundation.org/pipermail/bitcoin-dev/2015-August/010396.html
  // if (this.version >= 8 && prev.isUpgraded(8))
  //   flags.locktimeMedian = true;

  // If we are an ancestor of a checkpoint, we can
  // skip the input verification.
  if (height < network.checkpoints.lastHeight && !network.checkpoints[height])
    flags.scriptChecks = false;

  // Get timestamp for tx.isFinal().
  ts = flags.locktimeMedian
    ? prev.getMedianTime()
    : this.ts;

  // Check all transactions
  for (i = 0; i < this.txs.length; i++) {
    tx = this.txs[i];

    // Transactions must be finalized with
    // regards to nSequence and nLockTime.
    if (!tx.isFinal(height, ts)) {
      this._debug('TX is not final: %s (%s)', this.rhash, i);
      return false;
    }

    // Check for tx sigops limits
    // Bitcoind does not check for this when accepting
    // a block even though it probably should.
    // if (tx.sigops(true) > constants.script.maxTxSigops) {
    //   // Block 71036 abused checksig to
    //   // include a huge number of sigops.
    //   this._debug('Block TX has too many sigops: %s', this.rhash);
    //   if (!(network.type === 'main' && height === 71036))
    //     return false;
    // }

    // Check for block sigops limits
    // Start counting P2SH sigops once block
    // timestamps reach March 31st, 2012.
    if (this.ts >= constants.block.bip16time)
      sigops += tx.sigops(true);
    else
      sigops += tx.sigops();

    if (sigops > constants.script.maxBlockSigops) {
      this._debug('Block has too many sigops: %s', this.rhash);
      return false;
    }

    // BIP30 - Ensure there are no duplicate txids
    if (this.chain.index[tx.hash('hex')]) {
      // Blocks 91842 and 91880 created duplicate
      // txids by using the same exact output script
      // and extraNonce.
      this._debug('Block is overwriting txids: %s', this.rhash);
      if (!(network.type === 'main' && (height === 91842 || height === 91880)))
        return false;
    }

    // Verify the inputs of every tx (CheckInputs)
    if (flags.scriptChecks !== false) {
      if (tx.isCoinbase())
        continue;

      for (j = 0; j < tx.inputs.length; j++) {
        input = tx.inputs[j];

        // We need the previous output in order
        // to verify the script.
        if (!input.out.tx)
          continue;

        assert(input.out.tx);

        // Verify the script
        if (!tx.verify(j, true, flags)) {
          this._debug('Block has invalid inputs: %s', this.rhash);
          return false;
        }

        // Ensure tx is not double spending an output
        // if (this.chain.isSpent(input.out.hash, input.out.index)) {
        //   this._debug('Block is using spent inputs: %s', this.rhash);
        //   return false;
        // }
      }
    }
  }

  return true;
};

Block.prototype.isGenesis = function isGenesis() {
  return this.hash('hex') === utils.toHex(network.genesis._hash);
};

Block.prototype.getHeight = function getHeight() {
  if (!this.chain)
    return -1;
  return this.chain.getHeight(this.hash('hex'));
};

Block.prototype.getNextBlock = function getNextBlock() {
  var next;

  if (!this.chain)
    return utils.toHex(constants.zeroHash);

  next = this.chain.getNextBlock(this.hash('hex'));

  if (!next)
    return utils.toHex(constants.zeroHash);

  return next;
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

Block.prototype.getEntry = function getEntry() {
  if (!this.chain)
    return;
  return this.chain.getBlock(this);
};

Block.prototype.isOrphan = function isOrphan() {
  if (!this.chain)
    return true;
  return this.chain.hasBlock(this.prevBlock);
};

Block.prototype.__defineGetter__('chain', function() {
  return this._chain || bcoin.chain.global;
});

Block.prototype.__defineGetter__('rhash', function() {
  return utils.revHex(this.hash('hex'));
});

Block.prototype.__defineGetter__('height', function() {
  return this.getHeight();
});

Block.prototype.__defineGetter__('nextBlock', function() {
  return this.getNextBlock();
});

Block.prototype.__defineGetter__('reward', function() {
  return this.getReward().reward;
});

Block.prototype.__defineGetter__('fee', function() {
  return this.getReward().fee;
});

Block.prototype.__defineGetter__('coinbase', function() {
  var tx = this.txs[0];
  if (!tx || !tx.isCoinbase())
    return;
  return tx;
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
  copy.height = this.height;
  copy.nextBlock = this.nextBlock;
  copy.reward = utils.btc(this.reward);
  copy.fee = utils.btc(this.fee);
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
    network: this.network,
    relayedBy: this.relayedBy,
    block: utils.toHex(bcoin.protocol.framer.block(this, this.subtype))
  };
};

Block.fromJSON = function fromJSON(json) {
  var raw, parser, data, block;

  utils.assert.equal(json.v, 1);
  utils.assert.equal(json.type, 'block');

  raw = utils.toArray(json.block, 'hex');

  parser = new bcoin.protocol.parser();

  if (json.subtype === 'merkleblock')
    data = parser.parseMerkleBlock(raw);
  else if (json.subtype === 'block' || json.subtype === 'header')
    data = parser.parseBlock(raw);

  data.network = json.network;
  data.relayedBy = json.relayedBy;

  block = new Block(data, json.subtype);

  block._hash = json.hash;

  return block;
};

/**
 * Expose
 */

module.exports = Block;
