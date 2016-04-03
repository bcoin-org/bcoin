/**
 * miner.js - inefficient miner for bcoin (because we can)
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

var bcoin = require('../bcoin');
var utils = require('./utils');
var assert = utils.assert;
var constants = bcoin.protocol.constants;

var bn = require('bn.js');
var EventEmitter = require('events').EventEmitter;

/**
 * Miner
 */

function Miner(node, options) {
  if (!(this instanceof Miner))
    return new Miner(node, options);

  EventEmitter.call(this);

  if (!options)
    options = {};

  this.options = options;
  this.address = this.options.address;
  this.coinbaseFlags = this.options.coinbaseFlags || 'mined by bcoin';

  // Allow a dsha256 option in case someone
  // wants to pass in a faster linked in function.
  this.dsha256 = this.options.dsha256 || utils.dsha256;

  this.node = node;
  this.pool = node.pool;
  this.chain = node.chain;
  this.mempool = node.mempool;

  this.running = false;
  this.timeout = null;

  this.fee = new bn(0);
  this.last = this.node.chain.tip;
  this.block = null;
  this.iterations = 0;
  this._begin = utils.now();

  this._init();
}

utils.inherits(Miner, EventEmitter);

Miner.prototype._init = function _init() {
  var self = this;

  if (this.mempool) {
    this.mempool.on('tx', function(tx) {
      if (!self.running)
        return;
      self.addTX(tx);
    });
  } else {
    this.pool.on('tx', function(tx) {
      if (!self.running)
        return;
      self.addTX(tx);
    });
  }

  this.chain.on('tip', function(tip) {
    if (!self.running)
      return;
    self.last = tip;
    self.start();
  });

  this.on('block', function(block) {
    utils.debug(
      'Found block: %d (%s)',
      block.height,
      block.hash('hex'));
    // Emit the block hex as a failsafe (in case we can't send it)
    utils.debug('Raw: %s', utils.toHex(block.render()));
    self.pool.sendBlock(block);
  });

  this.on('status', function(stat) {
    utils.debug(
      'hashrate=%dkhs hashes=%d target=%d height=%d best=%s',
      stat.hashrate / 1000 | 0,
      stat.hashes,
      stat.target,
      stat.height,
      stat.best);
  });
};

Miner.prototype.start = function start() {
  var self = this;

  // Wait for `tip`.
  if (!this.last)
    return;

  this.stop();

  this.running = true;

  // Reset iterations
  this.iterations = 0;

  // Create a new block and start hashing
  this.createBlock(function(err, block) {
    if (err)
      return self.emit('error', err);

    self.block = block;

    if (!self.mempool)
      return self.iterate();

    self.mempool.getSnapshot(function(err, hashes) {
      if (err)
        return self.emit('error', err);

      utils.forEachSerial(hashes, function(hash, next) {
        self.mempool.getTX(hash, function(err, tx) {
          if (err)
            return next(err);

          self.mempool.fillAllCoins(tx, function(err) {
            if (err)
              return next(err);

            self.addTX(tx);
            next();
          });
        });
      }, function(err) {
        if (err)
          return self.emit('error', err);

        self.iterate();
      });
    });
  });
};

Miner.prototype.stop = function stop() {
  if (!this.running)
    return;

  this.running = false;

  clearTimeout(this.timeout);
  this.timeout = null;
};

Miner.prototype.addTX = function addTX(tx) {
  var size = this.block.getVirtualSize() + tx.getVirtualSize();

  // Deliver me from the block size debate, please
  if (size > constants.blocks.maxSize)
    return false;

  if (this.block._txMap[tx.hash('hex')])
    return false;

  if (!this.block.witness && tx.hasWitness())
    return false;

  // Add the tx to our block
  this.block.txs.push(tx);
  this.block._txMap[tx.hash('hex')] = true;

  // Calculate our new reward fee
  this.fee.iadd(tx.getFee());

  // Update coinbase value
  this.updateCoinbase();

  // Update merkle root for new coinbase and new tx
  this.updateMerkle();

  return true;
};

Miner.prototype.createBlock = function createBlock(callback) {
  var self = this;
  var ts, target, coinbase, headers, block;

  // Find target
  this.last.ensureAncestors(function(err) {
    if (err) {
      self.last.free();
      return callback(err);
    }

    // Calculate version with versionbits
    self.chain.computeBlockVersion(self.last, function(err, version) {
      if (err) {
        self.last.free();
        return callback(err);
      }

      ts = Math.max(utils.now(), this.last.ts + 1);

      target = self.chain.getTarget(self.last, ts);

      // Create a coinbase
      coinbase = bcoin.mtx();

      coinbase.addInput({
        prevout: {
          hash: utils.toHex(constants.zeroHash),
          index: 0xffffffff
        },
        coin: null,
        script: new bcoin.script([
          // Height (required in v2+ blocks)
          bcoin.script.array(self.last.height + 1),
          // extraNonce - incremented when
          // the nonce overflows.
          bcoin.script.array(0),
          // Add a nonce to ensure we don't
          // collide with a previous coinbase
          // of ours. This isn't really
          // necessary nowdays due to bip34
          // (used above).
          bcoin.script.array(utils.nonce()),
          // Let the world know this little
          // miner succeeded.
          new Buffer(self.coinbaseFlags, 'ascii')
        ]),
        witness: new bcoin.script.witness([]),
        sequence: 0xffffffff
      });

      coinbase.addOutput({
        address: self.address,
        value: new bn(0)
      });

      // Create our block
      headers = {
        version: version,
        prevBlock: self.last.hash,
        merkleRoot: utils.toHex(constants.zeroHash),
        ts: ts,
        bits: target,
        nonce: 0
      };

      block = bcoin.block(headers, 'block');
      block._txMap = {};

      block.txs.push(coinbase);

      block.target = utils.fromCompact(target);
      block.extraNonce = new bn(0, 'le');

      if (self.chain.segwitActive) {
        // Set up the witness nonce and
        // commitment output for segwit.
        block.witness = true;
        block.witnessNonce = utils.nonce().toBuffer();
        coinbase.inputs[0].witness.items[0] = block.witnessNonce;
        coinbase.addOutput({
          script: new bcoin.script([]),
          value: new bn(0)
        });
      }

      // Update coinbase since our coinbase was added.
      self.updateCoinbase(block);

      // Create our merkle root.
      self.updateMerkle(block);

      self.last.free();

      return callback(null, block);
    });
  });
};

Miner.prototype.updateCommitment = function updateCommitment(block) {
  var coinbase = block.txs[0];
  var hash;

  assert(coinbase);

  if (!block)
    block = this.block;

  delete block._txMap[coinbase.hash('hex')];

  hash = block.getCommitmentHash();
  coinbase.outputs[1].script = bcoin.script.createCommitment(hash);

  block._txMap[coinbase.hash('hex')] = true;
};

Miner.prototype.updateCoinbase = function updateCoinbase(block) {
  var coinbase = block.txs[0];
  var reward = bcoin.block.reward(this.last.height + 1);

  assert(coinbase);

  if (!block)
    block = this.block;

  delete block._txMap[coinbase.hash('hex')];

  coinbase.inputs[0].script[1] = block.extraNonce.toBuffer();
  coinbase.outputs[0].value = reward.add(this.fee);

  block._txMap[coinbase.hash('hex')] = true;
};

Miner.prototype.updateMerkle = function updateMerkle(block) {
  if (!block)
    block = this.block;

  // Always update commitment before updating merkle root.
  // The updated commitment output will change the merkle root.
  if (block.witness)
    this.updateCommitment(block);

  block.ts = utils.now();
  block.merkleRoot = block.getMerkleRoot('hex');
};

Miner.prototype.iterate = function iterate() {
  var self = this;

  this.timeout = setTimeout(function() {
    // Try to find a block: do one iteration of extraNonce
    if (!self.findNonce())
      return self.iterate();

    // Add our block to the chain
    self.chain.add(self.block, function(err) {
      if (err) {
        if (err.type === 'VerifyError')
          utils.debug('Miner: %s could not be added to chain.', block.rhash);
        return self.emit('error', err);
      }

      // Emit our newly found block
      self.emit('block', self.block);

      // `tip` will now be emitted by chain
      // and the whole process starts over.
    });
  }, 100);
};

Miner.prototype.__defineGetter__('hashes', function() {
  return new bn(this.iterations).muln(0xffffffff).addn(this.block.nonce);
});

Miner.prototype.__defineGetter__('rate', function() {
  if (!this.block.nonce)
    return 0;
  // Calculate our terrible hashrate
  return (this.block.nonce / (utils.now() - this._begin)) * 2 | 0;
});

Miner.prototype.sendStatus = function sendStatus() {
  this.emit('status', {
    block: this.block,
    target: this.block.bits,
    hashes: this.hashes.toString(10),
    hashrate: this.rate,
    height: this.last.height + 1,
    best: utils.revHex(this.last.hash)
  });
};

Miner.prototype.findNonce = function findNonce() {
  var data = this.block.abbr();
  var now;

  // Track how long we've been at it.
  this._begin = utils.now();

  // The heart and soul of the miner: match the target.
  while (this.block.nonce <= 0xffffffff) {
    // Hash and test against the next target
    if (utils.testTarget(this.block.target, this.dsha256(data)))
      return true;

    // Increment the nonce to get a different hash
    this.block.nonce++;

    // Update the raw buffer (faster than
    // constantly serializing the block)
    utils.writeU32(data, this.block.nonce, 76);

    // Send progress report every so often
    if (this.block.nonce % 100000 === 0)
      this.sendStatus();
  }

  // Keep track of our iterations
  this.iterations++;

  // Send progress report
  this.sendStatus();

  // If we took more a second or more (likely),
  // skip incrementing the extra nonce and just
  // update the timestamp. This improves
  // performance because we do not have to
  // recalculate the merkle root.
  now = utils.now();
  if (now > this.block.ts && now > this.last.ts) {
    this.block.ts = now;
    // Overflow the nonce
    this.block.nonce = 0;
    return false;
  }

  // Overflow the nonce and increment the extraNonce.
  this.block.nonce = 0;
  this.block.extraNonce.iaddn(1);

  // We incremented the extraNonce, need to update coinbase.
  this.updateCoinbase();

  // We changed the coinbase, need to update merkleRoot.
  this.updateMerkle();

  return false;
};

/**
 * Expose
 */

module.exports = Miner;
