/**
 * miner.js - inefficient miner for bcoin (because we can)
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

var bcoin = require('../bcoin');
var utils = bcoin.utils;
var assert = utils.assert;
var constants = bcoin.protocol.constants;

var bn = require('bn.js');
var inherits = require('inherits');
var EventEmitter = require('events').EventEmitter;

var crypto = require('crypto');

/**
 * Miner
 */

function Miner(options) {
  if (!(this instanceof Miner))
    return new Miner(options);

  EventEmitter.call(this);

  if (!options)
    options = {};

  this.options = options;
  this.address = this.options.address;
  this.msg = this.options.msg || 'mined by bcoin';

  this.pool = options.pool || bcoin.pool.global;
  this.chain = options.chain || this.pool.chain || bcoin.chain.global;

  this.running = false;
  this.timeout = null;
  this.interval = null;

  this.fee = new bn(0);
  this.last = this.chain.getTip();
  this.block = null;
  this.iterations = 0;
  this._begin = utils.now();

  this._init();
}

inherits(Miner, EventEmitter);

Miner.prototype._init = function _init() {
  var self = this;

  this.pool.on('tx', function(tx) {
    self.addTX(tx);
  });

  this.chain.on('block', function(block) {
    self.addBlock(block);
  });

  // this.chain.on('tip', function(entry) {
  //   self.addBlock(entry);
  // });

  this.on('block', function(block) {
    self.chain.emit('debug',
      'Found block: %d (%s)',
      block.height,
      block.hash('hex'));
    // Emit the block hex as a failsafe (in case we can't send it)
    self.chain.emit('debug', 'Block: %s', utils.toHex(block.render()));
    self.pool.sendBlock(block);
  });

  this.on('status', function(stat) {
    self.chain.emit('debug',
      'hashrate=%dkhs hashes=%d target=%d height=%d best=%s',
      stat.hashrate / 1000 | 0,
      stat.hashes,
      stat.target,
      stat.height,
      stat.best);
  });
};

Miner.prototype.start = function start() {
  var mempool = this.pool.loadMempool.bind(this.pool);

  this.stop();

  this.running = true;

  // Ask our peers for mempool txs every so often.
  this.interval = setInterval(mempool, 60 * 1000);

  // Reset iterations
  this.iterations = 0;

  // Create a new block and start hashing
  this.block = this.createBlock();
  this.iterate();
};

Miner.prototype.stop = function stop() {
  if (!this.running)
    return;

  this.running = false;

  clearTimeout(this.timeout);
  this.timeout = null;

  clearInterval(this.interval);
  this.interval = null;
};

Miner.prototype.add = function add(msg) {
  if (msg.type === 'tx')
    return this.addTX(msg);
  return this.addBlock(msg);
};

Miner.prototype.addBlock = function addBlock(block) {
  if (!block)
    block = this.chain.getTip();

  // Somebody found the next block before
  // us, start over with the new target.
  if (block.height > this.last.height) {
    this.last = block.type === 'block'
      ? this.chain.getBlock(block)
      : block;
    assert(this.last);
    this.start();
  }
};

Miner.prototype.addTX = function addTX(tx) {
  var full, ts;

  full = this.index.inputs.every(function(input) {
    return !!input.out.tx;
  });

  // Cannot calculate fee if we don't have the prev_out.
  // Could possibly just burn some coins.
  if (this.options.burn === false) {
    if (!full)
      return;
  }

  // Ignore if it's already in a block
  if (tx.height !== -1)
    return;

  if (!tx.verify(null, true))
    return;

  if (tx.isCoinbase())
    return;

  // Get timestamp for tx.isFinal() - bip113
  ts = this.block.version === 8
    ? this.last.getMedianTime()
    : this.block.ts;

  if (!tx.isFinal(this.last.height + 1, ts))
    return;

  // Deliver me from the block size debate, please
  if (this.block.size() + tx.size() > constants.blocks.maxSize)
    return;

  // Add the tx to our block
  this.block.txs.push(tx);

  // Calculate our new reward fee
  if (full)
    this.fee.iadd(tx.getFee());

  // Update coinbase value
  this.updateCoinbase();

  // Update merkle root for new coinbase and new tx
  this.updateMerkle();
};

Miner.prototype.createBlock = function createBlock(tx) {
  var ts, target, coinbase, headers, block;

  ts = Math.max(utils.now(), this.last.ts + 1);

  // Find target
  target = this.chain.target(this.last, ts);

  // Create a coinbase
  coinbase = bcoin.tx();

  coinbase.input({
    out: {
      hash: utils.toHex(constants.zeroHash),
      index: 0xffffffff
    },
    script: [
      // Height (required in v2+ blocks)
      bcoin.script.array(this.last.height + 1),
      // extraNonce - incremented when
      // the nonce overflows.
      [],
      // Add a nonce to ensure we don't
      // collide with a previous coinbase
      // of ours. This isn't really
      // necessary nowdays due to bip34
      // (used above).
      utils.nonce().toArray(),
      // Let the world know this little
      // miner succeeded.
      utils.ascii2array(this.msg || 'mined by bcoin')
    ],
    seq: 0xffffffff
  });

  if (script.size(coinbase.inputs[0].script) > 100)
    throw new Error('Coinbase script is too large');

  coinbase.output({
    address: this.address,
    value: new bn(0)
  });

  // Create our block
  headers = {
    version: 4,
    prevBlock: this.last.hash,
    merkleRoot: utils.toHex(constants.zeroHash.slice()),
    ts: ts,
    bits: target,
    nonce: 0
  };

  block = bcoin.block(headers, 'block');

  delete block.valid;

  block.txs.push(coinbase);

  block.target = utils.fromCompact(target);
  block.extraNonce = script.num(0);

  // Update coinbase since our coinbase was added.
  this.updateCoinbase(block);

  // Create our merkle root.
  this.updateMerkle(block);

  return block;
};

Miner.prototype.updateCoinbase = function updateCoinbase(block) {
  var coinbase = block.txs[0];
  var reward = bcoin.block.reward(this.last.height + 1);

  assert(coinbase);

  if (!block)
    block = this.block;

  coinbase.inputs[0].script[1] = block.extraNonce.toArray();
  coinbase.outputs[0].value = reward.add(this.fee);
};

Miner.prototype.updateMerkle = function updateMerkle(block) {
  if (!block)
    block = this.block;

  block.ts = utils.now();
  block.merkleRoot = block.getMerkleRoot();
};

Miner.prototype.iterate = function iterate() {
  var self = this;

  this.timeout = setTimeout(function() {
    var hash;

    // Try to find a block: do one iteration of extraNonce
    if (!self.findNonce())
      return self.iterate();

    hash = self.block.hash('hex');

    // Make sure our block is valid
    if (!self.block.verify())
      return self.emit('debug', '%s did not verify.', hash);

    // Add our block to the chain
    res = self.chain.add(self.block);
    if (res > 0)
      return self.emit('debug', '%s could not be added to chain.', hash);

    // Emit our newly found block
    self.emit('block', self.block);

    // Try to find a new block
    self.last = self.chain.getBlock(self.block);
    assert(self.last);
    self.block = self.createBlock();

    return self.iterate();
  }, 10);
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
  var data = new Buffer(this.block.render());
  var now;

  // Track how long we've been at it.
  this._begin = utils.now();

  // The heart and soul of the miner: match the target.
  while (this.block.nonce <= 0xffffffff) {
    // Hash and test against the next target
    if (utils.testTarget(this.block.target, utils.dsha256(data)))
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
