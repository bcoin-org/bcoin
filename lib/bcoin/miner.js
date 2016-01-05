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

/**
 * Miner
 */

function Miner(options) {
  if (!(this instanceof Miner))
    return new Miner(options);

  if (!options)
    options = {};

  this.options = options;
  this.address = this.options.address;
  this.msg = this.options.msg || 'mined by bcoin';

  this.chain = options.chain || bcoin.chain.global;
  this.pool = options.pool || bcoin.pool.global;

  this.running = false;
  this.timeout = null;
  this.interval = null;

  this.fee = new bn(0);
  this.last = this.chain.getTip();
  this.block = null;
  this.rate = 0;
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
    self.emit('debug',
      'Found block: %d (%s)',
      self.last.height + 1,
      block.hash('hex'));
    self.pool.sendBlock(block);
  });

  this.on('status', function(stat) {
    self.emit('debug', 'Hashes per second: %s', stat.hashrate);
  });
};

Miner.prototype.start = function start() {
  var mempool = this.pool.loadMempool.bind(this.pool);

  this.stop();

  this.running = true;

  // Ask our peers for mempool txs every so often.
  this.interval = setInterval(mempool, 60 * 1000);

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
    this.last = block.verify
      ? this.chain.getBlock(block)
      : block;
    assert(this.last);
    this.start();
  }
};

Miner.prototype.addTX = function addTX(tx) {
  var full = this.index.inputs.every(function(input) {
    return !!input.out.tx;
  });

  // Cannot calculate fee if we don't have the prev_out.
  // Could possibly just burn some coins.
  if (this.options.burn === false) {
    if (!full)
      return;
  }

  // Pretty important
  if (!tx.verify())
    return;

  // Ignore if it's already in a block
  if (tx.height !== -1)
    return;

  // Deliver me from the block size debate, please
  if (this.block.size() + tx.size() > constants.blocks.maxSize)
    return;

  // Add the tx to our block
  this.block.txs.push(tx);

  // Calulcate our new reward fee
  if (full)
    this.fee.iadd(tx.getFee());

  // Update coinbase value
  this.updateCoinbase();

  // Update merkle root for new coinbase and new tx
  this.updateMerkle();
};

Miner.prototype.createBlock = function createBlock(tx) {
  var target, coinbase, headers, block;

  // Update target
  target = this.chain.target(this.last);

  // Create a coinbase
  coinbase = bcoin.tx();

  coinbase.input({
    out: {
      hash: utils.toHex(constants.zeroHash),
      index: 0xffffffff
    },
    script: [
      new bn(this.last.height + 1).toArray().reverse(),
      [],
      utils.ascii2array(this.msg || 'mined by bcoin')
    ],
    seq: 0xffffffff
  });

  coinbase.output({
    address: this.address,
    value: new bn(0)
  });

  // Create our block
  headers = {
    version: 4,
    prevBlock: this.last.verify
      ? this.last.hash('hex')
      : this.last.hash,
    merkleRoot: utils.toHex(constants.zeroHash.slice()),
    ts: utils.now(),
    bits: utils.toCompact(target),
    nonce: 0
  };

  block = bcoin.block(headers, 'block');

  delete block.valid;

  block.txs.push(coinbase);

  // Update coinbase since our coinbase was added.
  this.updateCoinbase(block);

  // Create our merkle root.
  this.updateMerkle(block);

  block.target = target;
  block.extraNonce = new bn(0);

  return block;
};

Miner.prototype.updateCoinbase = function updateCoinbase(block) {
  var coinbase = block.coinbase;

  assert(coinbase);

  if (!block)
    block = this.block;

  coinbase.inputs[0].script[1] = block.extraNonce.toArray();
  coinbase.outputs[0].value = bcoin.block.reward(this.last.height + 1).add(fee);
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

Miner.prototype.findNonce = function findNonce() {
  var begin = utils.now();

  // The heart and soul of the miner: match the target.
  while (this.block.nonce <= 0xffffffff) {
    if (utils.testTarget(this.block.target, this.block.hash()))
      return true;

    this.block.nonce++;
  }

  // Calculate our terrible hashrate
  this.rate = (0xffffffff / (utils.now() - begin)) * 2;

  // Overflow the nonce and increment the extraNonce.
  this.block.nonce = 0;
  this.block.extraNonce.iaddn(1);

  // We incremented the extraNonce, need to update coinbase.
  this.updateCoinbase();

  // We changed the coinbase, need to update merkleRoot.
  this.updateMerkle();

  // Send progress report
  this.emit('status', {
    block: this.block,
    target: this.block.target,
    hashes: this.block.extraNonce.mul(0xffffffff).toString(10),
    hashrate: this.rate
  });

  return false;
};

/**
 * Expose
 */

module.exports = Miner;
