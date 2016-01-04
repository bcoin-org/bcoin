/**
 * miner.js - simple miner for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

var bcoin = require('../bcoin');
var network = bcoin.protocol.network;
var constants = bcoin.protocol.constants;
var utils = bcoin.utils;
var bn = require('bn.js');
var inherits = require('inherits');
var EventEmitter = require('events').EventEmitter;
var assert = utils.assert;

/**
 * Miner
 */

exports.miner = function miner(options, callback) {
  var chain = bcoin.chain.global;
  var e = new EventEmitter;
  var fee = new bn(0);
  var last = chain.getTip();
  var nextBlock, timeout, blockChecker;

  function addBlock(b) {
    var block = b || chain.getTip();
    if (block.height > last.height) {
      last = block;
      // Somebody found the next block before us,
      // start over with new target.
      stop();
      start();
    }
  }

  function addTX(tx) {
    if (tx.inputs[0].output && !tx.verify())
      return;

    if (tx.height !== -1)
      return;

    if (block.size() + tx.size() > constants.blocks.maxSize)
      return;

    nextBlock.txs.push(tx);

    fee.iadd(tx.getFee());

    // Update coinbase value
    updateCoinbase(nextBlock);
    // Update merkle root for new coinbase and new tx
    updateMerkle(nextBlock);
  }

  function newBlock() {
    var coinbase, block, target;

    coinbase = bcoin.tx();

    coinbase.input({
      out: {
        hash: constants.zeroHash,
        index: 0xffffffff
      },
      script: [
        new bn(last.height + 1).toArray().reverse(),
        [],
        utils.ascii2array(options.msg || 'mined by bcoin')
      ],
      seq: 0xffffffff
    });

    coinbase.output({
      address: options.address,
      value: new bn(0)
    });

    target = chain.target(last);

    block = {
      version: 4,
      prevBlock: last.verify ? last.hash('hex') : last.hash,
      merkleRoot: constants.zeroHash.slice(),
      ts: utils.now(),
      bits: utils.toCompact(target),
      nonce: 0
    };

    block = bcoin.block(block, 'block');
    delete block.valid;
    block.verify = block._verify;

    block.target = target;
    block.extraNonce = new bn(0);

    block.txs.push(coinbase);

    // Update coinbase since our coinbase was added.
    updateCoinbase(block);
    // Create our merkle root.
    updateMerkle(block);

    return block;
  }

  function updateCoinbase(block) {
    var coinbase = block.txs[0];
    coinbase.inputs[0].script[1] = block.extraNonce.toArray();
    coinbase.outputs[0].value = bcoin.block.reward(last.height + 1).add(fee);
  }

  function updateMerkle(block) {
    block.ts = utils.now();
    block.merkleRoot = block.getMerkleRoot();
  }

  function iter(block) {
    timeout = setTimeout(function() {
      var hash, begin, rate;

      begin = utils.now();

      while (block.nonce <= 0xffffffff) {
        if (utils.testTarget(block.target, block.hash())) {
          e.emit('block', block);
          last = block;
          nextBlock = newBlock();
          return iter(nextBlock);
        }
        block.nonce++;
      }

      rate = (0xffffffff / (utils.now() - begin)) * 2;

      block.nonce = 0;
      block.extraNonce.iaddn(1);

      // We incremented the extraNonce, need to update coinbase.
      updateCoinbase(block);
      // We changed the coinbase, need to update merkleRoot.
      updateMerkle(block);

      e.emit('status', {
        block: block,
        target: utils.fromCompact(block.bits),
        hashes: block.extraNonce.mul(0xffffffff),
        hashrate: rate
      });

      return iter(block);
    }, 10);
  }

  function start() {
    blockChecker = setInterval(addBlock, 1000);
    nextBlock = newBlock();
    iter(nextBlock);
  }

  function stop() {
    if (!timeout)
      return;
    clearTimeout(timeout);
    timeout = null;
    clearInterval(blockChecker);
    blockChecker = null;
  }

  e.addBlock = addBlock;
  e.add = e.addTX = addTX;
  e.start = start;
  e.stop = stop;

  return e;
};

module.exports = function mine(pool, options) {
  var options, miner;

  options = {
    address: options.address,
    msg: options.msg || 'mined by bcoin',
    log: options.log
  };

  miner = exports.miner(options);

  // Use mempool
  pool.on('tx', function(tx) {
    miner.addTX(tx);
  });

  pool.chain.on('tip', function(block) {
    miner.addBlock(block);
  });

  miner.on('block', function(block) {
    pool.sendBlock(block);
  });

  miner.on('status', function(stat) {
    if (options.log)
      console.log('Hashes per second: %s', stat.hashrate);
  });

  miner.start();

  return miner;
};
