/*!
 * env.js - environment for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License).
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var lazy = require('./utils/lazy');

/**
 * A BCoin "environment" which exposes all
 * constructors for primitives, the blockchain,
 * mempool, wallet, etc. It also exposes a
 * global worker pool.
 * @constructor
 */

function Environment() {
  this.env = Environment;
  this.require = lazy(require, this);

  // BN
  this.require('bn', 'bn.js');
  this.require('elliptic', 'elliptic');

  // Horrible BIP
  this.require('bip70', './bip70');

  // Blockchain
  this.require('blockchain', './blockchain');
  this.require('chain', './blockchain/chain');
  this.require('chaindb', './blockchain/chaindb');
  this.require('chainentry', './blockchain/chainentry');

  // BTC
  this.require('btc', './btc');
  this.require('amount', './btc/amount');
  this.require('uri', './btc/uri');

  // Coins
  this.require('coins', './coins');
  this.require('coinview', './coins/coinview');

  // Crypto
  this.require('crypto', './crypto');
  this.require('ec', './crypto/ec');
  this.require('pk', './crypto/pk');
  this.require('schnorr', './crypto/schnorr');

  // DB
  this.require('db', './db');
  this.require('ldb', './db/ldb');

  // HD
  this.require('hd', './hd');

  // HTTP
  this.require('http', './http');
  this.require('rpc', './http/rpc');

  // Mempool
  this.require('txmempool', './mempool');
  this.require('fees', './mempool/fees');
  this.require('mempool', './mempool/mempool');
  this.require('mempoolentry', './mempool/mempoolentry');

  // Miner
  this.require('mining', './mining');
  this.require('miner', './mining/miner');
  this.require('minerblock', './mining/minerblock');

  // Net
  this.require('net', './net');
  this.require('bip150', './net/bip150');
  this.require('bip151', './net/bip151');
  this.require('bip152', './net/bip152');
  this.require('packets', './net/packets');
  this.require('peer', './net/peer');
  this.require('pool', './net/pool');
  this.require('tcp', './net/tcp');

  // Node
  this.require('node', './node');
  this.require('config', './node/config');
  this.require('fullnode', './node/fullnode');
  this.require('logger', './node/logger');
  this.require('spvnode', './node/spvnode');

  // Primitives
  this.require('primitives', './primitives');
  this.require('address', './primitives/address');
  this.require('block', './primitives/block');
  this.require('coin', './primitives/coin');
  this.require('headers', './primitives/headers');
  this.require('input', './primitives/input');
  this.require('invitem', './primitives/invitem');
  this.require('keyring', './primitives/keyring');
  this.require('merkleblock', './primitives/merkleblock');
  this.require('mtx', './primitives/mtx');
  this.require('netaddress', './primitives/netaddress');
  this.require('outpoint', './primitives/outpoint');
  this.require('output', './primitives/output');
  this.require('tx', './primitives/tx');

  // Protocol
  this.require('protocol', './protocol');
  this.require('consensus', './protocol/consensus');
  this.require('errors', './protocol/errors');
  this.require('network', './protocol/network');
  this.require('networks', './protocol/networks');
  this.require('policy', './protocol/policy');
  this.require('timedata', './protocol/timedata');

  // Script
  this.require('txscript', './script');
  this.require('opcode', './script/opcode');
  this.require('program', './script/program');
  this.require('script', './script/script');
  this.require('sigcache', './script/sigcache');
  this.require('stack', './script/stack');
  this.require('witness', './script/witness');

  // Utils
  this.require('utils', './utils');
  this.require('base58', './utils/base58');
  this.require('co', './utils/co');
  this.require('encoding', './utils/encoding');
  this.require('reader', './utils/reader');
  this.require('staticwriter', './utils/staticwriter');
  this.require('util', './utils/util');
  this.require('writer', './utils/writer');

  // Wallet
  this.require('wallet', './wallet');
  this.require('path', './wallet/path');
  this.require('walletkey', './wallet/walletkey');
  this.require('walletdb', './wallet/walletdb');

  // Workers
  this.require('workers', './workers');
  this.require('workerpool', './workers/workerpool');
}

/**
 * Set the default network.
 * @param {String} options
 */

Environment.prototype.set = function set(options) {
  if (typeof options === 'string')
    options = { network: options };

  if (!options)
    options = {};

  if (options.network)
    this.network.set(options.network);

  this.workerpool.set(options);

  if (options.sigcacheSize != null)
    this.sigcache.resize(options.sigcacheSize);

  return this;
};

/**
 * Get the adjusted time of
 * the default network.
 * @returns {Number} Adjusted time.
 */

Environment.prototype.now = function now() {
  return this.network.primary.now();
};

/**
 * Cache all necessary modules.
 */

Environment.prototype.cache = function cache() {
  this.bip70;
  this.common;
  this.crypto;
  this.fullnode;
  this.http;
  this.spvnode;
};

/*
 * Expose by converting `exports` to an
 * Environment.
 */

exports.cache = Environment.prototype.cache;
exports.set = Environment.prototype.set;
exports.now = Environment.prototype.now;

Environment.call(exports);
