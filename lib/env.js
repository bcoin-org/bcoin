/*!
 * env.js - environment for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License).
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var lazy = require('./utils/lazy');

/**
 * A bcoin "environment" which exposes all
 * constructors for primitives, the blockchain,
 * mempool, wallet, etc. It also exposes a
 * global worker pool.
 * @exports Environment
 * @constructor
 * @property {Function} env - See {@link Environment}.
 * @property {Function} require - See {@link module:utils/lazy}.
 *
 * @property {Function} bn - See {@url https://github.com/indutny/bn.js}.
 * @property {Object} elliptic - See {@url https://github.com/indutny/elliptic}.
 *
 * @property {Object} bip70 - See {@link module:bip70}.
 *
 * @property {Object} blockchain - See {@link module:blockchain}.
 * @property {Function} chain - See {@link module:blockchain.Chain}.
 * @property {Function} chaindb - See {@link module:blockchain.ChainDB}.
 * @property {Function} chainentry - See {@link module:blockchain.ChainEntry}.
 *
 * @property {Object} btc
 * @property {Function} amount
 * @property {Function} uri
 *
 * @property {Object} coins
 * @property {Function} coinview
 *
 * @property {Object} crypto
 * @property {Object} ec
 * @property {Object} pk
 * @property {Object} schnorr
 *
 * @property {Object} db
 * @property {Object} ldb
 *
 * @property {Object} hd
 *
 * @property {Object} http
 * @property {Object} rpc
 *
 * @property {Object} txmempool
 * @property {Object} fees
 * @property {Object} mempool
 * @property {Object} mempoolentry
 *
 * @property {Object} mining
 * @property {Object} miner
 * @property {Object} minerblock
 *
 * @property {Object} net
 * @property {Object} bip150
 * @property {Object} bip151
 * @property {Object} bip152
 * @property {Object} dns
 * @property {Object} packets
 * @property {Object} peer
 * @property {Object} pool
 * @property {Object} tcp
 *
 * @property {Object} node
 * @property {Object} config
 * @property {Object} fullnode
 * @property {Object} logger
 * @property {Object} spvnode
 *
 * @property {Object} primitives
 * @property {Object} address
 * @property {Object} block
 * @property {Object} coin
 * @property {Object} headers
 * @property {Object} input
 * @property {Object} invitem
 * @property {Object} keyring
 * @property {Object} merkleblock
 * @property {Object} mtx
 * @property {Object} netaddress
 * @property {Object} outpoint
 * @property {Object} output
 * @property {Object} tx
 *
 * @property {Object} protocol
 * @property {Object} consensus
 * @property {Object} errors
 * @property {Object} network
 * @property {Object} networks
 * @property {Object} policy
 * @property {Object} timedata
 *
 * @property {Object} txscript
 * @property {Object} opcodes
 * @property {Object} program
 * @property {Object} script
 * @property {Object} sigcache
 * @property {Object} stack
 * @property {Object} witness
 *
 * @property {Object} utils
 * @property {Object} base32
 * @property {Object} base58
 * @property {Object} bloom
 * @property {Object} co
 * @property {Object} encoding
 * @property {Object} lock
 * @property {Object} reader
 * @property {Object} staticwriter
 * @property {Object} util
 * @property {Object} writer
 *
 * @property {Object} wallet
 * @property {Object} path
 * @property {Object} walletkey
 * @property {Object} walletdb
 *
 * @property {Object} workers
 * @property {Object} workerpool
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
  this.require('template', './mining/template');

  // Net
  this.require('net', './net');
  this.require('bip150', './net/bip150');
  this.require('bip151', './net/bip151');
  this.require('bip152', './net/bip152');
  this.require('dns', './net/dns');
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
  this.require('base32', './utils/base32');
  this.require('base58', './utils/base58');
  this.require('bloom', './utils/bloom');
  this.require('co', './utils/co');
  this.require('encoding', './utils/encoding');
  this.require('lock', './utils/lock');
  this.require('reader', './utils/reader');
  this.require('staticwriter', './utils/staticwriter');
  this.require('util', './utils/util');
  this.require('writer', './utils/writer');

  // Wallet
  this.require('wallet', './wallet');
  this.require('path', './wallet/path');
  this.require('walletkey', './wallet/walletkey');
  this.require('walletdb', './wallet/walletdb');
  this.require('walletplugin', './wallet/plugin');

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
