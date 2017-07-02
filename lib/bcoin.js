/*!
 * bcoin.js - a javascript bitcoin library.
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License).
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

/**
 * A bcoin "environment" which exposes all
 * constructors for primitives, the blockchain,
 * mempool, wallet, etc. It also exposes a
 * global worker pool.
 *
 * @exports bcoin
 * @type {Object}
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
 * @property {Object} secp256k1
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

const bcoin = exports;

/**
 * Define a module for lazy loading.
 * @param {String} name
 * @param {String} path
 */

bcoin.define = function _require(name, path) {
  let cache;
  bcoin.__defineGetter__(name, function() {
    if (!cache)
      cache = require(path);
    return cache;
  });
};

/**
 * Set the default network.
 * @param {String} network
 */

bcoin.set = function set(network) {
  bcoin.network.set(network);
  return bcoin;
};

/**
 * Cache all necessary modules.
 */

bcoin.cache = function cache() {
  bcoin.bip70;
  bcoin.blockchain;
  bcoin.btc;
  bcoin.coins;
  bcoin.crypto;
  bcoin.db;
  bcoin.hd;
  bcoin.http;
  bcoin.txmempool;
  bcoin.mining;
  bcoin.net;
  bcoin.node;
  bcoin.primitives;
  bcoin.protocol;
  bcoin.txscript;
  bcoin.utils;
  bcoin.wallet;
  bcoin.workers;
  bcoin.pkg;
};

/*
 * Expose
 */

// Horrible BIP
bcoin.define('bip70', './bip70');

// Blockchain
bcoin.define('blockchain', './blockchain');
bcoin.define('chain', './blockchain/chain');
bcoin.define('chaindb', './blockchain/chaindb');
bcoin.define('chainentry', './blockchain/chainentry');

// BTC
bcoin.define('btc', './btc');
bcoin.define('amount', './btc/amount');
bcoin.define('uri', './btc/uri');

// Coins
bcoin.define('coins', './coins');
bcoin.define('coinview', './coins/coinview');

// Crypto
bcoin.define('crypto', './crypto');
bcoin.define('bn', './crypto/bn');
bcoin.define('secp256k1', './crypto/secp256k1');
bcoin.define('schnorr', './crypto/schnorr');

// DB
bcoin.define('db', './db');
bcoin.define('ldb', './db/ldb');

// HD
bcoin.define('hd', './hd');

// HTTP
bcoin.define('http', './http');
bcoin.define('rpc', './http/rpc');

// Mempool
bcoin.define('txmempool', './mempool');
bcoin.define('fees', './mempool/fees');
bcoin.define('mempool', './mempool/mempool');
bcoin.define('mempoolentry', './mempool/mempoolentry');

// Miner
bcoin.define('mining', './mining');
bcoin.define('miner', './mining/miner');
bcoin.define('template', './mining/template');

// Net
bcoin.define('net', './net');
bcoin.define('bip150', './net/bip150');
bcoin.define('bip151', './net/bip151');
bcoin.define('bip152', './net/bip152');
bcoin.define('dns', './net/dns');
bcoin.define('packets', './net/packets');
bcoin.define('peer', './net/peer');
bcoin.define('pool', './net/pool');
bcoin.define('tcp', './net/tcp');

// Node
bcoin.define('node', './node');
bcoin.define('config', './node/config');
bcoin.define('fullnode', './node/fullnode');
bcoin.define('logger', './node/logger');
bcoin.define('spvnode', './node/spvnode');

// Primitives
bcoin.define('primitives', './primitives');
bcoin.define('address', './primitives/address');
bcoin.define('block', './primitives/block');
bcoin.define('coin', './primitives/coin');
bcoin.define('headers', './primitives/headers');
bcoin.define('input', './primitives/input');
bcoin.define('invitem', './primitives/invitem');
bcoin.define('keyring', './primitives/keyring');
bcoin.define('merkleblock', './primitives/merkleblock');
bcoin.define('mtx', './primitives/mtx');
bcoin.define('netaddress', './primitives/netaddress');
bcoin.define('outpoint', './primitives/outpoint');
bcoin.define('output', './primitives/output');
bcoin.define('tx', './primitives/tx');

// Protocol
bcoin.define('protocol', './protocol');
bcoin.define('consensus', './protocol/consensus');
bcoin.define('errors', './protocol/errors');
bcoin.define('network', './protocol/network');
bcoin.define('networks', './protocol/networks');
bcoin.define('policy', './protocol/policy');
bcoin.define('timedata', './protocol/timedata');

// Script
bcoin.define('txscript', './script');
bcoin.define('opcode', './script/opcode');
bcoin.define('program', './script/program');
bcoin.define('script', './script/script');
bcoin.define('sigcache', './script/sigcache');
bcoin.define('stack', './script/stack');
bcoin.define('witness', './script/witness');

// Utils
bcoin.define('utils', './utils');
bcoin.define('base32', './utils/base32');
bcoin.define('base58', './utils/base58');
bcoin.define('bloom', './utils/bloom');
bcoin.define('co', './utils/co');
bcoin.define('encoding', './utils/encoding');
bcoin.define('int64', './utils/int64');
bcoin.define('lock', './utils/lock');
bcoin.define('reader', './utils/reader');
bcoin.define('staticwriter', './utils/staticwriter');
bcoin.define('util', './utils/util');
bcoin.define('writer', './utils/writer');

// Wallet
bcoin.define('wallet', './wallet');
bcoin.define('path', './wallet/path');
bcoin.define('walletkey', './wallet/walletkey');
bcoin.define('walletdb', './wallet/walletdb');

// Workers
bcoin.define('workers', './workers');
bcoin.define('workerpool', './workers/workerpool');

// Package Info
bcoin.define('pkg', './pkg');
