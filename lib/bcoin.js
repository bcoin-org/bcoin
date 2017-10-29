/*!
 * bcoin.js - a javascript bitcoin library.
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License).
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

/* eslint prefer-arrow-callback: "off" */

'use strict';

/**
 * A bcoin "environment" which exposes all
 * constructors for primitives, the blockchain,
 * mempool, wallet, etc. It also exposes a
 * global worker pool.
 *
 * @exports bcoin
 * @type {Object}
 */

const bcoin = exports;

/**
 * Define a module for lazy loading.
 * @param {String} name
 * @param {String} path
 */

bcoin.define = function define(name, path) {
  let cache;
  Object.defineProperty(bcoin, name, {
    get() {
      if (!cache)
        cache = require(path);
      return cache;
    }
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

// HD
bcoin.define('hd', './hd');

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
bcoin.define('fullnode', './node/fullnode');
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
bcoin.define('scriptnum', './script/scriptnum');
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
