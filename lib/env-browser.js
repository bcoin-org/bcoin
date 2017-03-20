/*!
 * env.js - environment for bcoin
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
 * @exports Environment
 * @constructor
 * @property {Function} env - See {@link Environment}.
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

  // BN
  this.bn = require('bn.js');
  this.elliptic = require('elliptic');

  // Horrible BIP
  this.bip70 = require('./bip70');

  // Blockchain
  this.blockchain = require('./blockchain');
  this.chain = require('./blockchain/chain');
  this.chaindb = require('./blockchain/chaindb');
  this.chainentry = require('./blockchain/chainentry');

  // BTC
  this.btc = require('./btc');
  this.amount = require('./btc/amount');
  this.uri = require('./btc/uri');

  // Coins
  this.coins = require('./coins');
  this.coinview = require('./coins/coinview');

  // Crypto
  this.crypto = require('./crypto');
  this.ec = require('./crypto/ec');
  this.pk = require('./crypto/pk');
  this.schnorr = require('./crypto/schnorr');

  // DB
  this.db = require('./db');
  this.ldb = require('./db/ldb');

  // HD
  this.hd = require('./hd/hd');

  // HTTP
  this.http = require('./http');
  this.rpc = require('./http/rpc');

  // Mempool
  this.txmempool = require('./mempool');
  this.fees = require('./mempool/fees');
  this.mempool = require('./mempool/mempool');
  this.mempoolentry = require('./mempool/mempoolentry');

  // Miner
  this.mining = require('./mining');
  this.miner = require('./mining/miner');
  this.template = require('./mining/template');

  // Net
  this.net = require('./net');
  this.bip150 = require('./net/bip150');
  this.bip151 = require('./net/bip151');
  this.bip152 = require('./net/bip152');
  this.dns = require('./net/dns');
  this.packets = require('./net/packets');
  this.peer = require('./net/peer');
  this.pool = require('./net/pool');
  this.tcp = require('./net/tcp');

  // Node
  this.node = require('./node');
  this.config = require('./node/config');
  this.fullnode = require('./node/fullnode');
  this.logger = require('./node/logger');
  this.spvnode = require('./node/spvnode');

  // Primitives
  this.primitives = require('./primitives');
  this.address = require('./primitives/address');
  this.block = require('./primitives/block');
  this.coin = require('./primitives/coin');
  this.headers = require('./primitives/headers');
  this.input = require('./primitives/input');
  this.invitem = require('./primitives/invitem');
  this.keyring = require('./primitives/keyring');
  this.merkleblock = require('./primitives/merkleblock');
  this.mtx = require('./primitives/mtx');
  this.netaddress = require('./primitives/netaddress');
  this.outpoint = require('./primitives/outpoint');
  this.output = require('./primitives/output');
  this.tx = require('./primitives/tx');

  // Protocol
  this.protocol = require('./protocol');
  this.consensus = require('./protocol/consensus');
  this.errors = require('./protocol/errors');
  this.network = require('./protocol/network');
  this.networks = require('./protocol/networks');
  this.policy = require('./protocol/policy');
  this.timedata = require('./protocol/timedata');

  // Script
  this.txscript = require('./script');
  this.opcode = require('./script/opcode');
  this.program = require('./script/program');
  this.script = require('./script/script');
  this.sigcache = require('./script/sigcache');
  this.stack = require('./script/stack');
  this.witness = require('./script/witness');

  // Utils
  this.utils = require('./utils');
  this.base32 = require('./utils/base32');
  this.base58 = require('./utils/base58');
  this.bloom = require('./utils/bloom');
  this.co = require('./utils/co');
  this.encoding = require('./utils/encoding');
  this.lock = require('./utils/lock');
  this.reader = require('./utils/reader');
  this.staticwriter = require('./utils/staticwriter');
  this.util = require('./utils/util');
  this.writer = require('./utils/writer');

  // Wallet
  this.wallet = require('./wallet');
  this.path = require('./wallet/path');
  this.walletkey = require('./wallet/walletkey');
  this.walletdb = require('./wallet/walletdb');
  this.walletplugin = require('./wallet/plugin');

  // Workers
  this.workers = require('./workers');
  this.workerpool = require('./workers/workerpool');
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
