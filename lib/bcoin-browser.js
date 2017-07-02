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
  ;
};

/*
 * Expose
 */

// Horrible BIP
bcoin.bip70 = require('./bip70');

// Blockchain
bcoin.blockchain = require('./blockchain');
bcoin.chain = require('./blockchain/chain');
bcoin.chaindb = require('./blockchain/chaindb');
bcoin.chainentry = require('./blockchain/chainentry');

// BTC
bcoin.btc = require('./btc');
bcoin.amount = require('./btc/amount');
bcoin.uri = require('./btc/uri');

// Coins
bcoin.coins = require('./coins');
bcoin.coinview = require('./coins/coinview');

// Crypto
bcoin.crypto = require('./crypto');
bcoin.bn = require('./crypto/bn');
bcoin.secp256k1 = require('./crypto/secp256k1');
bcoin.schnorr = require('./crypto/schnorr');

// DB
bcoin.db = require('./db');
bcoin.ldb = require('./db/ldb');

// HD
bcoin.hd = require('./hd');

// HTTP
bcoin.http = require('./http');
bcoin.rpc = require('./http/rpc');

// Mempool
bcoin.txmempool = require('./mempool');
bcoin.fees = require('./mempool/fees');
bcoin.mempool = require('./mempool/mempool');
bcoin.mempoolentry = require('./mempool/mempoolentry');

// Miner
bcoin.mining = require('./mining');
bcoin.miner = require('./mining/miner');
bcoin.template = require('./mining/template');

// Net
bcoin.net = require('./net');
bcoin.bip150 = require('./net/bip150');
bcoin.bip151 = require('./net/bip151');
bcoin.bip152 = require('./net/bip152');
bcoin.dns = require('./net/dns');
bcoin.packets = require('./net/packets');
bcoin.peer = require('./net/peer');
bcoin.pool = require('./net/pool');
bcoin.tcp = require('./net/tcp');

// Node
bcoin.node = require('./node');
bcoin.config = require('./node/config');
bcoin.fullnode = require('./node/fullnode');
bcoin.logger = require('./node/logger');
bcoin.spvnode = require('./node/spvnode');

// Primitives
bcoin.primitives = require('./primitives');
bcoin.address = require('./primitives/address');
bcoin.block = require('./primitives/block');
bcoin.coin = require('./primitives/coin');
bcoin.headers = require('./primitives/headers');
bcoin.input = require('./primitives/input');
bcoin.invitem = require('./primitives/invitem');
bcoin.keyring = require('./primitives/keyring');
bcoin.merkleblock = require('./primitives/merkleblock');
bcoin.mtx = require('./primitives/mtx');
bcoin.netaddress = require('./primitives/netaddress');
bcoin.outpoint = require('./primitives/outpoint');
bcoin.output = require('./primitives/output');
bcoin.tx = require('./primitives/tx');

// Protocol
bcoin.protocol = require('./protocol');
bcoin.consensus = require('./protocol/consensus');
bcoin.errors = require('./protocol/errors');
bcoin.network = require('./protocol/network');
bcoin.networks = require('./protocol/networks');
bcoin.policy = require('./protocol/policy');
bcoin.timedata = require('./protocol/timedata');

// Script
bcoin.txscript = require('./script');
bcoin.opcode = require('./script/opcode');
bcoin.program = require('./script/program');
bcoin.script = require('./script/script');
bcoin.sigcache = require('./script/sigcache');
bcoin.stack = require('./script/stack');
bcoin.witness = require('./script/witness');

// Utils
bcoin.utils = require('./utils');
bcoin.base32 = require('./utils/base32');
bcoin.base58 = require('./utils/base58');
bcoin.bloom = require('./utils/bloom');
bcoin.co = require('./utils/co');
bcoin.encoding = require('./utils/encoding');
bcoin.int64 = require('./utils/int64');
bcoin.lock = require('./utils/lock');
bcoin.reader = require('./utils/reader');
bcoin.staticwriter = require('./utils/staticwriter');
bcoin.util = require('./utils/util');
bcoin.writer = require('./utils/writer');

// Wallet
bcoin.wallet = require('./wallet');
bcoin.path = require('./wallet/path');
bcoin.walletkey = require('./wallet/walletkey');
bcoin.walletdb = require('./wallet/walletdb');

// Workers
bcoin.workers = require('./workers');
bcoin.workerpool = require('./workers/workerpool');

// Package Info
bcoin.pkg = require('./pkg');

/*
 * Expose Globally
 */

global.bcoin = bcoin;
