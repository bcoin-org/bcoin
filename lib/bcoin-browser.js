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

// HD
bcoin.hd = require('./hd');

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
bcoin.packets = require('./net/packets');
bcoin.peer = require('./net/peer');
bcoin.pool = require('./net/pool');

// Node
bcoin.node = require('./node');
bcoin.fullnode = require('./node/fullnode');
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
bcoin.scriptnum = require('./script/scriptnum');
bcoin.sigcache = require('./script/sigcache');
bcoin.stack = require('./script/stack');
bcoin.witness = require('./script/witness');

// Utils
bcoin.utils = require('./utils');
bcoin.co = require('./utils/co');
bcoin.lock = require('./utils/lock');
bcoin.util = require('./utils/util');

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
