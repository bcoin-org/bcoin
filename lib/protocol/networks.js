/*!
 * network.js - bitcoin networks for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

/**
 * @module protocol/networks
 */

var BN = require('../crypto/bn');

var network = exports;
var main, testnet, regtest, simnet, ltc;

/**
 * Network type list.
 * @memberof module:protocol/networks
 * @const {String[]}
 * @default
 */

network.types = ['main', 'testnet', 'regtest', 'simnet'];

/**
 * Mainnet
 * @static
 * @lends module:protocol/networks
 * @type {Object}
 */

main = network.main = {};

/**
 * Symbolic network type.
 * @const {String}
 * @default
 */

main.type = 'main';

/**
 * Default DNS seeds.
 * @const {String[]}
 * @default
 */

main.seeds = [
  'seed-a.litecoin.loshan.co.uk',
  'dnsseed.thrasher.io',
  'dnsseed.litecointools.com',
  'dnsseed.litecoinpool.org',
  'dnsseed.koin-project.com'
];

/**
 * Packet magic number.
 * @const {Number}
 * @default
 */

main.magic = 0xdbb6c0fb;

/**
 * Default network port.
 * @const {Number}
 * @default
 */

main.port = 9333;

/**
 * Checkpoint block list.
 * @const {Object}
 */

main.checkpointMap = {
  1500: '67299ab5a20244afc95e8376d48b5fe4545ad055a707a7cf88d25d9565291a84',
  4032: '4608cfd9e3d75f9687a935fd6ae2805b720335ce05595ef00efc9871420ee99c',
  8064: '700d4394a67d98b3fc29b7f0efeeb9baa4b8400c151f6510f29051fc534398eb',
  16128: '3d15cd1c2ae103ec4b7acd9d4d1ddc6fb66c0e9b1d9f80afa6f9b75918df2e60',
  23420: '07b501510bce8f974e87ec30258fa57d54fea9c30aa9b2d20bfd1aa89cdf0fd8',
  50000: 'a6207ad0713e2b2b88323a4fdb2a6727c11904cc2d01a575f0689b02eb37dc69',
  80000: '0ae9b2cd2e186748cbbe8c6ab420f9a85599a864c7493f5000a376f6027ccb4f',
  120000: '3161ac52357a6a021b12e7e9ce298e9ec88e82325f15f0a7daf6054f92269dbd',
  161500: '43ff718479f7bb8d41b8283b12914902dc1cba777c225cf7b44b4f478098e8db',
  179620: '09f7b9782b0ba55883b2dca7e969fa2fbed70f6e448ed12604c00a995cc6d92a',
  240000: 'aa885055a13e2eab6e4e0c59c439db739c4cf23676ee17a27c15c2b4c4d14071',
  383640: '64f3c626f1c396a090057d4be94ba32751a310f1b35ec6af5b21a994f009682b',
  409004: 'a3085935f1b439cfe9770edcfb67b682d974ad95931d6108faf1d963d6187548',
  456000: '0420375624e31b407dac0105a4a64ce397f822be060d9387d46c36c61cf734bf',
  638902: '384fc7ae3bc5ec5cc49ccd3d95fc9a81a5f3fc758c9ae28dd263ece856862315',
  721000: 'e540989a758adc4116743ee6a235b2ea14b7759dd93b46e27894dfe14d7b8a19'
};

/**
 * Last checkpoint height.
 * @const {Number}
 * @default
 */

main.lastCheckpoint = 721000;

/**
 * @const {Number}
 * @default
 */

main.halvingInterval = 840000;

/**
 * Genesis block header.
 * @const {NakedBlock}
 */

main.genesis = {
  version: 1,
  hash: 'e2bf047e7e5a191aa4ef34d314979dc9986e0f19251edaba5940fd1fe365a712',
  prevBlock: '0000000000000000000000000000000000000000000000000000000000000000',
  merkleRoot: 'd9ced4ed1130f7b7faad9be25323ffafa33232a17c3edf6cfd97bee6bafbdd97',
  ts: 1231006505,
  bits: 486604799,
  nonce: 2083236893,
  height: 0
};

/**
 * The network's genesis block in a hex string.
 * @const {String}
 */

main.genesisBlock =
  '0100000000000000000000000000000000000000000000000000000000000000000000'
  + '00d9ced4ed1130f7b7faad9be25323ffafa33232a17c3edf6cfd97bee6bafbdd97b9aa'
  + '8e4ef0ff0f1ecd513f7c01010000000100000000000000000000000000000000000000'
  + '00000000000000000000000000ffffffff4804ffff001d0104404e592054696d657320'
  + '30352f4f63742f32303131205374657665204a6f62732c204170706c65e28099732056'
  + '6973696f6e6172792c2044696573206174203536ffffffff0100f2052a010000004341'
  + '040184710fa689ad5023690c80f3a49c8f13f8d45b8c857fbcbc8bc4a8e4d3eb4b10f4'
  + 'd4604fa08dce601aaf0f470216fe1b51850b4acf21b179c45070ac7b03a9ac00000000';

/**
 * POW-related constants.
 * @enum {Number}
 * @default
 */

main.pow = {
  /**
   * Default target.
   * @const {BN}
   */

  limit: new BN(
    '00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
    'hex'
  ),

  /**
   * Compact pow limit.
   * @const {Number}
   * @default
   */

  bits: 504365055,

  /**
   * Minimum chainwork for best chain.
   * @const {BN}
   */

  chainwork: new BN(
    '000000000000000000000000000000000000000000000005c13f99f6d0b1a908',
    'hex'
  ),

  /**
   * Desired retarget period in seconds.
   * @const {Number}
   * @default
   */

  targetTimespan: 3.5 * 24 * 60 * 60,

  /**
   * Average block time.
   * @const {Number}
   * @default
   */

  targetSpacing: 2.5 * 60,

  /**
   * Retarget interval in blocks.
   * @const {Number}
   * @default
   */

  retargetInterval: 2016,

  /**
   * Whether to reset target if a block
   * has not been mined recently.
   * @const {Boolean}
   * @default
   */

  targetReset: false,

  /**
   * Do not allow retargetting.
   * @const {Boolean}
   * @default
   */

  noRetargeting: false
};

/**
 * Block constants.
 * @enum {Number}
 * @default
 */

main.block = {
  /**
   * Height at which bip34 was activated.
   * Used for avoiding bip30 checks.
   */

  bip34height: 710000,

  /**
   * Hash of the block that activated bip34.
   */

  bip34hash: 'cf519deb9a32b4c72612ff0c42bf3a04f262fa41d4c8a7d58e763aa804d209fa',

  /**
   * Height at which bip65 was activated.
   */

  bip65height: 916185,

  /**
   * Hash of the block that activated bip65.
   */

  bip65hash: 'a311c3a90d1d940a114964f03c80be99242b25ddb1ccf965931de4372078a9ed',

  /**
   * Height at which bip66 was activated.
   */

  bip66height: 811252,

  /**
   * Hash of the block that activated bip66.
   */

  bip66hash: '29b63e43197b9a0a45570e83880c298a41318086143801c987d65c74181387fb',

  /**
   * Safe height to start pruning.
   */

  pruneAfterHeight: 1000,

  /**
   * Safe number of blocks to keep.
   */

  keepBlocks: 288,

  /**
   * Age used for the time delta to
   * determine whether the chain is synced.
   */

  maxTipAge: 24 * 60 * 60,

  /**
   * Height at which block processing is
   * slow enough that we can output
   * logs without spamming.
   */

  slowHeight: 900000
};

/**
 * Map of historical blocks which create duplicate transactions hashes.
 * @see https://github.com/bitcoin/bips/blob/master/bip-0030.mediawiki
 * @const {Object}
 * @default
 */

main.bip30 = {};

/**
 * For versionbits.
 * @const {Number}
 * @default
 */

main.activationThreshold = 6048; // 95% of 2016

/**
 * Confirmation window for versionbits.
 * @const {Number}
 * @default
 */

main.minerWindow = 8064; // nPowTargetTimespan / nPowTargetSpacing

/**
 * Deployments for versionbits.
 * @const {Object}
 * @default
 */

main.deployments = {
  testdummy: {
    name: 'testdummy',
    bit: 28,
    startTime: 1199145601, // January 1, 2008
    timeout: 1230767999, // December 31, 2008
    force: true
  },
  csv: {
    name: 'csv',
    bit: 0,
    startTime: 1485561600, // January 28, 2017
    timeout: 1517356801, // January 31st, 2018
    force: true
  },
  segwit: {
    name: 'segwit',
    bit: 1,
    startTime: 1485561600, // January 28, 2017
    timeout: 1517356801, // January 31st, 2018
    force: false
  }
};

/**
 * Deployments for versionbits (array form, sorted).
 * @const {Array}
 * @default
 */

main.deploys = [
  main.deployments.csv,
  main.deployments.segwit,
  main.deployments.testdummy
];

/**
 * Key prefixes.
 * @enum {Number}
 * @default
 */

main.keyPrefix = {
  privkey: 0xb0,
  xpubkey: 0x0488b21e,
  xprivkey: 0x0488ade4,
  xprivkey58: 'xprv',
  xpubkey58: 'xpub',
  coinType: 0
};

/**
 * {@link Address} prefixes.
 * @enum {Number}
 */

main.addressPrefix = {
  pubkeyhash: 0x30,
  scripthash: 0x32,
  witnesspubkeyhash: 0x06,
  witnessscripthash: 0x0a,
  bech32: 'lc'
};

/**
 * Default value for whether the mempool
 * accepts non-standard transactions.
 * @const {Boolean}
 * @default
 */

main.requireStandard = true;

/**
 * Default http port.
 * @const {Number}
 * @default
 */

main.rpcPort = 9332;

/**
 * Default min relay rate.
 * @const {Rate}
 * @default
 */

main.minRelay = 1000;

/**
 * Default normal relay rate.
 * @const {Rate}
 * @default
 */

main.feeRate = 100000;

/**
 * Maximum normal relay rate.
 * @const {Rate}
 * @default
 */

main.maxFeeRate = 400000;

/**
 * Whether to allow self-connection.
 * @const {Boolean}
 */

main.selfConnect = false;

/**
 * Whether to request mempool on sync.
 * @const {Boolean}
 */

main.requestMempool = false;

/*
 * Testnet (v3)
 * https://en.bitcoin.it/wiki/Testnet
 */

testnet = network.testnet = {};

testnet.type = 'testnet';

testnet.seeds = [
  'testnet-seed.litecointools.com',
  'seed-b.litecoin.loshan.co.uk',
  'dnsseed-testnet.thrasher.io'
];

testnet.magic = 0xf1c8d2fd;

testnet.port = 19335;

testnet.checkpointMap = {
  2056: '8932a8789c96c516d8a1080a29c7e7e387d2397a83864f9adcaf97ba318a7417',
};

testnet.lastCheckpoint = 2056;

testnet.halvingInterval = 840000;

testnet.genesis = {
  version: 1,
  hash: 'a0293e4eeb3da6e6f56f81ed595f57880d1a21569e13eefdd951284b5a626649',
  prevBlock: '0000000000000000000000000000000000000000000000000000000000000000',
  merkleRoot: 'd9ced4ed1130f7b7faad9be25323ffafa33232a17c3edf6cfd97bee6bafbdd97',
  ts: 1486949366,
  bits: 504365040,
  nonce: 293345,
  height: 0
};

testnet.genesisBlock =
  '010000000000000000000000000000000000000000000000000000000000000000000'
  + '000d9ced4ed1130f7b7faad9be25323ffafa33232a17c3edf6cfd97bee6bafbdd97f6'
  + '0ba158f0ff0f1ee179040001010000000100000000000000000000000000000000000'
  + '00000000000000000000000000000ffffffff4804ffff001d0104404e592054696d65'
  + '732030352f4f63742f32303131205374657665204a6f62732c204170706c65e280997'
  + '320566973696f6e6172792c2044696573206174203536ffffffff0100f2052a010000'
  + '004341040184710fa689ad5023690c80f3a49c8f13f8d45b8c857fbcbc8bc4a8e4d3e'
  + 'b4b10f4d4604fa08dce601aaf0f470216fe1b51850b4acf21b179c45070ac7b03a9ac'
  + '00000000';

testnet.pow = {
  limit: new BN(
    '00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
    'hex'
  ),
  bits: 504365055,
  chainwork: new BN(
    '00000000000000000000000000000000000000000000000000000000872d04d7',
    'hex'
  ),
  targetTimespan: 3.5 * 24 * 60 * 60,
  targetSpacing: 2.5 * 60,
  retargetInterval: 2016,
  targetReset: true,
  noRetargeting: false
};

testnet.block = {
  bip34height: 0xffffffff,
  bip34hash: null,
  bip65height: 52,
  bip65hash: 'b8b13c6d43c62424d7d4aa8aa96029780954c33eb0081743beaabc7f1a385bd9',
  bip66height: 52,
  bip66hash: 'b8b13c6d43c62424d7d4aa8aa96029780954c33eb0081743beaabc7f1a385bd9',
  pruneAfterHeight: 1000,
  keepBlocks: 10000,
  maxTipAge: 24 * 60 * 60,
  slowHeight: 950000
};

testnet.bip30 = {};

testnet.activationThreshold = 1512; // 75% for testchains

testnet.minerWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing

testnet.deployments = {
  testdummy: {
    name: 'testdummy',
    bit: 28,
    startTime: 1199145601, // January 1, 2008
    timeout: 1230767999, // December 31, 2008
    force: true
  },
  csv: {
    name: 'csv',
    bit: 0,
    startTime: 1483228800, // January 1, 2017
    timeout: 1517356801, // January 31st, 2018
    force: true
  },
  segwit: {
    name: 'segwit',
    bit: 1,
    startTime: 1483228800, // January 1, 2017
    timeout: 1517356801, // January 31st, 2018
    force: false
  }
};

testnet.deploys = [
  testnet.deployments.csv,
  testnet.deployments.segwit,
  testnet.deployments.testdummy
];

testnet.keyPrefix = {
  privkey: 0xef,
  xpubkey: 0x043587cf,
  xprivkey: 0x04358394,
  xpubkey58: 'tpub',
  xprivkey58: 'tprv',
  coinType: 1
};

testnet.addressPrefix = {
  pubkeyhash: 0x6f,
  scripthash: 0xc4,
  witnesspubkeyhash: 0x03,
  witnessscripthash: 0x28,
  bech32: 'tb'
};

testnet.requireStandard = false;

testnet.rpcPort = 19336;

testnet.minRelay = 1000;

testnet.feeRate = 20000;

testnet.maxFeeRate = 60000;

testnet.selfConnect = false;

testnet.requestMempool = false;

/*
 * Regtest
 */

regtest = network.regtest = {};

regtest.type = 'regtest';

regtest.seeds = [
  '127.0.0.1'
];

regtest.magic = 0xdab5bffa;

regtest.port = 19444;

regtest.checkpointMap = {};
regtest.lastCheckpoint = 0;

regtest.halvingInterval = 150;

regtest.genesis = {
  version: 1,
  hash: 'f916c456fc51df627885d7d674ed02dc88a225adb3f02ad13eb4938ff3270853',
  prevBlock: '0000000000000000000000000000000000000000000000000000000000000000',
  merkleRoot: 'd9ced4ed1130f7b7faad9be25323ffafa33232a17c3edf6cfd97bee6bafbdd97',
  ts: 1296688602,
  bits: 545259519,
  nonce: 2,
  height: 0
};

regtest.genesisBlock =
  '010000000000000000000000000000000000000000000000000000000000000000000'
  + '000d9ced4ed1130f7b7faad9be25323ffafa33232a17c3edf6cfd97bee6bafbdd97da'
  + 'e5494dffff7f200000000001010000000100000000000000000000000000000000000'
  + '00000000000000000000000000000ffffffff4804ffff001d0104404e592054696d65'
  + '732030352f4f63742f32303131205374657665204a6f62732c204170706c65e280997'
  + '320566973696f6e6172792c2044696573206174203536ffffffff0100f2052a010000'
  + '004341040184710fa689ad5023690c80f3a49c8f13f8d45b8c857fbcbc8bc4a8e4d3e'
  + 'b4b10f4d4604fa08dce601aaf0f470216fe1b51850b4acf21b179c45070ac7b03a9ac'
  + '00000000';

regtest.pow = {
  limit: new BN(
    '7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
    'hex'
  ),
  bits: 545259519,
  chainwork: new BN(
    '0000000000000000000000000000000000000000000000000000000000000002',
    'hex'
  ),
  targetTimespan: 3.5 * 24 * 60 * 60,
  targetSpacing: 2.5 * 60,
  retargetInterval: 2016,
  targetReset: true,
  noRetargeting: true
};

regtest.block = {
  bip34height: 0xffffffff,
  bip34hash: null,
  bip65height: 1351,
  bip65hash: null,
  bip66height: 1251,
  bip66hash: null,
  pruneAfterHeight: 1000,
  keepBlocks: 10000,
  maxTipAge: 0xffffffff,
  slowHeight: 0
};

regtest.bip30 = {};

regtest.activationThreshold = 108; // 75% for testchains

regtest.minerWindow = 144; // Faster than normal for regtest (144 instead of 2016)

regtest.deployments = {
  testdummy: {
    name: 'testdummy',
    bit: 28,
    startTime: 0,
    timeout: 0xffffffff,
    force: true
  },
  csv: {
    name: 'csv',
    bit: 0,
    startTime: 0,
    timeout: 0xffffffff,
    force: true
  },
  segwit: {
    name: 'segwit',
    bit: 1,
    startTime: 0,
    timeout: 0xffffffff,
    force: false
  }
};

regtest.deploys = [
  regtest.deployments.csv,
  regtest.deployments.segwit,
  regtest.deployments.testdummy
];

regtest.keyPrefix = {
  privkey: 0x5a,
  xpubkey: 0xeab4fa05,
  xprivkey: 0xeab404c7,
  xpubkey58: 'rpub',
  xprivkey58: 'rprv',
  coinType: 1
};

regtest.addressPrefix = {
  pubkeyhash: 0x3c,
  scripthash: 0x26,
  witnesspubkeyhash: 0x7a,
  witnessscripthash: 0x14,
  bech32: 'rb'
};

regtest.requireStandard = false;

regtest.rpcPort = 19445;

regtest.minRelay = 1000;

regtest.feeRate = 20000;

regtest.maxFeeRate = 60000;

regtest.selfConnect = true;

regtest.requestMempool = true;

/*
 * Simnet (btcd)
 */

simnet = network.simnet = {};

simnet.type = 'simnet';

simnet.seeds = [
  '127.0.0.1'
];

simnet.magic = 0x12141c16;

simnet.port = 18555;

simnet.checkpointMap = {};

simnet.lastCheckpoint = 0;

simnet.halvingInterval = 210000;

simnet.genesis = {
  version: 1,
  hash: 'f67ad7695d9b662a72ff3d8edbbb2de0bfa67b13974bb9910d116d5cbd863e68',
  prevBlock: '0000000000000000000000000000000000000000000000000000000000000000',
  merkleRoot: '3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a',
  ts: 1401292357,
  bits: 545259519,
  nonce: 2,
  height: 0
};

simnet.genesisBlock =
  '0100000000000000000000000000000000000000000000000000000000000000000000'
  + '003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a4506'
  + '8653ffff7f200200000001010000000100000000000000000000000000000000000000'
  + '00000000000000000000000000ffffffff4d04ffff001d0104455468652054696d6573'
  + '2030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66'
  + '207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01'
  + '000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f'
  + '61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f'
  + 'ac00000000';

simnet.pow = {
  limit: new BN(
    // High target of 0x207fffff (545259519)
    '7fffff0000000000000000000000000000000000000000000000000000000000',
    'hex'
  ),
  bits: 545259519,
  chainwork: new BN(
    '0000000000000000000000000000000000000000000000000000000000000002',
    'hex'
  ),
  targetTimespan: 3.5 * 24 * 60 * 60,
  targetSpacing: 2.5 * 60,
  retargetInterval: 2016,
  targetReset: true,
  noRetargeting: false
};

simnet.block = {
  bip34height: 0,
  bip34hash: 'f67ad7695d9b662a72ff3d8edbbb2de0bfa67b13974bb9910d116d5cbd863e68',
  bip65height: 0,
  bip65hash: 'f67ad7695d9b662a72ff3d8edbbb2de0bfa67b13974bb9910d116d5cbd863e68',
  bip66height: 0,
  bip66hash: 'f67ad7695d9b662a72ff3d8edbbb2de0bfa67b13974bb9910d116d5cbd863e68',
  pruneAfterHeight: 1000,
  keepBlocks: 10000,
  maxTipAge: 0xffffffff,
  slowHeight: 0
};

simnet.bip30 = {};

simnet.activationThreshold = 75; // 75% for testchains

simnet.minerWindow = 100; // nPowTargetTimespan / nPowTargetSpacing

simnet.deployments = {
  testdummy: {
    name: 'testdummy',
    bit: 28,
    startTime: 1199145601, // January 1, 2008
    timeout: 1230767999, // December 31, 2008
    force: true
  },
  csv: {
    name: 'csv',
    bit: 0,
    startTime: 0, // March 1st, 2016
    timeout: 0xffffffff, // May 1st, 2017
    force: true
  },
  segwit: {
    name: 'segwit',
    bit: 1,
    startTime: 0, // May 1st 2016
    timeout: 0xffffffff, // May 1st 2017
    force: false
  }
};

simnet.deploys = [
  simnet.deployments.csv,
  simnet.deployments.segwit,
  simnet.deployments.testdummy
];

simnet.keyPrefix = {
  privkey: 0x64,
  xpubkey: 0x0420bd3a,
  xprivkey: 0x0420b900,
  xpubkey58: 'spub',
  xprivkey58: 'sprv',
  coinType: 115
};

simnet.addressPrefix = {
  pubkeyhash: 0x3f,
  scripthash: 0x7b,
  witnesspubkeyhash: 0x19,
  witnessscripthash: 0x28,
  bech32: 'sc'
};

simnet.requireStandard = false;

simnet.rpcPort = 18556;

simnet.minRelay = 1000;

simnet.feeRate = 20000;

simnet.maxFeeRate = 60000;

simnet.selfConnect = false;

simnet.requestMempool = false;
