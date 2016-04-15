/*!
 * network.js - bitcoin networks for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/indutny/bcoin
 */

var bn = require('bn.js');
var utils = require('../utils');
var assert = utils.assert;

/**
 * @module network
 */

var network = exports;
var main, testnet, regtest, segnet3, segnet4;

/**
 * Network type list.
 * @memberof module:network
 * @const {String[]}
 * @default
 */

network.types = ['main', 'testnet', 'regtest', 'segnet3', 'segnet4'];

/**
 * Get a new network object by type.
 * @memberof module:network
 * @param {String} type - Network type.
 * @returns {Object}
 */

network.get = function get(type) {
  assert(network[type], 'Network not found.');
  return utils.merge({}, network, network[type]);
};

/**
 * Main
 * @static
 * @lends module:network
 * @type {Object}
 */

main = network.main = {};

/**
 * Key prefixes.
 * @enum {Number}
 * @default
 */

main.prefixes = {
  privkey: 128,
  xpubkey: 0x0488b21e,
  xprivkey: 0x0488ade4
};

/**
 * {@link Base58Address} constants.
 * @const {Object}
 */

main.address = {
  /**
   * {@link Base58Address} prefixes.
   * @enum {Number}
   * @default
   */
  prefixes: {
    pubkeyhash: 0,
    scripthash: 5,
    witnesspubkeyhash: 6,
    witnessscripthash: 10
  },
  /**
   * {@link Base58Address} versions.
   * @enum {Number}
   * @default
   */
  versions: {
    witnesspubkeyhash: 0,
    witnessscripthash: 0
  }
};

/**
 * {@link Base58Address} prefixes by value.
 * @type {RevMap}
 * @default
 */

main.address.prefixesByVal = utils.revMap(main.address.prefixes);

/**
 * {@link Base58Address} versions by value.
 * @type {RevMap}
 * @default
 */

main.address.versionsByVal = utils.revMap(main.address.versions);

/**
 * Symbolic network type.
 * @const {String}
 * @default
 */

main.type = 'main';

/**
 * Default seeds.
 * @const {String[]}
 * @default
 */

main.seeds = [
  'seed.bitcoin.sipa.be', // Pieter Wuille
  'dnsseed.bluematt.me', // Matt Corallo
  'dnsseed.bitcoin.dashjr.org', // Luke Dashjr
  'seed.bitcoinstats.com', // Christian Decker
  'bitseed.xf2.org', // Jeff Garzik
  'seed.bitcoin.jonasschnelli.ch' // Jonas Schnelli
];

/**
 * Default network port.
 * @const {Number}
 * @default
 */

main.port = 8333;

/**
 * Public key for verifying alert packets.
 * @const {Buffer}
 */

main.alertKey = new Buffer(''
  + '04fc9702847840aaf195de8442ebecedf5b095c'
  + 'dbb9bc716bda9110971b28a49e0ead8564ff0db'
  + '22209e0374782c093bb899692d524e9d6a6956e'
  + '7c5ecbcd68284',
  'hex');

/**
 * Checkpoint block list.
 * @const {Object}
 */

main.checkpoints = [
  { height: 11111,  hash: '0000000069e244f73d78e8fd29ba2fd2ed618bd6fa2ee92559f542fdb26e7c1d' },
  { height: 33333,  hash: '000000002dd5588a74784eaa7ab0507a18ad16a236e7b1ce69f00d7ddfb5d0a6' },
  { height: 74000,  hash: '0000000000573993a3c9e41ce34471c079dcf5f52a0e824a81e7f953b8661a20' },
  { height: 105000, hash: '00000000000291ce28027faea320c8d2b054b2e0fe44a773f3eefb151d6bdc97' },
  { height: 134444, hash: '00000000000005b12ffd4cd315cd34ffd4a594f430ac814c91184a0d42d2b0fe' },
  { height: 168000, hash: '000000000000099e61ea72015e79632f216fe6cb33d7899acb35b75c8303b763' },
  { height: 193000, hash: '000000000000059f452a5f7340de6682a977387c17010ff6e6c3bd83ca8b1317' },
  { height: 210000, hash: '000000000000048b95347e83192f69cf0366076336c639f9b7228e9ba171342e' },
  { height: 216116, hash: '00000000000001b4f4b433e81ee46494af945cf96014816a4e2370f11b23df4e' },
  { height: 225430, hash: '00000000000001c108384350f74090433e7fcf79a606b8e797f065b130575932' },
  { height: 250000, hash: '000000000000003887df1f29024b06fc2200b55f8af8f35453d7be294df2d214' },
  { height: 279000, hash: '0000000000000001ae8c72a0b0c301f67e3afca10e819efa9041e458e9bd7e40' },
  { height: 295000, hash: '00000000000000004d9b4ef50f0f9d686fd69db2e03af35a100370c64632a983' }
];

main.checkpoints = main.checkpoints.reduce(function(out, block) {
  out[block.height] = utils.revHex(block.hash);
  return block;
}, {});

main.checkpoints.tsLastCheckpoint = 1397080064;
main.checkpoints.txsLastCheckpoint = 36544669;
main.checkpoints.txsPerDay = 60000.0;
main.checkpoints.lastHeight = 295000;

/**
 * @const {Number}
 * @default
 */

main.halvingInterval = 210000;

/**
 * Genesis block header.
 * @const {NakedBlock}
 */

main.genesis = {
  version: 1,
  hash: utils.revHex(
    '000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f'
  ),
  prevBlock: '0000000000000000000000000000000000000000000000000000000000000000',
  merkleRoot: utils.revHex(
    '4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b'
  ),
  ts: 1231006505,
  bits: 0x1d00ffff,
  nonce: 2083236893
};

/**
 * Packet magic number.
 * @const {Number}
 * @default
 */

main.magic = 0xd9b4bef9;

/**
 * Default target.
 * @const {Buffer}
 */

main.powLimit = new bn(
  '00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
  'hex'
);

/**
 * Default retarget interval.
 * @const {Number}
 * @default
 */

main.powTargetTimespan = 14 * 24 * 60 * 60; // two weeks

/**
 * Average block time.
 * @const {Number}
 * @default
 */

main.powTargetSpacing = 10 * 60;

/**
 * Retarget interval in blocks.
 * @const {Number}
 * @default
 */

main.powDiffInterval = main.powTargetTimespan / main.powTargetSpacing | 0;

/**
 * @const {Boolean}
 * @default
 */

main.powAllowMinDifficultyBlocks = false;

/**
 * @const {Boolean}
 * @default
 */

main.powNoRetargeting = false;

/**
 * Block constants.
 * @enum {Number}
 * @default
 */

main.block = {
  majorityEnforceUpgrade: 750,
  majorityRejectOutdated: 950,
  majorityWindow: 1000,
  bip34height: 227931
};

/**
 * Height at which segwit is activated (segnet3).
 * @const {Number}
 * @default
 */

main.segwitHeight = 2000000000;

/**
 * The network's genesis block in a hex string.
 * @const {String}
 */

main.genesisBlock = '0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c0101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000';

/**
 * For versionbits.
 * @const {Number}
 * @default
 */

main.ruleChangeActivationThreshold = 1916; // 95% of 2016

/**
 * Confirmation window for versionbits.
 * @const {Number}
 * @default
 */

main.minerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing

/**
 * Deployments for versionbits.
 * @const {Object}
 * @default
 */

main.deployments = {
  csv: {
    bit: 0,
    startTime: 1459468800, // April 1st, 2016
    timeout: 1491004800 // April 1st, 2017
  }
  // bip109: {
  //   bit: 4,
  //   startTime: 1453939200, // Jan 28th, 2016
  //   timeout: 1514764800 // Jan 1st, 2018
  // }
};

/**
 * Expose the network height (will be updated the Chain).
 * The only global variable currently in BCoin.
 * @const {Number}
 */

main.height = -1;

/*
 * Testnet (v3)
 * https://en.bitcoin.it/wiki/Testnet
 */

testnet = network.testnet = {};

testnet.type = 'testnet';

testnet.prefixes = {
  privkey: 239,
  xpubkey: 0x043587cf,
  xprivkey: 0x04358394
};

testnet.address = {
  prefixes: {
    pubkeyhash: 111,
    scripthash: 196,
    witnesspubkeyhash: 3,
    witnessscripthash: 40
  },
  versions: {
    witnesspubkeyhash: 0,
    witnessscripthash: 0
  }
};

testnet.address.prefixesByVal = utils.revMap(testnet.address.prefixes);
testnet.address.versionsByVal = utils.revMap(testnet.address.versions);

testnet.seeds = [
 'testnet-seed.alexykot.me',
 'testnet-seed.bitcoin.petertodd.org',
 'testnet-seed.bluematt.me',
 'testnet-seed.bitcoin.schildbach.de'
];

testnet.port = 18333;

testnet.alertKey = new Buffer(''
  + '04302390343f91cc401d56d68b123028bf52e5f'
  + 'ca1939df127f63c6467cdf9c8e2c14b61104cf8'
  + '17d0b780da337893ecc4aaff1309e536162dabb'
  + 'db45200ca2b0a',
  'hex');

testnet.checkpoints = [
  { height: 546, hash: '000000002a936ca763904c3c35fce2f3556c559c0214345d31b1bcebf76acb70' }
];

testnet.checkpoints = testnet.checkpoints.reduce(function(out, block) {
  out[block.height] = utils.revHex(block.hash);
  return block;
}, {});

testnet.checkpoints.tsLastCheckpoint = 1338180505;
testnet.checkpoints.txsLastCheckpoint = 16341;
testnet.checkpoints.txsPerDay = 300;
testnet.checkpoints.lastHeight = 546;

testnet.halvingInterval = 210000;

// http://blockexplorer.com/testnet/b/0
// http://blockexplorer.com/testnet/rawblock/000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943
testnet.genesis =  {
  version: 1,
  hash: utils.revHex(
    '000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943'
  ),
  prevBlock: '0000000000000000000000000000000000000000000000000000000000000000',
  merkleRoot: utils.revHex(
    '4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b'
  ),
  ts: 1296688602,
  bits: 0x1d00ffff,
  nonce: 414098458
};

testnet.magic = 0x0709110b;

testnet.powLimit = new bn(
  '00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
  'hex'
);
testnet.powTargetTimespan = 14 * 24 * 60 * 60; // two weeks
testnet.powTargetSpacing = 10 * 60;
testnet.powDiffInterval = testnet.powTargetTimespan / testnet.powTargetSpacing | 0;
testnet.powAllowMinDifficultyBlocks = true;
testnet.powNoRetargeting = false;

testnet.block = {
  majorityEnforceUpgrade: 51,
  majorityRejectOutdated: 75,
  majorityWindow: 100,
  bip34height: 21111
};

testnet.segwitHeight = 2000000000;

testnet.genesisBlock = '0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4adae5494dffff001d1aa4ae180101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000';

testnet.ruleChangeActivationThreshold = 1512; // 75% for testchains
testnet.minerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
testnet.deployments = {
  csv: {
    bit: 0,
    startTime: 1459468800,
    timeout: 1491004800
  }
};

testnet.height = -1;

/*
 * Regtest
 */

regtest = network.regtest = {};

regtest.type = 'regtest';

regtest.prefixes = {
  privkey: 239,
  xpubkey: 0x043587cf,
  xprivkey: 0x04358394
};

regtest.address = {
  prefixes: {
    pubkeyhash: 111,
    scripthash: 196,
    witnesspubkeyhash: 3,
    witnessscripthash: 40
  },
  versions: {
    witnesspubkeyhash: 0,
    witnessscripthash: 0
  }
};

regtest.address.prefixesByVal = utils.revMap(regtest.address.prefixes);
regtest.address.versionsByVal = utils.revMap(regtest.address.versions);

regtest.seeds = [
  '127.0.0.1'
];

regtest.port = 18444;

// regtest._alertKey = bcoin.ec.generate();
// regtest.alertKey = regtest._alertKey.getPublic(true, 'array');

regtest.checkpoints = {};
regtest.checkpoints.tsLastCheckpoint = 0;
regtest.checkpoints.txsLastCheckpoint = 0;
regtest.checkpoints.txsPerDay = 300;
regtest.checkpoints.lastHeight = 0;

regtest.halvingInterval = 150;

regtest.genesis =  {
  version: 1,
  hash: utils.revHex(
    '0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206'
  ),
  prevBlock: '0000000000000000000000000000000000000000000000000000000000000000',
  merkleRoot: utils.revHex(
    '4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b'
  ),
  ts: 1296688602,
  bits: 0x207fffff,
  nonce: 2
};

regtest.magic = 0xdab5bffa;

regtest.powLimit = new bn(
  '7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
  'hex'
);
regtest.powTargetTimespan = 14 * 24 * 60 * 60; // two weeks
regtest.powTargetSpacing = 10 * 60;
regtest.powDiffInterval = regtest.powTargetTimespan / regtest.powTargetSpacing | 0;
regtest.powAllowMinDifficultyBlocks = true;
regtest.powNoRetargeting = true;

regtest.block = {
  majorityEnforceUpgrade: 750,
  majorityRejectOutdated: 950,
  majorityWindow: 1000,
  bip34height: -1
};

regtest.segwitHeight = 0;

regtest.genesisBlock = '0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4adae5494dffff7f20020000000101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000';

regtest.ruleChangeActivationThreshold = 108; // 75% for testchains
regtest.minerConfirmationWindow = 144; // Faster than normal for regtest (144 instead of 2016)
regtest.deployments = {
  csv: {
    bit: 0,
    startTime: 0,
    timeout: 999999999999
  }
};

regtest.height = -1;

/*
 * segnet3
 */

segnet3 = network.segnet3 = {};

segnet3.type = 'segnet3';

segnet3.prefixes = {
  privkey: 158,
  xpubkey: 0x053587cf,
  xprivkey: 0x05358394
};

segnet3.address = {
  prefixes: {
    pubkeyhash: 30,
    scripthash: 50,
    witnesspubkeyhash: 3,
    witnessscripthash: 40
  },
  versions: {
    witnesspubkeyhash: 0,
    witnessscripthash: 0
  }
};

segnet3.address.prefixesByVal = utils.revMap(segnet3.address.prefixes);
segnet3.address.versionsByVal = utils.revMap(segnet3.address.versions);

segnet3.seeds = [
  '104.243.38.34',
  '104.155.1.158',
  '119.246.245.241',
  '46.101.235.82'
];

segnet3.port = 28333;

segnet3.alertKey = new Buffer(''
  + '04302390343f91cc401d56d68b123028bf52e5f'
  + 'ca1939df127f63c6467cdf9c8e2c14b61104cf8'
  + '17d0b780da337893ecc4aaff1309e536162dabb'
  + 'db45200ca2b0a',
  'hex');

segnet3.checkpoints = [];

segnet3.checkpoints = segnet3.checkpoints.reduce(function(out, block) {
  out[block.height] = utils.revHex(block.hash);
  return block;
}, {});

segnet3.checkpoints.tsLastCheckpoint = 0;
segnet3.checkpoints.txsLastCheckpoint = 0;
segnet3.checkpoints.txsPerDay = 300;
segnet3.checkpoints.lastHeight = 0;

segnet3.halvingInterval = 210000;

segnet3.genesis = {
  version: 1,
  hash: utils.revHex(
    '0d5b9c518ddf053fcac71730830df4526a9949c08f34acf6a1d30464d22f02aa'
  ),
  prevBlock: '0000000000000000000000000000000000000000000000000000000000000000',
  merkleRoot: utils.revHex(
    '4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b'
  ),
  ts: 1452831101,
  bits: 0x1d00ffff,
  nonce: 0
};

segnet3.magic = 0xcaea962e;

segnet3.powLimit = new bn(
  '00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
  'hex'
);
segnet3.powTargetTimespan = 14 * 24 * 60 * 60; // two weeks
segnet3.powTargetSpacing = 10 * 60;
segnet3.powDiffInterval = segnet3.powTargetTimespan / segnet3.powTargetSpacing | 0;
segnet3.powAllowMinDifficultyBlocks = true;
segnet3.powNoRetargeting = false;

segnet3.block = {
  majorityEnforceUpgrade: 7,
  majorityRejectOutdated: 9,
  majorityWindow: 10,
  bip34height: -1
};

segnet3.segwitHeight = 0;

segnet3.genesisBlock = '0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a7d719856ffff001d000000000101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000';

segnet3.ruleChangeActivationThreshold = 108;
segnet3.minerConfirmationWindow = 144;
segnet3.deployments = {};

segnet3.height = -1;
segnet3.witness = true;

segnet4 = network.segnet4 = {};

utils.merge(segnet4, segnet3);

segnet4.type = 'segnet4';

segnet4.seeds = [
  '37.34.48.17'
];

segnet4.port = 28901;
segnet4.segwitHeight = -1;
segnet4.magic = 0xc4a1abdc;

segnet4.powLimit = new bn(
  // 512x lower min difficulty than mainnet
  '000001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
  'hex'
);

segnet4.deployments = utils.merge({}, main.deployments, {
  witness: {
    bit: 1,
    startTime: 0,
    timeout: 999999999999
  }
  // bip109: {
  //   bit: 4,
  //   startTime: 1453939200, // Jan 28th, 2016
  //   timeout: 1514764800 // Jan 1st, 2018
  // }
});

segnet4.genesis = {
  version: 1,
  hash: 'b291211d4bb2b7e1b7a4758225e69e50104091a637213d033295c010f55ffb18',
  prevBlock: '0000000000000000000000000000000000000000000000000000000000000000',
  merkleRoot: utils.revHex(
    '4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b'
  ),
  ts: 1452831101,
  bits: 503447551,
  nonce: 0
};

segnet4.genesisBlock = '0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a7d719856ffff011e000000000101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000';

/*
 * Global
 */

network.xprivkeys = {
  '76066276': 'main',
  '70615956': 'testnet',
  '87393172': 'segnet3',
  'xprv': 'main',
  'tprv': 'testnet',
  '2791': 'segnet3',
  '2791': 'segnet4'
};

network.xpubkeys = {
  '76067358': 'main',
  '70617039': 'testnet',
  '87394255': 'segnet3',
  'xpub': 'main',
  'tpub': 'testnet',
  '2793': 'segnet3',
  '2793': 'segnet4'
};
