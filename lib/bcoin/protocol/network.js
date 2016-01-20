/**
 * network.js - bitcoin networks for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

var bcoin = require('../../bcoin');
var bn = require('bn.js');
var utils = bcoin.utils;

/**
 * Network
 */

var network = exports;
var main, testnet, regtest;

network.set = function set(type) {
  var net = network[type];
  utils.merge(network, net);
};

/**
 * Main
 */

main = network.main = {};

main.prefixes = {
  pubkey: 0,
  pubkeyhash: 0,
  multisig: 0,
  scripthash: 5,
  privkey: 128,
  xpubkey: 0x0488b21e,
  xprivkey: 0x0488ade4
};

main.type = 'main';

main.seeds = [
  'seed.bitcoin.sipa.be', // Pieter Wuille
  'dnsseed.bluematt.me', // Matt Corallo
  'dnsseed.bitcoin.dashjr.org', // Luke Dashjr
  'seed.bitcoinstats.com', // Christian Decker
  'bitseed.xf2.org', // Jeff Garzik
  'seed.bitcoin.jonasschnelli.ch' // Jonas Schnelli
];

main.port = 8333;

main.alertKey = utils.toArray(''
  + '04fc9702847840aaf195de8442ebecedf5b095c'
  + 'dbb9bc716bda9110971b28a49e0ead8564ff0db'
  + '22209e0374782c093bb899692d524e9d6a6956e'
  + '7c5ecbcd68284',
  'hex');

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
main.checkpoints.lastHeight = Object.keys(main.checkpoints).sort().pop();

main.halvingInterval = 210000;

// http://blockexplorer.com/b/0
// http://blockexplorer.com/rawblock/000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f
main.genesis = {
  version: 1,
  hash: utils.revHex(
    '000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f'
  ),
  prevBlock: utils.toHex(
             [ 0, 0, 0, 0, 0, 0, 0, 0,
               0, 0, 0, 0, 0, 0, 0, 0,
               0, 0, 0, 0, 0, 0, 0, 0,
               0, 0, 0, 0, 0, 0, 0, 0 ]),
  merkleRoot: utils.revHex(
    '4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b'
  ),
  ts: 1231006505,
  bits: 0x1d00ffff,
  nonce: 2083236893
};

main.magic = 0xd9b4bef9;

main.preload = {
  v: 2,
  type: 'chain',
  network: main.type,
  entries: [
    {
      hash: main.genesis.hash,
      version: main.genesis.version,
      prevBlock: main.genesis.prevBlock,
      ts: main.genesis.ts,
      bits: main.genesis.bits,
      height: 0
    }
  ]
};

try {
  main._preload = require('./preload');
  utils.assert(main._preload.entries[0]);
  main.preload = main._preload;
  delete main._preload;
} catch (e) {
  delete main._preload;
}

main.powLimit = new bn(
  '00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
  'hex'
);
main.powTargetTimespan = 14 * 24 * 60 * 60; // two weeks
main.powTargetSpacing = 10 * 60;
main.powDiffInterval = main.powTargetTimespan / main.powTargetSpacing | 0;
main.powAllowMinDifficultyBlocks = false;
main.powNoRetargeting = false;

main.block = {
  majorityEnforceUpgrade: 750,
  majorityRejectOutdated: 950,
  majorityWindow: 1000
};

/**
 * Testnet (v3)
 * https://en.bitcoin.it/wiki/Testnet
 */

testnet = network.testnet = {};

testnet.type = 'testnet';

testnet.prefixes = {
  pubkey: 111,
  pubkeyhash: 111,
  multisig: 111,
  scripthash: 196,
  privkey: 239,
  xpubkey: 0x043587cf,
  xprivkey: 0x04358394
};

testnet.seeds = [
 'testnet-seed.alexykot.me',
 'testnet-seed.bitcoin.petertodd.org',
 'testnet-seed.bluematt.me',
 'testnet-seed.bitcoin.schildbach.de'
];

testnet.port = 18333;

testnet.alertKey = utils.toArray(''
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
testnet.checkpoints.lastHeight = Object.keys(testnet.checkpoints).sort().pop();

testnet.halvingInterval = 210000;

// http://blockexplorer.com/testnet/b/0
// http://blockexplorer.com/testnet/rawblock/000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943
testnet.genesis =  {
  version: 1,
  hash: utils.revHex(
    '000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943'
  ),
  prevBlock: utils.toHex(
             [ 0, 0, 0, 0, 0, 0, 0, 0,
               0, 0, 0, 0, 0, 0, 0, 0,
               0, 0, 0, 0, 0, 0, 0, 0,
               0, 0, 0, 0, 0, 0, 0, 0 ]),
  merkleRoot: utils.revHex(
    '4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b'
  ),
  ts: 1296688602,
  bits: 0x1d00ffff,
  nonce: 414098458
};

testnet.magic = 0x0709110b;

testnet.preload = {
  v: 2,
  type: 'chain',
  network: testnet.type,
  entries: [
    {
      hash: testnet.genesis.hash,
      version: testnet.genesis.version,
      prevBlock: testnet.genesis.prevBlock,
      ts: testnet.genesis.ts,
      bits: testnet.genesis.bits,
      height: 0
    }
  ]
};

try {
  testnet._preload = require('./preload-test');
  utils.assert(testnet._preload.entries[0]);
  testnet.preload = testnet._preload;
  delete testnet._preload;
} catch (e) {
  delete testnet._preload;
}

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
  majorityWindow: 100
};

/**
 * Regtest
 */

regtest = network.regtest = {};

regtest.type = 'testnet';

regtest.prefixes = {
  pubkey: 111,
  pubkeyhash: 111,
  multisig: 111,
  scripthash: 196,
  privkey: 239,
  xpubkey: 0x043587cf,
  xprivkey: 0x04358394
};

regtest.seeds = [
  '127.0.0.1'
];

regtest.port = 18444;

regtest._alertKey = bcoin.ecdsa.genKeyPair();
regtest.alertKey = regtest._alertKey.getPublic(true, 'array');

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
  prevBlock: utils.toHex(
             [ 0, 0, 0, 0, 0, 0, 0, 0,
               0, 0, 0, 0, 0, 0, 0, 0,
               0, 0, 0, 0, 0, 0, 0, 0,
               0, 0, 0, 0, 0, 0, 0, 0 ]),
  merkleRoot: utils.revHex(
    '4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b'
  ),
  ts: 1296688602,
  bits: 0x207fffff,
  nonce: 2
};

regtest.magic = 0xdab5bffa;

regtest.preload = {
  v: 2,
  type: 'chain',
  network: regtest.type,
  entries: [
    {
      hash: regtest.genesis.hash,
      version: regtest.genesis.version,
      prevBlock: regtest.genesis.prevBlock,
      ts: regtest.genesis.ts,
      bits: regtest.genesis.bits,
      height: 0
    }
  ]
};

try {
  regtest._preload = require('./preload-regtest');
  utils.assert(regtest._preload.entries[0]);
  regtest.preload = regtest._preload;
  delete regtest._preload;
} catch (e) {
  delete regtest._preload;
}

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
  majorityWindow: 1000
};
