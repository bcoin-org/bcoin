var bcoin = require('../../bcoin');
var utils = bcoin.utils;

exports.minVersion = 70001;
exports.version = 70002;
exports.magic = 0xd9b4bef9;
exports.genesis = {
  version: 1,
  prevBlock: [ 0, 0, 0, 0, 0, 0, 0, 0,
               0, 0, 0, 0, 0, 0, 0, 0,
               0, 0, 0, 0, 0, 0, 0, 0,
               0, 0, 0, 0, 0, 0, 0, 0 ],
  merkleRoot: utils.toArray(
    '4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b',
    'hex'
  ).reverse(),
  ts: 1231006505,
  bits: 0x1d00ffff,
  nonce: 2083236893
};

// version - services field
exports.services = {
  network: 1
};

exports.inv = {
  error: 0,
  tx: 1,
  block: 2,
  filtered: 3
};

exports.invByVal = {
  0: 'error',
  1: 'tx',
  2: 'block',
  3: 'filtered'
};

exports.filterFlags = {
  none: 0,
  all: 1,
  pubkeyOnly: 2
};
