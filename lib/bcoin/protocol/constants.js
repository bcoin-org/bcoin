var bcoin = require('../../bcoin');
var utils = bcoin.utils;

exports.minVersion = 70001;
exports.version = 70002;
exports.magic = 0xd9b4bef9;
exports.genesis = utils.toArray(
    '000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f', 'hex');

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
