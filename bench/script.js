'use strict';

var BN = require('bn.js');
var bcoin = require('../').set('main');
var constants = bcoin.constants;
var util = bcoin.util;
var assert = require('assert');
var scriptTypes = constants.scriptTypes;
var opcodes = constants.opcodes;
var bench = require('./bench');
var fs = require('fs');
var Script = bcoin.script;

bcoin.cache();

Script.prototype.fromPubkeyhashOld = function fromScripthash(hash) {
  assert(Buffer.isBuffer(hash) && hash.length === 20);
  this.push(opcodes.OP_DUP);
  this.push(opcodes.OP_HASH160);
  this.push(hash);
  this.push(opcodes.OP_EQUALVERIFY);
  this.push(opcodes.OP_CHECKSIG);
  this.compile();
  return this;
};

Script.fromPubkeyhashOld = function fromScripthash(hash) {
  return new Script().fromPubkeyhashOld(hash);
};

var hashes = [];
for (var i = 0; i < 100000; i++)
  hashes.push(bcoin.crypto.randomBytes(20));

var end = bench('old');
for (var i = 0; i < hashes.length; i++)
  Script.fromPubkeyhashOld(hashes[i]);
end(i);

var end = bench('hash');
for (var i = 0; i < hashes.length; i++)
  Script.fromPubkeyhash(hashes[i]);
end(i);
