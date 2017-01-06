'use strict';

var assert = require('assert');
var constants = require('../lib/protocol/constants');
var crypto = require('../lib/crypto/crypto');
var Script = require('../lib/script/script');
var bench = require('./bench');
var opcodes = Script.opcodes;
var i, hashes, end;

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

hashes = [];
for (i = 0; i < 100000; i++)
  hashes.push(crypto.randomBytes(20));

end = bench('old');
for (i = 0; i < hashes.length; i++)
  Script.fromPubkeyhashOld(hashes[i]);
end(i);

end = bench('hash');
for (i = 0; i < hashes.length; i++)
  Script.fromPubkeyhash(hashes[i]);
end(i);
