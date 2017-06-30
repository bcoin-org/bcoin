'use strict';

const assert = require('assert');
const random = require('../lib/crypto/random');
const Script = require('../lib/script/script');
const bench = require('./bench');
const opcodes = Script.opcodes;
let i, hashes, end;

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
  hashes.push(random.randomBytes(20));

end = bench('old');
for (i = 0; i < hashes.length; i++)
  Script.fromPubkeyhashOld(hashes[i]);
end(i);

end = bench('hash');
for (i = 0; i < hashes.length; i++)
  Script.fromPubkeyhash(hashes[i]);
end(i);
