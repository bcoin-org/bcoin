'use strict';

const bench = require('./bench');
const SHA1 = require('../lib/sha1');
const SHA256 = require('../lib/sha256');
const SHA512 = require('../lib/sha512');
const RIPEMD160 = require('../lib/ripemd160');
const BLAKE2b = require('../lib/blake2b');
const BLAKE2s = require('../lib/blake2s');
const SHA3 = require('../lib/sha3');
const Hash256 = require('../lib/hash256');
const random = require('../lib/random');

for (const size of [32, 64, 65, 128, 512]) {
  const rounds = 200000;
  const msg = random.randomBytes(size);

  bench(`sha1 (${size})`, rounds, () => {
    SHA1.digest(msg);
  });

  bench(`sha256 (${size})`, rounds, () => {
    SHA256.digest(msg);
  });

  bench(`sha512 (${size})`, rounds, () => {
    SHA512.digest(msg);
  });

  bench(`ripemd160 (${size})`, rounds, () => {
    RIPEMD160.digest(msg);
  });

  bench(`blake2b (${size})`, rounds, () => {
    BLAKE2b.digest(msg);
  });

  bench(`blake2s (${size})`, rounds, () => {
    BLAKE2s.digest(msg);
  });

  bench(`sha3 (${size})`, rounds, () => {
    SHA3.digest(msg);
  });

  bench(`hash256 (${size})`, rounds, () => {
    Hash256.digest(msg);
  });

  if (size !== 512)
    console.log('---');
}
