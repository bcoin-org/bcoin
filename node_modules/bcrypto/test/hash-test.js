'use strict';

const assert = require('bsert');
const fs = require('fs');
const rng = require('../lib/random');
const BLAKE2b160 = require('../lib/blake2b160');
const BLAKE2b256 = require('../lib/blake2b256');
const BLAKE2b384 = require('../lib/blake2b384');
const BLAKE2b512 = require('../lib/blake2b512');
const BLAKE2s128 = require('../lib/blake2s128');
const BLAKE2s160 = require('../lib/blake2s160');
const BLAKE2s224 = require('../lib/blake2s224');
const BLAKE2s256 = require('../lib/blake2s256');
const GOST94 = require('../lib/gost94');
const Hash160 = require('../lib/hash160');
const Hash256 = require('../lib/hash256');
const Keccak224 = require('../lib/keccak224');
const Keccak256 = require('../lib/keccak256');
const Keccak384 = require('../lib/keccak384');
const Keccak512 = require('../lib/keccak512');
const MD2 = require('../lib/md2');
const MD4 = require('../lib/md4');
const MD5 = require('../lib/md5');
const MD5SHA1 = require('../lib/md5sha1');
const RIPEMD160 = require('../lib/ripemd160');
const SHA1 = require('../lib/sha1');
const SHA224 = require('../lib/sha224');
const SHA256 = require('../lib/sha256');
const SHA384 = require('../lib/sha384');
const SHA512 = require('../lib/sha512');
const SHA3_224 = require('../lib/sha3-224');
const SHA3_256 = require('../lib/sha3-256');
const SHA3_384 = require('../lib/sha3-384');
const SHA3_512 = require('../lib/sha3-512');
const SHAKE128 = require('../lib/shake128');
const SHAKE256 = require('../lib/shake256');
const Whirlpool = require('../lib/whirlpool');

const hashes = [
  ['blake2b160', BLAKE2b160],
  ['blake2b256', BLAKE2b256],
  ['blake2b384', BLAKE2b384],
  ['blake2b512', BLAKE2b512],
  ['blake2s128', BLAKE2s128],
  ['blake2s160', BLAKE2s160],
  ['blake2s224', BLAKE2s224],
  ['blake2s256', BLAKE2s256],
  ['gost94', GOST94],
  ['hash160', Hash160],
  ['hash256', Hash256],
  ['keccak224', Keccak224],
  ['keccak256', Keccak256],
  ['keccak384', Keccak384],
  ['keccak512', Keccak512],
  ['md2', MD2],
  ['md4', MD4],
  ['md5', MD5],
  ['md5-sha1', MD5SHA1],
  ['ripemd160', RIPEMD160],
  ['sha1', SHA1],
  ['sha224', SHA224],
  ['sha256', SHA256],
  ['sha384', SHA384],
  ['sha512', SHA512],
  ['sha3-224', SHA3_224],
  ['sha3-256', SHA3_256],
  ['sha3-384', SHA3_384],
  ['sha3-512', SHA3_512],
  ['shake128', SHAKE128],
  ['shake256', SHAKE256],
  ['whirlpool', Whirlpool]
];

function hashRand(hash, arg, data) {
  const ctx = hash.hash();
  const max = Math.max(2, data.length >>> 2);

  let i = 0;

  ctx.init(arg);

  while (i < data.length) {
    const j = rng.randomRange(0, max);

    ctx.update(data.slice(i, i + j));

    i += j;
  }

  return ctx.final();
}

describe('Hash', function() {
  for (const [name, hash] of hashes) {
    const file = `${__dirname}/data/hashes/${name}.json`;
    const text = fs.readFileSync(file, 'utf8');
    const vectors = JSON.parse(text);

    describe(hash.id, () => {
      for (const [msg_, arg_, key_, expect_] of vectors) {
        const msg = Buffer.from(msg_, 'hex');
        const arg = arg_ != null ? Buffer.from(arg_, 'hex') : undefined;
        const key = key_ != null ? Buffer.from(key_, 'hex') : null;
        const expect = Buffer.from(expect_, 'hex');
        const text = expect_.slice(0, 32) + '...';

        if (key) {
          it(`should get ${hash.id} hmac of ${text}`, () => {
            const ch = Buffer.alloc(1);
            const ctx = hash.hmac();

            assert.bufferEqual(ctx.init(key).update(msg).final(), expect);

            ctx.init(key);

            for (let i = 0; i < msg.length; i++) {
              ch[0] = msg[i];
              ctx.update(ch);
            }

            assert.bufferEqual(ctx.final(), expect);

            assert.bufferEqual(hash.mac(msg, key), expect);
          });
        } else {
          it(`should get ${hash.id} hash of ${text}`, () => {
            const ch = Buffer.alloc(1);
            const size = msg.length >>> 1;
            const left = msg.slice(0, size);
            const right = msg.slice(size);
            const mid = right.length >>> 1;
            const right1 = right.slice(0, mid);
            const right2 = right.slice(mid);
            const ctx = hash.hash();

            assert.bufferEqual(ctx.init(arg).update(msg).final(), expect);

            ctx.init(arg);

            for (let i = 0; i < msg.length; i++) {
              ch[0] = msg[i];
              ctx.update(ch);
            }

            assert.bufferEqual(ctx.final(), expect);

            assert.bufferEqual(hash.digest(msg, arg), expect);
            assert.bufferEqual(hashRand(hash, arg, msg), expect);

            if (arg == null) {
              assert.bufferEqual(hash.multi(left, right), expect);
              assert.bufferEqual(hash.multi(left, right1, right2), expect);

              assert.bufferEqual(hash.root(expect, expect),
                                 hash.multi(expect, expect));
            } else {
              assert.bufferEqual(hash.multi(left, right, null, arg), expect);
              assert.bufferEqual(hash.multi(left, right1, right2, arg), expect);

              assert.bufferEqual(hash.root(expect, expect, arg),
                                 hash.multi(expect, expect, null, arg));
            }
          });
        }
      }
    });
  }
});
