'use strict';

const assert = require('bsert');
const SHA1 = require('../lib/sha1');
const SHA256 = require('../lib/sha256');
const SHA512 = require('../lib/sha512');
const SHA3_256 = require('../lib/sha3-256');
const BLAKE2s256 = require('../lib/blake2s256');
const BLAKE2b512 = require('../lib/blake2b512');
const BLAKE2b256 = require('../lib/blake2b256');
const pbkdf2 = require('../lib/pbkdf2');
const vectors = require('./data/pbkdf2.json');

const hashes = {
  SHA1,
  SHA256,
  SHA512,
  SHA3_256,
  BLAKE2s256,
  BLAKE2b512
};

describe('PBKDF2', function() {
  for (const [name, passwd_, salt_, iter, len, expect_] of vectors) {
    const hash = hashes[name];
    const passwd = Buffer.from(passwd_, 'hex');
    const salt = Buffer.from(salt_, 'hex');
    const expect = Buffer.from(expect_, 'hex');
    const pwd = passwd.toString('hex', 0, 16) + '...';

    it(`should compute ${name} pbkdf2 for ${pwd}`, () => {
      const key = pbkdf2.derive(hash, passwd, salt, iter, len);
      assert.bufferEqual(key, expect);
    });

    it(`should compute ${name} pbkdf2 for ${pwd} (async)`, async () => {
      const key = await pbkdf2.deriveAsync(hash, passwd, salt, iter, len);
      assert.bufferEqual(key, expect);
    });
  }

  {
    const passwd = Buffer.from('foo');
    const salt = Buffer.from('foo');
    const iter = 2000;
    const len = 16;
    const expect = Buffer.from('fa7fcd855a5d342bfedeb14153334534', 'hex');

    it('should compute pbkdf2 for blake2b256', () => {
      const key = pbkdf2.derive(BLAKE2b256, passwd, salt, iter, len);

      assert.bufferEqual(key, expect);
    });

    it('should compute pbkdf2 for blake2b256 (async)', async () => {
      const key = await pbkdf2.deriveAsync(BLAKE2b256, passwd, salt, iter, len);

      assert.bufferEqual(key, expect);
    });
  }
});
