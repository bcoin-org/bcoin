/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('bsert');
const crypto = require('crypto');
const SHA256 = require('../lib/sha256');
const BLAKE2b256 = require('../lib/blake2b256');
const random = require('../lib/random');
const pbkdf2 = require('../lib/pbkdf2');

function testVector() {
  const passwd = random.randomBytes(Math.random() * 64 | 0);
  const salt = random.randomBytes(Math.random() * 32 | 0);
  const iter = random.randomRange(1, 5000);
  const len = random.randomRange(1, 64);
  const expect = crypto.pbkdf2Sync(passwd, salt, iter, len, 'sha256');

  return {
    passwd,
    salt,
    iter,
    len,
    expect
  };
}

describe('PBKDF2', function() {
  for (let i = 0; i < 20; i++) {
    const {passwd, salt, iter, len, expect} = testVector();
    const pwd = passwd.toString('hex');

    it(`should compute pbkdf2 for ${pwd}`, () => {
      const key = pbkdf2.derive(SHA256, passwd, salt, iter, len);
      assert.bufferEqual(key, expect);
    });
  }

  for (let i = 0; i < 20; i++) {
    const {passwd, salt, iter, len, expect} = testVector();
    const pwd = passwd.toString('hex');

    it(`should compute pbkdf2 for ${pwd} (async)`, async () => {
      const key = await pbkdf2.deriveAsync(SHA256, passwd, salt, iter, len);
      assert.bufferEqual(key, expect);
    });
  }

  it('should compute pbkdf2 for blake2b256', () => {
    const passwd = Buffer.from('foo');
    const salt = Buffer.from('foo');
    const iter = 2000;
    const len = 16;
    const expect = Buffer.from('fa7fcd855a5d342bfedeb14153334534', 'hex');
    const key = pbkdf2.derive(BLAKE2b256, passwd, salt, iter, len);
    assert.bufferEqual(key, expect);
  });

  it('should compute pbkdf2 for blake2b256 (async)', async () => {
    const passwd = Buffer.from('foo');
    const salt = Buffer.from('foo');
    const iter = 2000;
    const len = 16;
    const expect = Buffer.from('fa7fcd855a5d342bfedeb14153334534', 'hex');
    const key = await pbkdf2.deriveAsync(BLAKE2b256, passwd, salt, iter, len);
    assert.bufferEqual(key, expect);
  });
});
