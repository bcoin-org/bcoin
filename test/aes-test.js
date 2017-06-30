'use strict';

const assert = require('assert');
const digest = require('../lib/crypto/digest');
const aes = require('../lib/crypto/aes');
const pbkdf2 = require('../lib/crypto/pbkdf2');
const nativeCrypto = require('crypto');

describe('AES', function() {
  function pbkdf2key(passphrase, iterations, dkLen, ivLen, alg) {
    let key = pbkdf2.derive(passphrase, '', iterations, dkLen + ivLen, 'sha512');
    return {
      key: key.slice(0, dkLen),
      iv: key.slice(dkLen, dkLen + ivLen)
    };
  }

  function nencrypt(data, passphrase) {
    let key, cipher;

    assert(nativeCrypto, 'No crypto module available.');
    assert(passphrase, 'No passphrase.');

    if (typeof data === 'string')
      data = Buffer.from(data, 'utf8');

    if (typeof passphrase === 'string')
      passphrase = Buffer.from(passphrase, 'utf8');

    key = pbkdf2key(passphrase, 2048, 32, 16);
    cipher = nativeCrypto.createCipheriv('aes-256-cbc', key.key, key.iv);

    return Buffer.concat([
      cipher.update(data),
      cipher.final()
    ]);
  }

  function ndecrypt(data, passphrase) {
    let key, decipher;

    assert(nativeCrypto, 'No crypto module available.');
    assert(passphrase, 'No passphrase.');

    if (typeof data === 'string')
      data = Buffer.from(data, 'hex');

    if (typeof passphrase === 'string')
      passphrase = Buffer.from(passphrase, 'utf8');

    key = pbkdf2key(passphrase, 2048, 32, 16);
    decipher = nativeCrypto.createDecipheriv('aes-256-cbc', key.key, key.iv);

    return Buffer.concat([
      decipher.update(data),
      decipher.final()
    ]);
  }

  function bencrypt(data, passphrase) {
    let key;

    assert(nativeCrypto, 'No crypto module available.');
    assert(passphrase, 'No passphrase.');

    if (typeof data === 'string')
      data = Buffer.from(data, 'utf8');

    if (typeof passphrase === 'string')
      passphrase = Buffer.from(passphrase, 'utf8');

    key = pbkdf2key(passphrase, 2048, 32, 16);
    return aes.encipher(data, key.key, key.iv);
  }

  function bdecrypt(data, passphrase) {
    let key;

    assert(nativeCrypto, 'No crypto module available.');
    assert(passphrase, 'No passphrase.');

    if (typeof data === 'string')
      data = Buffer.from(data, 'hex');

    if (typeof passphrase === 'string')
      passphrase = Buffer.from(passphrase, 'utf8');

    key = pbkdf2key(passphrase, 2048, 32, 16);
    return aes.decipher(data, key.key, key.iv);
  }

  function encrypt(data, passphrase) {
    let key;

    assert(nativeCrypto, 'No crypto module available.');
    assert(passphrase, 'No passphrase.');

    if (typeof data === 'string')
      data = Buffer.from(data, 'utf8');

    if (typeof passphrase === 'string')
      passphrase = Buffer.from(passphrase, 'utf8');

    key = pbkdf2key(passphrase, 2048, 32, 16);

    return aes.encipher(data, key.key, key.iv);
  }

  function decrypt(data, passphrase) {
    let key;

    assert(nativeCrypto, 'No crypto module available.');
    assert(passphrase, 'No passphrase.');

    if (typeof data === 'string')
      data = Buffer.from(data, 'hex');

    if (typeof passphrase === 'string')
      passphrase = Buffer.from(passphrase, 'utf8');

    key = pbkdf2key(passphrase, 2048, 32, 16);

    return aes.decipher(data, key.key, key.iv);
  }

  it('should encrypt and decrypt a hash with 2 blocks', () => {
    let hash = digest.sha256(Buffer.alloc(0));
    let enchash = encrypt(hash, 'foo');
    let dechash = decrypt(enchash, 'foo');

    let hash2 = digest.sha256(Buffer.alloc(0));
    let enchash2 = nencrypt(hash2, 'foo');
    let dechash2 = ndecrypt(enchash2, 'foo');

    let hash3 = digest.sha256(Buffer.alloc(0));
    let enchash3 = bencrypt(hash3, 'foo');
    let dechash3 = bdecrypt(enchash3, 'foo');

    assert.deepEqual(hash, hash2);
    assert.deepEqual(enchash, enchash2);
    assert.deepEqual(dechash, dechash2);
    assert.deepEqual(dechash, dechash3);
  });

  it('should encrypt and decrypt a hash with uneven blocks', () => {
    let hash = Buffer.concat([digest.sha256(Buffer.alloc(0)), Buffer.from([1,2,3])]);
    let enchash = encrypt(hash, 'foo');
    let dechash = decrypt(enchash, 'foo');

    let hash2 = Buffer.concat([digest.sha256(Buffer.alloc(0)), Buffer.from([1,2,3])]);
    let enchash2 = nencrypt(hash2, 'foo');
    let dechash2 = ndecrypt(enchash2, 'foo');

    assert.deepEqual(hash, hash2);
    assert.deepEqual(enchash, enchash2);
    assert.deepEqual(dechash, dechash2);
  });
});
