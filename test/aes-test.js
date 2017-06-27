'use strict';

var assert = require('assert');
var digest = require('../lib/crypto/digest');
var aes = require('../lib/crypto/aes');
var pbkdf2 = require('../lib/crypto/pbkdf2');
var nativeCrypto = require('crypto');

describe('AES', function() {
  function pbkdf2key(passphrase, iterations, dkLen, ivLen, alg) {
    var key = pbkdf2.derive(passphrase, '', iterations, dkLen + ivLen, 'sha512');
    return {
      key: key.slice(0, dkLen),
      iv: key.slice(dkLen, dkLen + ivLen)
    };
  }

  function nencrypt(data, passphrase) {
    var key, cipher;

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
    var key, decipher;

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
    var key;

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
    var key;

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
    var key;

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
    var key;

    assert(nativeCrypto, 'No crypto module available.');
    assert(passphrase, 'No passphrase.');

    if (typeof data === 'string')
      data = Buffer.from(data, 'hex');

    if (typeof passphrase === 'string')
      passphrase = Buffer.from(passphrase, 'utf8');

    key = pbkdf2key(passphrase, 2048, 32, 16);

    return aes.decipher(data, key.key, key.iv);
  }

  it('should encrypt and decrypt a hash with 2 blocks', function() {
    var hash = digest.sha256(Buffer.alloc(0));
    var enchash = encrypt(hash, 'foo');
    var dechash = decrypt(enchash, 'foo');

    var hash2 = digest.sha256(Buffer.alloc(0));
    var enchash2 = nencrypt(hash2, 'foo');
    var dechash2 = ndecrypt(enchash2, 'foo');

    var hash3 = digest.sha256(Buffer.alloc(0));
    var enchash3 = bencrypt(hash3, 'foo');
    var dechash3 = bdecrypt(enchash3, 'foo');

    assert.deepEqual(hash, hash2);
    assert.deepEqual(enchash, enchash2);
    assert.deepEqual(dechash, dechash2);
    assert.deepEqual(dechash, dechash3);
  });

  it('should encrypt and decrypt a hash with uneven blocks', function() {
    var hash = Buffer.concat([digest.sha256(Buffer.alloc(0)), Buffer.from([1,2,3])]);
    var enchash = encrypt(hash, 'foo');
    var dechash = decrypt(enchash, 'foo');

    var hash2 = Buffer.concat([digest.sha256(Buffer.alloc(0)), Buffer.from([1,2,3])]);
    var enchash2 = nencrypt(hash2, 'foo');
    var dechash2 = ndecrypt(enchash2, 'foo');

    assert.deepEqual(hash, hash2);
    assert.deepEqual(enchash, enchash2);
    assert.deepEqual(dechash, dechash2);
  });
});
