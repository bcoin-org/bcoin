var bn = require('bn.js');
var utils = require('../lib/bcoin/utils');
var assert = require('assert');
var aes = require('../lib/bcoin/aes');
var crypto = require('crypto');

describe('AES', function() {
  function nencrypt(data, passphrase) {
    var key, cipher;

    assert(crypto, 'No crypto module available.');
    assert(passphrase, 'No passphrase.');

    if (typeof data === 'string')
      data = new Buffer(data, 'utf8');

    if (typeof passphrase === 'string')
      passphrase = new Buffer(passphrase, 'utf8');

    key = utils.pbkdf2key(passphrase, null, 2048, 32, 16);
    cipher = crypto.createCipheriv('aes-256-cbc', key.key, key.iv);

    return Buffer.concat([
      cipher.update(data),
      cipher.final()
    ]);
  }

  function ndecrypt(data, passphrase) {
    var key, decipher;

    assert(crypto, 'No crypto module available.');
    assert(passphrase, 'No passphrase.');

    if (typeof data === 'string')
      data = new Buffer(data, 'hex');

    if (typeof passphrase === 'string')
      passphrase = new Buffer(passphrase, 'utf8');

    key = utils.pbkdf2key(passphrase, null, 2048, 32, 16);
    decipher = crypto.createDecipheriv('aes-256-cbc', key.key, key.iv);

    return Buffer.concat([
      decipher.update(data),
      decipher.final()
    ]);
  }

  function encrypt(data, passphrase) {
    var key, cipher;

    assert(crypto, 'No crypto module available.');
    assert(passphrase, 'No passphrase.');

    if (typeof data === 'string')
      data = new Buffer(data, 'utf8');

    if (typeof passphrase === 'string')
      passphrase = new Buffer(passphrase, 'utf8');

    key = utils.pbkdf2key(passphrase, null, 2048, 32, 16);

    return aes.cbc.encrypt(data, key.key, key.iv);
  }

  function decrypt(data, passphrase) {
    var key, decipher;

    assert(crypto, 'No crypto module available.');
    assert(passphrase, 'No passphrase.');

    if (typeof data === 'string')
      data = new Buffer(data, 'hex');

    if (typeof passphrase === 'string')
      passphrase = new Buffer(passphrase, 'utf8');

    key = utils.pbkdf2key(passphrase, null, 2048, 32, 16);

    return aes.cbc.decrypt(data, key.key, key.iv);
  }

  it('should encrypt and decrypt a hash with 2 blocks', function() {
    var hash = utils.sha256(new Buffer([]));
    var enchash = encrypt(hash, 'foo');
    var dechash = decrypt(enchash, 'foo');

    var hash2 = utils.sha256(new Buffer([]));
    var enchash2 = nencrypt(hash2, 'foo');
    var dechash2 = ndecrypt(enchash2, 'foo');

    assert.deepEqual(hash, hash2);
    assert.deepEqual(enchash, enchash2);
    assert.deepEqual(dechash, dechash2);
  });

  it('should encrypt and decrypt a hash with uneven blocks', function() {
    var hash = Buffer.concat([utils.sha256(new Buffer([])), new Buffer([1,2,3])]);
    var enchash = encrypt(hash, 'foo');
    var dechash = decrypt(enchash, 'foo');

    var hash2 = Buffer.concat([utils.sha256(new Buffer([])), new Buffer([1,2,3])]);
    var enchash2 = nencrypt(hash2, 'foo');
    var dechash2 = ndecrypt(enchash2, 'foo');

    assert.deepEqual(hash, hash2);
    assert.deepEqual(enchash, enchash2);
    assert.deepEqual(dechash, dechash2);
  });
});
