'use strict';

var assert = require('assert');
var BN = require('bn.js');
var ec = require('../lib/crypto/ec');
var base58 = require('../lib/utils/base58');
var encoding = require('../lib/utils/encoding');
var crypto = require('../lib/crypto/crypto');
var schnorr = require('../lib/crypto/schnorr');
var Amount = require('../lib/btc/amount');
var consensus = require('../lib/protocol/consensus');
var Validator = require('../lib/utils/validator');

describe('Utils', function() {
  var vectors, signed, unsigned;

  vectors = [
    ['', ''],
    ['61', '2g'],
    ['626262', 'a3gV'],
    ['636363', 'aPEr'],
    ['73696d706c792061206c6f6e6720737472696e67', '2cFupjhnEsSn59qHXstmK2ffpLv2'],
    ['00eb15231dfceb60925886b67d065299925915aeb172c06647', '1NS17iag9jJgTHD1VXjvLCEnZuQ3rJDE9L'],
    ['516b6fcd0f', 'ABnLTmg'],
    ['bf4f89001e670274dd', '3SEo3LWLoPntC'],
    ['572e4794', '3EFU7m'],
    ['ecac89cad93923c02321', 'EJDM8drfXA6uyA'],
    ['10c8511e', 'Rt5zm'],
    ['00000000000000000000', '1111111111']
  ];

  it('should encode/decode base58', function() {
    var buf = new Buffer('000000deadbeef', 'hex');
    var b = base58.encode(buf);
    var i, r;

    assert.equal(b, '1116h8cQN');
    assert.deepEqual(base58.decode(b), buf);

    for (i = 0; i < vectors.length; i++) {
      r = new Buffer(vectors[i][0], 'hex');
      b = vectors[i][1];
      assert.equal(base58.encode(r), b);
      assert.deepEqual(base58.decode(b), r);
    }
  });

  it('should verify proof-of-work', function() {
    var bits = 0x1900896c;
    var hash;

    hash = new Buffer(
      '672b3f1bb11a994267ea4171069ba0aa4448a840f38e8f340000000000000000',
      'hex'
    );

    assert(consensus.verifyPOW(hash, bits));
  });

  it('should convert satoshi to btc', function() {
    var btc = Amount.btc(5460);
    assert.equal(btc, '0.0000546');
    btc = Amount.btc(54678 * 1000000);
    assert.equal(btc, '546.78');
    btc = Amount.btc(5460 * 10000000);
    assert.equal(btc, '546.0');
  });

  it('should convert btc to satoshi', function() {
    var btc = Amount.value('0.0000546');
    assert(btc === 5460);
    btc = Amount.value('546.78');
    assert(btc === 54678 * 1000000);
    btc = Amount.value('546');
    assert(btc === 5460 * 10000000);
    btc = Amount.value('546.0');
    assert(btc === 5460 * 10000000);
    btc = Amount.value('546.0000');
    assert(btc === 5460 * 10000000);
    assert.doesNotThrow(function() {
      Amount.value('546.00000000000000000');
    });
    assert.throws(function() {
      Amount.value('546.00000000000000001');
    });
    assert.doesNotThrow(function() {
      Amount.value('90071992.54740991');
    });
    assert.doesNotThrow(function() {
      Amount.value('090071992.547409910');
    });
    assert.throws(function() {
      Amount.value('90071992.54740992');
    });
    assert.throws(function() {
      Amount.value('190071992.54740991');
    });
  });

  it('should write/read new varints', function() {
    var n, b;

    /*
     * 0:         [0x00]  256:        [0x81 0x00]
     * 1:         [0x01]  16383:      [0xFE 0x7F]
     * 127:       [0x7F]  16384:      [0xFF 0x00]
     * 128:  [0x80 0x00]  16511: [0x80 0xFF 0x7F]
     * 255:  [0x80 0x7F]  65535: [0x82 0xFD 0x7F]
     * 2^32:           [0x8E 0xFE 0xFE 0xFF 0x00]
     */

    n = 0;
    b = new Buffer(1);
    b.fill(0x00);
    encoding.writeVarint2(b, 0, 0);
    assert.equal(encoding.readVarint2(b, 0).value, 0);
    assert.deepEqual(b, [0]);

    b = new Buffer(1);
    b.fill(0x00);
    encoding.writeVarint2(b, 1, 0);
    assert.equal(encoding.readVarint2(b, 0).value, 1);
    assert.deepEqual(b, [1]);

    b = new Buffer(1);
    b.fill(0x00);
    encoding.writeVarint2(b, 127, 0);
    assert.equal(encoding.readVarint2(b, 0).value, 127);
    assert.deepEqual(b, [0x7f]);

    b = new Buffer(2);
    b.fill(0x00);
    encoding.writeVarint2(b, 128, 0);
    assert.equal(encoding.readVarint2(b, 0).value, 128);
    assert.deepEqual(b, [0x80, 0x00]);

    b = new Buffer(2);
    b.fill(0x00);
    encoding.writeVarint2(b, 255, 0);
    assert.equal(encoding.readVarint2(b, 0).value, 255);
    assert.deepEqual(b, [0x80, 0x7f]);

    b = new Buffer(2);
    b.fill(0x00);
    encoding.writeVarint2(b, 16383, 0);
    assert.equal(encoding.readVarint2(b, 0).value, 16383);
    assert.deepEqual(b, [0xfe, 0x7f]);

    b = new Buffer(2);
    b.fill(0x00);
    encoding.writeVarint2(b, 16384, 0);
    assert.equal(encoding.readVarint2(b, 0).value, 16384);
    assert.deepEqual(b, [0xff, 0x00]);

    b = new Buffer(3);
    b.fill(0x00);
    encoding.writeVarint2(b, 16511, 0);
    assert.equal(encoding.readVarint2(b, 0).value, 16511);
    // assert.deepEqual(b, [0x80, 0xff, 0x7f]);
    assert.deepEqual(b, [0xff, 0x7f, 0x00]);

    b = new Buffer(3);
    b.fill(0x00);
    encoding.writeVarint2(b, 65535, 0);
    assert.equal(encoding.readVarint2(b, 0).value, 65535);
    // assert.deepEqual(b, [0x82, 0xfd, 0x7f]);
    assert.deepEqual(b, [0x82, 0xfe, 0x7f]);

    b = new Buffer(5);
    b.fill(0x00);
    encoding.writeVarint2(b, Math.pow(2, 32), 0);
    assert.equal(encoding.readVarint2(b, 0).value, Math.pow(2, 32));
    assert.deepEqual(b, [0x8e, 0xfe, 0xfe, 0xff, 0x00]);
  });

  unsigned = [
    new BN('ffeeffee'),
    new BN('001fffeeffeeffee'),
    new BN('eeffeeff'),
    new BN('001feeffeeffeeff'),
    new BN(0),
    new BN(1)
  ];

  signed = [
    new BN('ffeeffee'),
    new BN('001fffeeffeeffee'),
    new BN('eeffeeff'),
    new BN('001feeffeeffeeff'),
    new BN(0),
    new BN(1),
    new BN('ffeeffee').ineg(),
    new BN('001fffeeffeeffee').ineg(),
    new BN('eeffeeff').ineg(),
    new BN('001feeffeeffeeff').ineg(),
    new BN(0).ineg(),
    new BN(1).ineg()
  ];

  unsigned.forEach(function(num) {
    var buf1 = new Buffer(8);
    var buf2 = new Buffer(8);
    var msg = 'should write+read a ' + num.bitLength() + ' bit unsigned int';

    it(msg, function() {
      var n1, n2;

      encoding.writeU64BN(buf1, num, 0);
      encoding.writeU64(buf2, num.toNumber(), 0);
      assert.deepEqual(buf1, buf2);

      n1 = encoding.readU64BN(buf1, 0);
      n2 = encoding.readU64(buf2, 0);
      assert.equal(n1.toNumber(), n2);
    });
  });

  signed.forEach(function(num) {
    var buf1 = new Buffer(8);
    var buf2 = new Buffer(8);
    var msg = 'should write+read a ' + num.bitLength()
      + ' bit ' + (num.isNeg() ? 'negative' : 'positive') + ' int';

    it(msg, function() {
      var n1, n2;

      encoding.write64BN(buf1, num, 0);
      encoding.write64(buf2, num.toNumber(), 0);
      assert.deepEqual(buf1, buf2);

      n1 = encoding.read64BN(buf1, 0);
      n2 = encoding.read64(buf2, 0);
      assert.equal(n1.toNumber(), n2);
    });

    msg = 'should write+read a ' + num.bitLength()
      + ' bit ' + (num.isNeg() ? 'negative' : 'positive') + ' int as unsigned';

    it(msg, function() {
      var n1, n2;

      encoding.writeU64BN(buf1, num, 0);
      encoding.writeU64(buf2, num.toNumber(), 0);
      assert.deepEqual(buf1, buf2);

      n1 = encoding.readU64BN(buf1, 0);
      if (num.isNeg()) {
        assert.throws(function() {
          encoding.readU64(buf2, 0);
        });
      } else {
        n2 = encoding.readU64(buf2, 0);
        assert.equal(n1.toNumber(), n2);
      }
    });
  });

  it('should do proper hkdf', function() {
    // https://tools.ietf.org/html/rfc5869
    var alg = 'sha256';
    var ikm = '0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b';
    var salt = '000102030405060708090a0b0c';
    var info = 'f0f1f2f3f4f5f6f7f8f9';
    var len = 42;
    var prkE, okmE, prk, okm;

    prkE = '077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5';
    okmE = '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1'
      + 'a5a4c5db02d56ecc4c5bf34007208d5b887185865';

    ikm = new Buffer(ikm, 'hex');
    salt = new Buffer(salt, 'hex');
    info = new Buffer(info, 'hex');

    prk = crypto.hkdfExtract(ikm, salt, alg);
    okm = crypto.hkdfExpand(prk, info, len, alg);

    assert.equal(prk.toString('hex'), prkE);
    assert.equal(okm.toString('hex'), okmE);

    alg = 'sha256';

    ikm = '000102030405060708090a0b0c0d0e0f'
      + '101112131415161718191a1b1c1d1e1f'
      + '202122232425262728292a2b2c2d2e2f'
      + '303132333435363738393a3b3c3d3e3f'
      + '404142434445464748494a4b4c4d4e4f';

    salt = '606162636465666768696a6b6c6d6e6f'
      + '707172737475767778797a7b7c7d7e7f'
      + '808182838485868788898a8b8c8d8e8f'
      + '909192939495969798999a9b9c9d9e9f'
      + 'a0a1a2a3a4a5a6a7a8a9aaabacadaeaf';

    info = 'b0b1b2b3b4b5b6b7b8b9babbbcbdbebf'
      + 'c0c1c2c3c4c5c6c7c8c9cacbcccdcecf'
      + 'd0d1d2d3d4d5d6d7d8d9dadbdcdddedf'
      + 'e0e1e2e3e4e5e6e7e8e9eaebecedeeef'
      + 'f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff';

    len = 82;

    prkE = '06a6b88c5853361a06104c9ceb35b45c'
      + 'ef760014904671014a193f40c15fc244';

    okmE = 'b11e398dc80327a1c8e7f78c596a4934'
      + '4f012eda2d4efad8a050cc4c19afa97c'
      + '59045a99cac7827271cb41c65e590e09'
      + 'da3275600c2f09b8367793a9aca3db71'
      + 'cc30c58179ec3e87c14c01d5c1f3434f'
      + '1d87';

    ikm = new Buffer(ikm, 'hex');
    salt = new Buffer(salt, 'hex');
    info = new Buffer(info, 'hex');

    prk = crypto.hkdfExtract(ikm, salt, alg);
    okm = crypto.hkdfExpand(prk, info, len, alg);

    assert.equal(prk.toString('hex'), prkE);
    assert.equal(okm.toString('hex'), okmE);
  });

  it('should do proper schnorr', function() {
    var key = ec.generatePrivateKey();
    var pub = ec.publicKeyCreate(key, true);
    var msg = crypto.hash256(new Buffer('foo', 'ascii'));
    var sig = schnorr.sign(msg, key);
    assert(schnorr.verify(msg, sig, pub));
    assert.deepEqual(schnorr.recover(sig, msg), pub);
  });

  it('should validate integers 0 and 1 as booleans', function() {
    var validator = new Validator({shouldBeTrue: 1, shouldBeFalse: 0});
    assert(validator.bool('shouldBeTrue') === true);
    assert(validator.bool('shouldBeFalse') === false);
  });
});
