'use strict';

const assert = require('assert');
const util = require('../lib/utils/util');
const bip70 = require('../lib/bip70');
const Address = require('../lib/primitives/address');
const x509 = bip70.x509;

const tests = require('./data/bip70.json');

tests.valid = Buffer.from(tests.valid, 'hex');
tests.invalid = Buffer.from(tests.invalid, 'hex');
tests.untrusted = Buffer.from(tests.untrusted, 'hex');
tests.ack = Buffer.from(tests.ack, 'hex');
tests.ca = {
  crt: Buffer.from(tests.ca.crt, 'hex'),
  priv: Buffer.from(tests.ca.priv, 'hex'),
  pub: Buffer.from(tests.ca.pub, 'hex')
};

x509.allowUntrusted = true;
x509.trusted.clear();

describe('BIP70', function() {
  function testRequest(data) {
    let request = bip70.PaymentRequest.fromRaw(data);
    let ser;

    assert.equal(request.pkiType, 'x509+sha256');
    assert(request.pkiData);
    assert(request.getChain());
    assert(request.paymentDetails);
    assert(request.paymentDetails.memo.length !== 0);
    assert(request.paymentDetails.paymentUrl.length !== 0);

    ser = request.toRaw();
    assert.equal(ser.toString('hex'), data.toString('hex'));
    assert(request.verify());
  }

  x509.verifyTime = function() { return true; };

  it('should parse and verify a payment request', () => {
    testRequest(tests.valid);
    testRequest(tests.invalid);
    testRequest(tests.untrusted);
  });

  it('should verify cert chain', () => {
    let request = bip70.PaymentRequest.fromRaw(tests.valid);

    assert.equal(request.version, 1);
    assert.equal(request.getChain().length, 4);
    assert.equal(request.paymentDetails.paymentUrl,
      'https://test.bitpay.com/i/CMWpuFsjgmQ2ZLiyGfcF1W');
    assert.equal(request.paymentDetails.network, 'test');
    assert.equal(request.paymentDetails.time, 1408645830);
    assert.equal(request.paymentDetails.expires, 1408646730);
    assert.equal(request.paymentDetails.outputs.length, 1);
    assert(!request.paymentDetails.merchantData);
    assert(request.paymentDetails.isExpired());

    assert(request.verifyChain());

    request = bip70.PaymentRequest.fromRaw(tests.invalid);

    assert.equal(request.version, 1);
    assert.equal(request.getChain().length, 3);
    assert.equal(request.paymentDetails.paymentUrl,
      'https://bitpay.com/i/PAQtNxX7KL8BtJBnfXyTaH');
    assert.equal(request.paymentDetails.network, 'main');
    assert.equal(request.paymentDetails.time, 1442409238);
    assert.equal(request.paymentDetails.expires, 1442410138);
    assert.equal(request.paymentDetails.outputs.length, 1);
    assert.equal(request.paymentDetails.merchantData.length, 76);
    assert(request.paymentDetails.getData('json'));
    assert(request.paymentDetails.isExpired());

    assert(request.verifyChain());

    request.paymentDetails.setData({foo:1}, 'json');
    assert.equal(request.paymentDetails.merchantData.length, 9);
    assert.deepStrictEqual(request.paymentDetails.getData('json'), {foo:1});
    assert(!request.verify());

    request = bip70.PaymentRequest.fromRaw(tests.untrusted);

    assert.equal(request.version, -1);
    assert.equal(request.getChain().length, 2);
    assert.equal(request.paymentDetails.paymentUrl,
      'https://www.coinbase.com/rp/55f9ca703d5d80008c0001f4');
    assert.equal(request.paymentDetails.network, null);
    assert.equal(request.paymentDetails.time, 1442433682);
    assert.equal(request.paymentDetails.expires, 1442434548);
    assert.equal(request.paymentDetails.outputs.length, 1);
    assert.equal(request.paymentDetails.merchantData.length, 32);
    assert.equal(request.paymentDetails.getData('utf8'),
      'bb79b6f2310e321bd3b1d929edbeb358');
    assert(request.paymentDetails.isExpired());

    assert(request.verifyChain());
  });

  it('should fail to verify cert signatures when enforcing trust', () => {
    let request;

    x509.allowUntrusted = false;

    request = bip70.PaymentRequest.fromRaw(tests.valid);
    assert(!request.verifyChain());

    request = bip70.PaymentRequest.fromRaw(tests.invalid);
    assert(!request.verifyChain());

    request = bip70.PaymentRequest.fromRaw(tests.untrusted);
    assert(!request.verifyChain());
  });

  it('should verify cert signatures once root cert is added', () => {
    let request = bip70.PaymentRequest.fromRaw(tests.valid);
    x509.setTrust([request.getChain().pop()]);
    assert(request.verifyChain());

    request = bip70.PaymentRequest.fromRaw(tests.untrusted);
    assert(!request.verifyChain());
  });

  it('should still fail to verify cert signatures for invalid', () => {
    let request = bip70.PaymentRequest.fromRaw(tests.invalid);
    assert(!request.verifyChain());
  });

  it('should get chain and ca for request', () => {
    let request = bip70.PaymentRequest.fromRaw(tests.valid);
    assert.equal(request.getChain().length, 4);
    assert.equal(request.getCA().name,
      'Go Daddy Class 2 Certification Authority');
  });

  it('should validate untrusted once again', () => {
    let request = bip70.PaymentRequest.fromRaw(tests.untrusted);
    x509.setTrust([request.getChain().pop()]);

    request = bip70.PaymentRequest.fromRaw(tests.untrusted);
    assert(request.verifyChain());
    assert.equal(request.getCA().name,
      'DigiCert SHA2 Extended Validation Server CA');
  });

  it('should parse a payment ack', () => {
    let ack = bip70.PaymentACK.fromRaw(tests.ack);
    assert.equal(ack.memo.length, 95);
    assert.equal(ack.memo, 'Transaction received by BitPay.'
      + ' Invoice will be marked as paid if the transaction is confirmed.');
    assert.equal(ack.toRaw().toString('hex'), tests.ack.toString('hex'));
  });

  it('should create a payment request, sign, and verify', () => {
    let request = new bip70.PaymentRequest({
      version: 25,
      paymentDetails: {
        network: 'testnet',
        paymentUrl: 'http://bcoin.io/payme',
        memo: 'foobar',
        time: util.now(),
        expires: util.now() + 3600,
        outputs: [
          { value: 10000, address: new Address() },
          { value: 50000, address: new Address() }
        ],
        merchantData: { foo: 'bar' }
      }
    });

    assert.equal(request.pkiType, null);
    assert(!request.pkiData);
    assert.equal(request.getChain().length, 0);
    assert(request.paymentDetails);
    assert(request.paymentDetails.memo.length !== 0);
    assert(request.paymentDetails.paymentUrl.length !== 0);
    assert.deepStrictEqual(request.paymentDetails.getData('json'), {foo:'bar'});

    assert.equal(request.version, 25);
    assert.equal(request.paymentDetails.paymentUrl, 'http://bcoin.io/payme');
    assert.equal(request.paymentDetails.network, 'testnet');
    assert(request.paymentDetails.time <= util.now());
    assert.equal(request.paymentDetails.expires,
      request.paymentDetails.time + 3600);
    assert.equal(request.paymentDetails.outputs.length, 2);
    assert(request.paymentDetails.merchantData);
    assert(!request.paymentDetails.isExpired());

    assert(!request.pkiData);
    request.sign(tests.ca.priv, [tests.ca.crt]);

    assert(request.pkiData);
    assert.equal(request.pkiType, 'x509+sha256');
    assert.equal(request.getChain().length, 1);

    assert(request.verify());
    assert(!request.verifyChain());

    testRequest(request.toRaw());

    x509.setTrust([tests.ca.crt]);
    assert(request.verifyChain());
    assert.equal(request.getCA().name, 'JJs CA');

    request.version = 24;
    assert(!request.verify());
  });
});
