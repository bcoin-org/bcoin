/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('./util/assert');
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

x509.verifyTime = function() {
  return true;
};

function testRequest(data) {
  const req = bip70.PaymentRequest.fromRaw(data);

  assert.strictEqual(req.pkiType, 'x509+sha256');
  assert(req.pkiData);
  assert(req.getChain());
  assert(req.paymentDetails);
  assert(req.paymentDetails.memo.length !== 0);
  assert(req.paymentDetails.paymentUrl.length !== 0);

  assert.bufferEqual(req.toRaw(), data);
  assert(req.verify());
}

describe('BIP70', function() {
  it('should parse and verify a payment request', () => {
    testRequest(tests.valid);
    testRequest(tests.invalid);
    testRequest(tests.untrusted);
  });

  it('should verify cert chain', () => {
    const req1 = bip70.PaymentRequest.fromRaw(tests.valid);

    assert.strictEqual(req1.version, 1);
    assert.strictEqual(req1.getChain().length, 4);
    assert.strictEqual(req1.paymentDetails.paymentUrl,
      'https://test.bitpay.com/i/CMWpuFsjgmQ2ZLiyGfcF1W');
    assert.strictEqual(req1.paymentDetails.network, 'test');
    assert.strictEqual(req1.paymentDetails.time, 1408645830);
    assert.strictEqual(req1.paymentDetails.expires, 1408646730);
    assert.strictEqual(req1.paymentDetails.outputs.length, 1);
    assert(!req1.paymentDetails.merchantData);
    assert(req1.paymentDetails.isExpired());

    assert(req1.verifyChain());

    const req2 = bip70.PaymentRequest.fromRaw(tests.invalid);

    assert.strictEqual(req2.version, 1);
    assert.strictEqual(req2.getChain().length, 3);
    assert.strictEqual(req2.paymentDetails.paymentUrl,
      'https://bitpay.com/i/PAQtNxX7KL8BtJBnfXyTaH');
    assert.strictEqual(req2.paymentDetails.network, 'main');
    assert.strictEqual(req2.paymentDetails.time, 1442409238);
    assert.strictEqual(req2.paymentDetails.expires, 1442410138);
    assert.strictEqual(req2.paymentDetails.outputs.length, 1);
    assert.strictEqual(req2.paymentDetails.merchantData.length, 76);
    assert(req2.paymentDetails.getData('json'));
    assert(req2.paymentDetails.isExpired());

    assert(req2.verifyChain());

    req2.paymentDetails.setData({foo:1}, 'json');
    assert.strictEqual(req2.paymentDetails.merchantData.length, 9);
    assert.deepStrictEqual(req2.paymentDetails.getData('json'), {foo:1});
    assert(!req2.verify());

    const req3 = bip70.PaymentRequest.fromRaw(tests.untrusted);

    assert.strictEqual(req3.version, -1);
    assert.strictEqual(req3.getChain().length, 2);
    assert.strictEqual(req3.paymentDetails.paymentUrl,
      'https://www.coinbase.com/rp/55f9ca703d5d80008c0001f4');
    assert.strictEqual(req3.paymentDetails.network, null);
    assert.strictEqual(req3.paymentDetails.time, 1442433682);
    assert.strictEqual(req3.paymentDetails.expires, 1442434548);
    assert.strictEqual(req3.paymentDetails.outputs.length, 1);
    assert.strictEqual(req3.paymentDetails.merchantData.length, 32);
    assert.strictEqual(req3.paymentDetails.getData('utf8'),
      'bb79b6f2310e321bd3b1d929edbeb358');
    assert(req3.paymentDetails.isExpired());

    assert(req3.verifyChain());
  });

  it('should fail to verify cert signatures when enforcing trust', () => {
    x509.allowUntrusted = false;

    const req1 = bip70.PaymentRequest.fromRaw(tests.valid);
    assert(!req1.verifyChain());

    const req2 = bip70.PaymentRequest.fromRaw(tests.invalid);
    assert(!req2.verifyChain());

    const req3 = bip70.PaymentRequest.fromRaw(tests.untrusted);
    assert(!req3.verifyChain());
  });

  it('should verify cert signatures once root cert is added', () => {
    const req1 = bip70.PaymentRequest.fromRaw(tests.valid);
    x509.setTrust([req1.getChain().pop()]);
    assert(req1.verifyChain());

    const req2 = bip70.PaymentRequest.fromRaw(tests.untrusted);
    assert(!req2.verifyChain());
  });

  it('should still fail to verify cert signatures for invalid', () => {
    const req = bip70.PaymentRequest.fromRaw(tests.invalid);
    assert(!req.verifyChain());
  });

  it('should get chain and ca for request', () => {
    const req = bip70.PaymentRequest.fromRaw(tests.valid);
    assert.strictEqual(req.getChain().length, 4);
    assert.strictEqual(req.getCA().name,
      'Go Daddy Class 2 Certification Authority');
  });

  it('should validate untrusted once again', () => {
    const req1 = bip70.PaymentRequest.fromRaw(tests.untrusted);
    x509.setTrust([req1.getChain().pop()]);

    const req2 = bip70.PaymentRequest.fromRaw(tests.untrusted);
    assert(req2.verifyChain());
    assert.strictEqual(req2.getCA().name,
      'DigiCert SHA2 Extended Validation Server CA');
  });

  it('should parse a payment ack', () => {
    const ack = bip70.PaymentACK.fromRaw(tests.ack);
    assert.strictEqual(ack.memo.length, 95);
    assert.strictEqual(ack.memo, 'Transaction received by BitPay.'
      + ' Invoice will be marked as paid if the transaction is confirmed.');
    assert.bufferEqual(ack.toRaw(), tests.ack);
  });

  it('should create a payment request, sign, and verify', () => {
    const req = new bip70.PaymentRequest({
      version: 25,
      paymentDetails: {
        network: 'testnet',
        paymentUrl: 'http://bcoin.io/payment',
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

    assert.strictEqual(req.pkiType, null);
    assert(!req.pkiData);
    assert.strictEqual(req.getChain().length, 0);
    assert(req.paymentDetails);
    assert(req.paymentDetails.memo.length !== 0);
    assert(req.paymentDetails.paymentUrl.length !== 0);
    assert.deepStrictEqual(req.paymentDetails.getData('json'), {foo:'bar'});

    assert.strictEqual(req.version, 25);
    assert.strictEqual(req.paymentDetails.paymentUrl,
      'http://bcoin.io/payment');
    assert.strictEqual(req.paymentDetails.network, 'testnet');
    assert(req.paymentDetails.time <= util.now());
    assert.strictEqual(req.paymentDetails.expires,
      req.paymentDetails.time + 3600);
    assert.strictEqual(req.paymentDetails.outputs.length, 2);
    assert(req.paymentDetails.merchantData);
    assert(!req.paymentDetails.isExpired());

    assert(!req.pkiData);
    req.setChain([tests.ca.crt]);
    req.sign(tests.ca.priv);

    assert(req.pkiData);
    assert.strictEqual(req.pkiType, 'x509+sha256');
    assert.strictEqual(req.getChain().length, 1);

    assert(req.verify());
    assert(!req.verifyChain());

    testRequest(req.toRaw());

    x509.setTrust([tests.ca.crt]);
    assert(req.verifyChain());
    assert.strictEqual(req.getCA().name, 'JJs CA');

    req.version = 24;
    assert(!req.verify());
  });
});
