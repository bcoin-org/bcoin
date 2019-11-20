/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('bsert');
const Path = require('path');
const fs = require('fs');
const rsa = require('../lib/rsa');
const pem = require('../lib/encoding/pem');
const pkcs1 = require('../lib/encoding/pkcs1');

const RSA_PRIVATE = Path.resolve(__dirname, 'data', 'rsa-private.pem');
const RSA_PUBLIC = Path.resolve(__dirname, 'data', 'rsa-public.pem');

const rsaPrivatePem = fs.readFileSync(RSA_PRIVATE, 'utf8');
const rsaPublicPem = fs.readFileSync(RSA_PUBLIC, 'utf8');
const rsaPrivateJson = require('./data/rsa-private.json');
const rsaPublicJson = require('./data/rsa-public.json');

describe('PKCS1', function() {
  it('should deserialize PKCS1 private key', () => {
    const key = pkcs1.RSAPrivateKey.fromPEM(rsaPrivatePem);
    const json = rsaPrivateJson;

    assert.strictEqual(key.version.value.toString('hex'), json.version);
    assert.strictEqual(key.n.value.toString('hex'), json.n);
    assert.strictEqual(key.e.value.toString('hex'), json.e);
    assert.strictEqual(key.d.value.toString('hex'), json.d);
    assert.strictEqual(key.p.value.toString('hex'), json.p);
    assert.strictEqual(key.q.value.toString('hex'), json.q);
    assert.strictEqual(key.dp.value.toString('hex'), json.dp);
    assert.strictEqual(key.dq.value.toString('hex'), json.dq);
    assert.strictEqual(key.qi.value.toString('hex'), json.qi);

    assert.strictEqual(key.toPEM(), rsaPrivatePem);
  });

  it('should deserialize PKCS1 public key', () => {
    const key = pkcs1.RSAPublicKey.fromPEM(rsaPublicPem);
    const json = rsaPublicJson;

    assert.strictEqual(key.n.value.toString('hex'), json.n);
    assert.strictEqual(key.e.value.toString('hex'), json.e);

    assert.strictEqual(key.toPEM(), rsaPublicPem);
  });

  it('should deserialize PKCS1 private key (backend)', () => {
    const data = pem.fromPEM(rsaPrivatePem, 'RSA PRIVATE KEY');
    const key = rsa.privateKeyImport(data);
    const json = rsaPrivateJson;

    assert.strictEqual(key.n.toString('hex'), json.n);
    assert.strictEqual(key.e.toString('hex'), json.e);
    assert.strictEqual(key.d.toString('hex'), json.d);
    assert.strictEqual(key.p.toString('hex'), json.p);
    assert.strictEqual(key.q.toString('hex'), json.q);
    assert.strictEqual(key.dp.toString('hex'), json.dp);
    assert.strictEqual(key.dq.toString('hex'), json.dq);
    assert.strictEqual(key.qi.toString('hex'), json.qi);

    const data2 = rsa.privateKeyExport(key);
    assert.bufferEqual(data, data2);
    const pem2 = pem.toPEM(data2, 'RSA PRIVATE KEY');

    assert.strictEqual(pem2, rsaPrivatePem);
  });

  it('should deserialize PKCS1 public key (backend)', () => {
    const data = pem.fromPEM(rsaPublicPem, 'RSA PUBLIC KEY');
    const key = rsa.publicKeyImport(data);
    const json = rsaPublicJson;

    assert.strictEqual(key.n.toString('hex'), json.n);
    assert.strictEqual(key.e.toString('hex'), json.e);

    const data2 = rsa.publicKeyExport(key);
    assert.bufferEqual(data, data2);
    const pem2 = pem.toPEM(data2, 'RSA PUBLIC KEY');

    assert.strictEqual(pem2, rsaPublicPem);
  });
});
