/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('bsert');
const Path = require('path');
const fs = require('fs');
const dsa = require('../lib/dsa');
const pem = require('../lib/encoding/pem');
const openssl = require('../lib/encoding/openssl');

const DSA_PARAMS = Path.resolve(__dirname, 'data', 'dsa-parameters.pem');
const DSA_PRIVATE = Path.resolve(__dirname, 'data', 'dsa-private.pem');
const DSA_PUBLIC = Path.resolve(__dirname, 'data', 'dsa-public.pem');

const dsaParamsPem = fs.readFileSync(DSA_PARAMS, 'utf8');
const dsaPrivatePem = fs.readFileSync(DSA_PRIVATE, 'utf8');
const dsaPublicPem = fs.readFileSync(DSA_PUBLIC, 'utf8');
const dsaParamsJson = require('./data/dsa-parameters.json');
const dsaPrivateJson = require('./data/dsa-private.json');
const dsaPublicJson = require('./data/dsa-public.json');

describe('OpenSSL', function() {
  it('should deserialize DSA parameters', () => {
    const key = openssl.DSAParams.fromPEM(dsaParamsPem);
    const json = dsaParamsJson;

    assert.strictEqual(key.p.value.toString('hex'), json.p);
    assert.strictEqual(key.q.value.toString('hex'), json.q);
    assert.strictEqual(key.g.value.toString('hex'), json.g);

    assert.strictEqual(key.toPEM(), dsaParamsPem);
  });

  it('should deserialize DSA private key', () => {
    const key = openssl.DSAPrivateKey.fromPEM(dsaPrivatePem);
    const json = dsaPrivateJson;

    assert.strictEqual(key.version.value.toString('hex'), json.version);
    assert.strictEqual(key.p.value.toString('hex'), json.p);
    assert.strictEqual(key.q.value.toString('hex'), json.q);
    assert.strictEqual(key.g.value.toString('hex'), json.g);
    assert.strictEqual(key.y.value.toString('hex'), json.y);
    assert.strictEqual(key.x.value.toString('hex'), json.x);

    assert.strictEqual(key.toPEM(), dsaPrivatePem);
  });

  it('should deserialize DSA public key', () => {
    const key = openssl.DSAPublicKey.fromPEM(dsaPublicPem);
    const json = dsaPublicJson;

    assert.strictEqual(key.p.value.toString('hex'), json.p);
    assert.strictEqual(key.q.value.toString('hex'), json.q);
    assert.strictEqual(key.g.value.toString('hex'), json.g);
    assert.strictEqual(key.y.value.toString('hex'), json.y);

    assert.strictEqual(key.toPEM(), dsaPublicPem);
  });

  it('should deserialize DSA private key (backend)', () => {
    const data = pem.fromPEM(dsaPrivatePem, 'DSA PRIVATE KEY');
    const key = dsa.privateKeyImport(data);
    const json = dsaPrivateJson;

    assert.strictEqual(key.p.toString('hex'), json.p);
    assert.strictEqual(key.q.toString('hex'), json.q);
    assert.strictEqual(key.g.toString('hex'), json.g);
    assert.strictEqual(key.y.toString('hex'), json.y);
    assert.strictEqual(key.x.toString('hex'), json.x);

    const data2 = dsa.privateKeyExport(key);
    assert.bufferEqual(data, data2);
    const pem2 = pem.toPEM(data2, 'DSA PRIVATE KEY');

    assert.strictEqual(pem2, dsaPrivatePem);
  });

  it('should deserialize DSA public key (backend)', () => {
    const data = pem.fromPEM(dsaPublicPem, 'DSA PUBLIC KEY');
    const key = dsa.publicKeyImport(data);
    const json = dsaPublicJson;

    assert.strictEqual(key.p.toString('hex'), json.p);
    assert.strictEqual(key.q.toString('hex'), json.q);
    assert.strictEqual(key.g.toString('hex'), json.g);
    assert.strictEqual(key.y.toString('hex'), json.y);

    const data2 = dsa.publicKeyExport(key);
    assert.bufferEqual(data, data2);
    const pem2 = pem.toPEM(data2, 'DSA PUBLIC KEY');

    assert.strictEqual(pem2, dsaPublicPem);
  });
});
