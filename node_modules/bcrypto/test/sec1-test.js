/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('bsert');

const parts = process.version.split(/[^\d]/);
const NODE_MAJOR = parts[1] >>> 0;

const ECDSA = (() => {
  if (!process.env.NODE_BACKEND || process.env.NODE_BACKEND === 'native') {
    if (NODE_MAJOR >= 10)
      return require('../lib/native/ecdsa');
  }
  return require('../lib/js/ecdsa');
})();

const p256 = require('../lib/p256');
const secp256k1 = require('../lib/secp256k1');
const secp256k1e = new ECDSA('SECP256K1', require('../lib/sha256'));
const pem = require('../lib/encoding/pem');
const sec1 = require('../lib/encoding/sec1');

const secpPriv =
  '47241e0e57d721fb1d89546bdc6c89ef9ece2f68c6d9ae59e1fe234917b74d4d';

const secpPub =
  '02c0d5ad34fd41ab7852c8488db707bc016aedf689470239e365889fd98c26803b';

const secpPem = `
-----BEGIN EC PRIVATE KEY-----
MFQCAQEEIEckHg5X1yH7HYlUa9xsie+ezi9oxtmuWeH+I0kXt01NoAcGBSuBBAAK
oSQDIgACwNWtNP1Bq3hSyEiNtwe8AWrt9olHAjnjZYif2YwmgDs=
-----END EC PRIVATE KEY-----
`;

const secpPem2 = `
-----BEGIN EC PRIVATE KEY-----
MIHTAgEBBCBHJB4OV9ch+x2JVGvcbInvns4vaMbZrlnh/iNJF7dNTaCBhTCBggIB
ATAsBgcqhkjOPQEBAiEA/////////////////////////////////////v///C8w
BgQBAAQBBwQhAnm+Zn753LusVaBilc6HCwcCm/zbLc4o2VnygVsW+BeYAiEA////
/////////////////rqu3OavSKA7v9JejNA2QUECAQGhJAMiAALA1a00/UGreFLI
SI23B7wBau32iUcCOeNliJ/ZjCaAOw==
-----END EC PRIVATE KEY-----
`;

const p256Priv =
  '55d8cac4638da243144e390c81507042af5f5d90af5a672fdeafaa250a73e944';

const p256Pub =
  '03c2f2b14bf9f6b395c254f3b5c121e034597b3065fa96777dfaa7ae70412033ff';

const p256Pem = `
-----BEGIN EC PRIVATE KEY-----
MFcCAQEEIFXYysRjjaJDFE45DIFQcEKvX12Qr1pnL96vqiUKc+lEoAoGCCqGSM49
AwEHoSQDIgADwvKxS/n2s5XCVPO1wSHgNFl7MGX6lnd9+qeucEEgM/8=
-----END EC PRIVATE KEY-----
`;

describe('SEC1', function() {
  it('should parse secp256k1 key', () => {
    const key = sec1.ECPrivateKey.fromPEM(secpPem);

    assert.strictEqual(key.version.toNumber(), 1);
    assert.strictEqual(key.privateKey.value.toString('hex'), secpPriv);
    assert.strictEqual(key.namedCurveOID.getCurveName(), 'SECP256K1');
    assert.strictEqual(key.publicKey.bits, 264);
    assert.strictEqual(key.publicKey.value.toString('hex'), secpPub);
    assert.strictEqual(key.publicKey.rightAlign().toString('hex'), secpPub);
    assert.strictEqual(key.toPEM().trim(), secpPem.trim());
  });

  it('should parse secp256k1 key (secp256k1-node)', () => {
    const key = sec1.ECPrivateKey.fromPEM(secpPem2);

    assert.strictEqual(key.version.toNumber(), 1);
    assert.strictEqual(key.privateKey.value.toString('hex'), secpPriv);
    assert.strictEqual(key.namedCurveOID.getCurveName(), null);
    assert.strictEqual(key.publicKey.bits, 264);
    assert.strictEqual(key.publicKey.value.toString('hex'), secpPub);
    assert.strictEqual(key.publicKey.rightAlign().toString('hex'), secpPub);
  });

  it('should parse secp256k1 key (backend)', () => {
    const str = secpPem;
    const data = pem.fromPEM(str, 'EC PRIVATE KEY');
    const key = secp256k1.privateKeyImport(data);

    assert.strictEqual(key.toString('hex'), secpPriv);
    assert.strictEqual(secp256k1.publicKeyCreate(key).toString('hex'), secpPub);

    const data2 = secp256k1.privateKeyExport(key);
    const pem2 = pem.toPEM(data2, 'EC PRIVATE KEY');

    assert.strictEqual(pem2.trim(), str.trim());
  });

  it('should parse secp256k1 key (backend, secp256k1-node)', () => {
    const str = secpPem2;
    const data = pem.fromPEM(str, 'EC PRIVATE KEY');
    const key = secp256k1.privateKeyImport(data);

    assert.strictEqual(key.toString('hex'), secpPriv);
    assert.strictEqual(secp256k1.publicKeyCreate(key).toString('hex'), secpPub);
  });

  it('should parse secp256k1 key (backend-ossl, secp256k1-node)', () => {
    const str = secpPem2;
    const data = pem.fromPEM(str, 'EC PRIVATE KEY');
    const key = secp256k1e.privateKeyImport(data);

    assert.strictEqual(key.toString('hex'), secpPriv);
    assert.strictEqual(
      secp256k1e.publicKeyCreate(key).toString('hex'),
      secpPub);
  });

  it('should parse p256 key', () => {
    const key = sec1.ECPrivateKey.fromPEM(p256Pem);

    assert.strictEqual(key.version.toNumber(), 1);
    assert.strictEqual(key.privateKey.value.toString('hex'), p256Priv);
    assert.strictEqual(key.namedCurveOID.getCurveName(), 'P256');
    assert.strictEqual(key.publicKey.bits, 264);
    assert.strictEqual(key.publicKey.value.toString('hex'), p256Pub);
    assert.strictEqual(key.publicKey.rightAlign().toString('hex'), p256Pub);
    assert.strictEqual(key.toPEM().trim(), p256Pem.trim());
  });

  it('should parse p256 key (backend)', () => {
    const data = pem.fromPEM(p256Pem, 'EC PRIVATE KEY');
    const key = p256.privateKeyImport(data);

    assert.strictEqual(key.toString('hex'), p256Priv);
    assert.strictEqual(p256.publicKeyCreate(key).toString('hex'), p256Pub);

    const data2 = p256.privateKeyExport(key);
    const pem2 = pem.toPEM(data2, 'EC PRIVATE KEY');

    assert.strictEqual(pem2.trim(), p256Pem.trim());
  });
});
