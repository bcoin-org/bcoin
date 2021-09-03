'use strict';

const assert = require('bsert');
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
  it('should parse secp256k1 key (1)', () => {
    const key = sec1.ECPrivateKey.fromPEM(secpPem);

    assert.strictEqual(key.version.toNumber(), 1);
    assert.strictEqual(key.privateKey.value.toString('hex'), secpPriv);
    assert.strictEqual(key.namedCurveOID.getCurveName(), 'SECP256K1');
    assert.strictEqual(key.publicKey.bits, 264);
    assert.strictEqual(key.publicKey.value.toString('hex'), secpPub);
    assert.strictEqual(key.publicKey.rightAlign().toString('hex'), secpPub);
    assert.strictEqual(key.toPEM().trim(), secpPem.trim());
  });

  it('should parse secp256k1 key (2)', () => {
    const key = sec1.ECPrivateKey.fromPEM(secpPem2);

    assert.strictEqual(key.version.toNumber(), 1);
    assert.strictEqual(key.privateKey.value.toString('hex'), secpPriv);
    assert.strictEqual(key.namedCurveOID.getCurveName(), null);
    assert.strictEqual(key.publicKey.bits, 264);
    assert.strictEqual(key.publicKey.value.toString('hex'), secpPub);
    assert.strictEqual(key.publicKey.rightAlign().toString('hex'), secpPub);
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
});
