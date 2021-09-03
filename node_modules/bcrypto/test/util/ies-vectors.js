'use strict';

const fs = require('fs');
const {resolve} = require('path');
const p192 = require('../../lib/js/p192');
const p224 = require('../../lib/js/p224');
const p256 = require('../../lib/js/p256');
const p384 = require('../../lib/js/p384');
const p521 = require('../../lib/js/p521');
const secp256k1 = require('../../lib/js/secp256k1');
const ed25519 = require('../../lib/ed25519');
const ed448 = require('../../lib/ed448');
const x25519 = require('../../lib/x25519');
const x448 = require('../../lib/x448');
const rsa = require('../../lib/rsa');
const dsa = require('../../lib/dsa');
const ecies = require('../../lib/ecies');
const dsaies = require('../../lib/dsaies');
const rsaies = require('../../lib/rsaies');
const SHA256 = require('../../lib/sha256');
const random = require('../../lib/random');

const PATH = resolve(__dirname, '..', 'data', 'ies');

const curves = [
  p192,
  p224,
  p256,
  p384,
  p521,
  secp256k1,
  ed25519,
  ed448,
  x25519,
  x448
];

for (const curve of curves) {
  const vectors = [];

  for (let i = 0; i < 16; i++) {
    const alice = curve.privateKeyGenerate();
    const bob = curve.privateKeyGenerate();
    const pub = curve.publicKeyCreate(bob);
    const msg = random.randomBytes((Math.random() * 300) | 0);
    const ct = ecies.encrypt(curve, SHA256, msg, pub, alice);

    vectors.push([
      alice.toString('hex'),
      bob.toString('hex'),
      pub.toString('hex'),
      msg.toString('hex'),
      ct.toString('hex')
    ]);
  }

  fs.writeFileSync(resolve(PATH, curve.id.toLowerCase() + '.json'),
                   JSON.stringify(vectors, null, 2) + '\n');
}

{
  const vectors = [];

  for (let i = 0; i < 16; i++) {
    let bits = 1024;
    let exp = 3;

    if ((i % 3) === 1) {
      bits = 2048;
      exp = 65537;
    } else if ((i % 3) === 2) {
      bits = 4096;
      exp = 65537;
    }

    const priv = rsa.privateKeyGenerate(bits, exp);
    const pub = rsa.publicKeyCreate(priv);
    const msg = random.randomBytes((Math.random() * 300) | 0);
    const label = Buffer.from('bcrypto');
    const ct = rsaies.encrypt(SHA256, msg, pub, 4096, label);

    vectors.push([
      rsa.privateKeyExport(priv).toString('hex'),
      rsa.publicKeyExport(pub).toString('hex'),
      msg.toString('hex'),
      ct.toString('hex')
    ]);
  }

  fs.writeFileSync(resolve(PATH, 'rsa.json'),
                   JSON.stringify(vectors, null, 2) + '\n');
}

{
  const vectors = [];

  for (let i = 0; i < 16; i++) {
    let bits = 1024;

    if ((i % 3) === 1)
      bits = 2048;
    else if ((i % 3) === 2)
      bits = 3072;

    const params = dsa.paramsGenerate(bits);
    const alice = dsa.privateKeyCreate(params);
    const bob = dsa.privateKeyCreate(params);
    const pub = dsa.publicKeyCreate(bob);
    const msg = random.randomBytes((Math.random() * 300) | 0);
    const ct = dsaies.encrypt(SHA256, msg, pub, alice);

    vectors.push([
      dsa.privateKeyExport(alice).toString('hex'),
      dsa.privateKeyExport(bob).toString('hex'),
      dsa.publicKeyExport(pub).toString('hex'),
      msg.toString('hex'),
      ct.toString('hex')
    ]);
  }

  fs.writeFileSync(resolve(PATH, 'dsa.json'),
                   JSON.stringify(vectors, null, 2) + '\n');
}
