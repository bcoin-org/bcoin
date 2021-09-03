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
const SHA1 = require('../../lib/sha1');
const SHA256 = require('../../lib/sha256');
const BLAKE2s256 = require('../../lib/blake2s256');
const random = require('../../lib/random');

const PATH = resolve(__dirname, '..', 'data', 'sign');

const ecdsa = [
  p192,
  p224,
  p256,
  p384,
  p521,
  secp256k1
];

const eddsa = [
  [ed25519, x25519],
  [ed448, x448]
];

const x = [
  x25519,
  x448
];

function jsonify(obj) {
  const out = {};

  for (const key of Object.keys(obj)) {
    if (Buffer.isBuffer(obj[key]))
      out[key] = obj[key].toString('hex');
    else
      out[key] = obj[key];
  }

  return out;
}

for (const curve of ecdsa) {
  const vectors = [];

  for (let i = 0; i < 16; i++) {
    const priv = curve.privateKeyGenerate();
    const pub = curve.publicKeyCreate(priv);
    const tweak = curve.privateKeyGenerate();
    const privAdd = curve.privateKeyTweakAdd(priv, tweak);
    const privMul = curve.privateKeyTweakMul(priv, tweak);
    const privNeg = curve.privateKeyNegate(priv);
    const privInv = curve.privateKeyInvert(priv);
    const pubAdd = curve.publicKeyTweakAdd(pub, tweak);
    const pubMul = curve.publicKeyTweakMul(pub, tweak);
    const pubNeg = curve.publicKeyNegate(pub);
    const pubDbl = curve.publicKeyCombine([pub, pub]);
    const pubConv = curve.publicKeyConvert(pub, false);
    const pubHybrid = Buffer.from(pubConv);
    const privJSON = jsonify(curve.privateKeyExport(priv));
    const pubJSON = jsonify(curve.publicKeyExport(pub));
    const msg = random.randomBytes(curve.hash.size);
    const [signature, recovery] = curve.signRecoverable(msg, priv);
    const other = curve.privateKeyGenerate();
    const secret = curve.derive(pub, other);

    pubHybrid[0] = 0x06 | (pubHybrid[pubHybrid.length - 1] & 1);

    vectors.push([
      priv.toString('hex'),
      pub.toString('hex'),
      tweak.toString('hex'),
      privAdd.toString('hex'),
      privMul.toString('hex'),
      privNeg.toString('hex'),
      privInv.toString('hex'),
      pubAdd.toString('hex'),
      pubMul.toString('hex'),
      pubNeg.toString('hex'),
      pubDbl.toString('hex'),
      pubConv.toString('hex'),
      pubHybrid.toString('hex'),
      privJSON,
      pubJSON,
      msg.toString('hex'),
      signature.toString('hex'),
      curve.signatureExport(signature).toString('hex'),
      recovery,
      other.toString('hex'),
      secret.toString('hex')
    ]);
  }

  fs.writeFileSync(resolve(PATH, curve.id.toLowerCase() + '.json'),
                   JSON.stringify(vectors, null, 2) + '\n');
}

for (const [curve, x] of eddsa) {
  const vectors = [];

  for (let i = 0; i < 32; i++) {
    const priv = curve.privateKeyGenerate();
    const [scalar, prefix] = curve.privateKeyExpand(priv);
    const reduced = curve.scalarReduce(scalar);
    const pub = curve.publicKeyFromScalar(scalar);
    const tweak = curve.scalarGenerate();
    const privAdd = curve.scalarTweakAdd(scalar, tweak);
    const privMul = curve.scalarTweakMul(scalar, tweak);
    const privNeg = curve.scalarNegate(scalar);
    const privInv = curve.scalarInvert(scalar);
    const pubAdd = curve.publicKeyTweakAdd(pub, tweak);
    const pubMul = curve.publicKeyTweakMul(pub, tweak);
    const pubNeg = curve.publicKeyNegate(pub);
    const pubDbl = curve.publicKeyCombine([pub, pub]);
    const pubConv = curve.publicKeyConvert(pub);
    const privJSON = jsonify(curve.privateKeyExport(priv));
    const pubJSON = jsonify(curve.publicKeyExport(pub));
    const msg = random.randomBytes(curve.size);
    const ph = (i & 1) === 0 ? null : true;
    const sig = curve.sign(msg, priv, ph);
    const sigAdd = curve.signTweakAdd(msg, priv, tweak, ph);
    const sigMul = curve.signTweakMul(msg, priv, tweak, ph);
    const other = curve.privateKeyGenerate();
    const edSecret = curve.derive(pub, other);
    const montSecret = x.derive(pubConv, curve.privateKeyConvert(other));

    vectors.push([
      priv.toString('hex'),
      scalar.toString('hex'),
      prefix.toString('hex'),
      reduced.toString('hex'),
      pub.toString('hex'),
      tweak.toString('hex'),
      privAdd.toString('hex'),
      privMul.toString('hex'),
      privNeg.toString('hex'),
      privInv.toString('hex'),
      pubAdd.toString('hex'),
      pubMul.toString('hex'),
      pubNeg.toString('hex'),
      pubDbl.toString('hex'),
      pubConv.toString('hex'),
      privJSON,
      pubJSON,
      msg.toString('hex'),
      ph,
      sig.toString('hex'),
      sigAdd.toString('hex'),
      sigMul.toString('hex'),
      other.toString('hex'),
      edSecret.toString('hex'),
      montSecret.toString('hex')
    ]);
  }

  fs.writeFileSync(resolve(PATH, curve.id.toLowerCase() + '.json'),
                   JSON.stringify(vectors, null, 2) + '\n');
}

for (const ka of x) {
  const vectors = [];

  for (let i = 0; i < 32; i++) {
    const priv = ka.privateKeyGenerate();
    const pub = ka.publicKeyCreate(priv);
    const json = jsonify(ka.privateKeyExport(priv));
    const secret = ka.derive(pub, priv);

    vectors.push([
      priv.toString('hex'),
      pub.toString('hex'),
      json,
      secret.toString('hex')
    ]);
  }

  fs.writeFileSync(resolve(PATH, ka.id.toLowerCase() + '.json'),
                   JSON.stringify(vectors, null, 2) + '\n');
}

{
  const vectors = [];

  for (let i = 0; i < 16; i++) {
    const r1 = Math.random() * 3 | 0;
    const r2 = Math.random() * 2 | 0;
    const label = Buffer.from('bcrypto');

    let hash = SHA1;
    let bits = 1024;
    let exp = 3;
    let saltLen = -1;

    if ((i % 3) === 1) {
      bits = 2048;
      exp = 65537;
    } else if ((i % 3) === 2) {
      bits = 4096;
      exp = 65537;
    }

    if (r1 === 1)
      hash = SHA256;
    else if (r1 === 2)
      hash = BLAKE2s256;

    if (r2 === 1)
      saltLen = 0;

    const priv = rsa.privateKeyGenerate(bits, exp);
    const pub = rsa.publicKeyCreate(priv);
    const msg = random.randomBytes(hash.size);
    const sig1 = rsa.sign(hash, msg, priv);
    const sig2 = rsa.signPSS(hash, msg, priv, saltLen);
    const ct1 = rsa.encrypt(msg, priv);
    const ct2 = rsa.encryptOAEP(hash, msg, priv, label);
    const padded = Buffer.alloc(priv.size(), 0x00);
    msg.copy(padded, padded.length - hash.size);
    const ct3 = rsa.encryptRaw(padded, priv);

    vectors.push([
      jsonify(rsa.privateKeyExport(priv)),
      jsonify(rsa.publicKeyExport(pub)),
      hash.id,
      saltLen,
      msg.toString('hex'),
      sig1.toString('hex'),
      sig2.toString('hex'),
      ct1.toString('hex'),
      ct2.toString('hex'),
      ct3.toString('hex')
    ]);
  }

  fs.writeFileSync(resolve(PATH, 'rsa.json'),
                   JSON.stringify(vectors, null, 2) + '\n');
}

{
  const vectors = [];

  for (let i = 0; i < 16; i++) {
    let bits = 1024;
    let size = 20;

    if ((i % 3) === 1) {
      bits = 2048;
      size = 32;
    } else if ((i % 3) === 2) {
      bits = 3072;
      size = 32;
    }

    const params = dsa.paramsGenerate(bits);
    const priv = dsa.privateKeyCreate(params);
    const pub = dsa.publicKeyCreate(priv);
    const msg = random.randomBytes(size);
    const sig = dsa.sign(msg, priv);

    vectors.push([
      jsonify(dsa.paramsExport(params)),
      jsonify(dsa.privateKeyExport(priv)),
      jsonify(dsa.publicKeyExport(pub)),
      msg.toString('hex'),
      sig.toString('hex'),
      dsa.signatureExport(sig).toString('hex')
    ]);
  }

  fs.writeFileSync(resolve(PATH, 'dsa.json'),
                   JSON.stringify(vectors, null, 2) + '\n');
}
