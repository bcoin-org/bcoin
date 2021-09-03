'use strict';

const fs = require('fs');
const secp256k1 = require('../../lib/secp256k1');
const random = require('../../lib/random');
const vectors = [];

for (let i = 0; i < 256; i++) {
  const key = secp256k1.privateKeyGenerate();
  const pub = secp256k1.publicKeyCreate(key);
  const msg = random.randomBytes(32);
  const sig = secp256k1.schnorrSign(msg, key);

  let priv = key;
  let result = true;
  let comment = null;

  if ((i % 4) === 1) {
    sig[i % sig.length] ^= 1;
    comment = 'mutated signature';
  } else if ((i % 4) === 2) {
    pub[i % pub.length] ^= 1;
    comment = 'mutated key';
  } else if ((i % 4) === 3) {
    msg[i % msg.length] ^= 1;
    comment = 'mutated message';
  }

  if ((i % 4) !== 0) {
    priv = Buffer.alloc(0);
    result = false;
  }

  vectors.push([
    priv.toString('hex'),
    pub.toString('hex'),
    msg.toString('hex'),
    sig.toString('hex'),
    result,
    comment
  ]);
}

fs.writeFileSync(`${__dirname}/../data/schnorr-legacy-custom.json`,
  JSON.stringify(vectors, null, 2) + '\n');
