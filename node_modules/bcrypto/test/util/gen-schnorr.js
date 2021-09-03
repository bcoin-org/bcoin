'use strict';

const fs = require('fs');
const schnorr = require('../../lib/js/schnorr');
const random = require('../../lib/random');
const vectors = [];

for (let i = 0; i < 256; i++) {
  const key = schnorr.privateKeyGenerate();
  const pub = schnorr.publicKeyCreate(key);
  const msg = random.randomBytes(32);
  const sig = schnorr.schnorrSign(msg, key);

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
    String(i),
    priv.toString('hex'),
    pub.toString('hex'),
    msg.toString('hex'),
    sig.toString('hex'),
    result,
    comment
  ]);
}

fs.writeFileSync(`${__dirname}/../data/schnorr-custom.json`,
  JSON.stringify(vectors, null, 2) + '\n');
