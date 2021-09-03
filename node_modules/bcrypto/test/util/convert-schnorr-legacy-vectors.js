'use strict';

// https://github.com/sipa/bips/blob/bip-schnorr/bip-schnorr/test-vectors.csv

const csv = require('./csv');

const iter = csv.asArray(process.argv[2]);
const json = [];

// Parse test vectors.
for (const [key_, pub_, msg_, sig_, result_, comment_] of iter) {
  const key = Buffer.from(key_, 'hex');
  const pub = Buffer.from(pub_, 'hex');
  const msg = Buffer.from(msg_, 'hex');
  const sig = Buffer.from(sig_, 'hex');
  const result = result_ === 'TRUE';
  const comment = comment_ || null;

  json.push([
    key.toString('hex'),
    pub.toString('hex'),
    msg.toString('hex'),
    sig.toString('hex'),
    result,
    comment
  ]);
}

console.log(JSON.stringify(json, null, 2));
