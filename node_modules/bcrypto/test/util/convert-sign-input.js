'use strict';

// https://ed25519.cr.yp.to/software.html
// https://ed25519.cr.yp.to/python/sign.input

const fs = require('fs');
const text = fs.readFileSync(process.argv[2], 'binary');
const lines = text.trim().split('\n');
const json = [];

for (const line of lines) {
  const parts = line.toUpperCase().split(':');
  const secret = Buffer.from(parts[0].slice(0, 64), 'hex');
  const pub = Buffer.from(parts[0].slice(64), 'hex');
  const msg = Buffer.from(parts[2], 'hex');
  const sig = Buffer.from(parts[3].slice(0, 128), 'hex');

  json.push([
    secret.toString('hex'),
    pub.toString('hex'),
    msg.toString('hex'),
    sig.toString('hex')
  ]);
}

console.log(JSON.stringify(json, null, 2));
