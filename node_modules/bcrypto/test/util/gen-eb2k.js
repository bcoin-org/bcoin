'use strict';

const fs = require('fs');
const crypto = require('crypto');

function createVector(pass) {
  const chacha = crypto.createCipher('chacha20', pass);
  const state = Buffer.alloc(64, 0x00);
  return chacha.update(state);
}

const vectors = [];

for (let i = 0; i < 128; i++) {
  const pass = crypto.randomBytes(Math.random() * 256 | 0);
  const state = createVector(pass);

  vectors.push([
    pass.toString('hex'),
    state.toString('hex')
  ]);
}

fs.writeFileSync(`${__dirname}/../data/eb2k.json`,
  JSON.stringify(vectors, null, 2) + '\n');
