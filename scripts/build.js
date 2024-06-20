#!/usr/bin/env node

'use strict';

const bpkg = require('bpkg');
const {join} = require('path');

const targets = [
  ['node', 'bcoin-node'],
  ['spvnode', 'bcoin-spvnode'],
  ['wallet', 'bwallet'],
  ['bcoin-cli', 'bcoin-cli'],
  ['bwallet-cli', 'bwallet-cli']
];

async function main() {
  for (const [input, output] of targets) {
    const path = join('bin', input);

    console.log(`Building ${path} as ${output}`);

    await bpkg({
      env: 'node',
      input: path,
      output: output,
      extensions: ['.js']
    });
  }
}

(async () => {
  await main();
})().catch((e) => {
  process.exit(1);
});
