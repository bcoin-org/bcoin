#!/usr/bin/env node

/*!
 * commit-tree.js - git commit sha512 tree hashes
 * Copyright (c) 2018, the bcoin developers (MIT License).
 * https://github.com/bcoin-org/bcoin
 *
 * Based on:
 * - https://github.com/bitcoin/bitcoin/commit/fa89670d34ac7839e7e2fe6f59fdfd6cc76c4483
 * - https://github.com/bitcoin/bitcoin/pull/9871
 *
 * Modify git commit message with Tree-SHA512:
 * ```
 * ./scripts/commit-tree.js <message>
 * ```
 *
 * Verify tree hashes by running:
 * ```
 * git ls-tree --full-tree -r --name-only HEAD | LANG=C sort \
 *   | xargs -n 1 sha512sum | sha512sum
 * ```
 */

'use strict';

const path = require('path');
const {createReadStream} = require('fs');
const {execFile} = require('child_process');
const SHA512 = require('bcrypto/lib/sha512');

process.title = 'bcoin-commit-tree';

async function gitTreeList() {
  return new Promise((resolve, reject) => {
    execFile(
      'git', ['ls-tree', '--full-tree', '-r', '--name-only', 'HEAD'],
      (err, stdout) => {
        if (err)
          reject(err);
        resolve(stdout.trim().split('\n').sort());
      });
  });
}

async function hashFile(file) {
  const ctx = new SHA512().init();

  return new Promise((resolve, reject) => {
    createReadStream(file, {flags: 'r'})
      .on('error', reject)
      .on('data', data => ctx.update(data))
      .on('end', () => resolve(ctx.final()));
  });
}

async function gitTreeHash() {
  const files = await gitTreeList();
  const ctx = new SHA512().init();

  while (files.length > 0) {
    const f = files.shift();
    const hash = await hashFile(f);
    ctx.update(Buffer.from(hash.toString('hex'), 'utf8'));
    ctx.update(Buffer.from(`  ${f}\n`, 'utf8'));
  }

  return ctx.final();
}

async function gitCommitMessage(message, signed, amend) {
  return new Promise((resolve, reject) => {
    let args = ['commit'];

    if (signed)
      args.push('-S');

    if (amend)
      args.push('--amend');

    args = args.concat(['-m', message]);

    execFile('git', args, (err, stdout) => {
      if (err)
        reject(err);
      resolve(stdout);
    });
  });
}

(async () => {
  const toplevel = path.resolve(__dirname, '../');
  process.chdir(toplevel);

  let message = '';

  if (process.argv.length > 2)
    message += `${process.argv[2]}\n\n`;

  const firstHash = await gitTreeHash();
  message += `Tree-SHA512: ${firstHash.toString('hex')}`;

  const output = await gitCommitMessage(message, true, true);
  process.stdout.write(output);

  const secondHash = await gitTreeHash();
  if (!secondHash.equals(firstHash))
    throw new Error('Tree hash changed unexpectedly.');
})().catch((err) => {
  console.log(err);
  process.exit(1);
});
