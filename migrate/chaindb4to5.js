'use strict';

const assert = require('assert');
const bdb = require('bdb');
const layout = require('../lib/blockchain/layout');

// changes:
// removes tx, addr indexes i.e layout.t, layout.T, layout.C

assert(process.argv.length > 2, 'Please pass in a database path.');

const db = bdb.create({
  location: process.argv[2],
  memory: false,
  compression: true,
  cacheSize: 32 << 20,
  createIfMissing: false
});

async function removeKey(name, key) {
  const iter = db.iterator({
    gte: key.min(),
    lte: key.max(),
    reverse: true,
    keys: true
  });

  let batch = db.batch();
  let total = 0;

  while (await iter.next()) {
    const {key} = iter;

    batch.del(key);

    if (++total % 10000 === 0) {
      console.log('Cleaned up %d %s index records.', total, name);
      await batch.write();
      batch = db.batch();
    }
  }

  await batch.write();

  console.log('Cleaned up %d %s index records.', total, name);
}

/*
 * Execute
 */

(async () => {
  await db.open();

  console.log('Opened %s.', process.argv[2]);
  console.log('Checking version.');
  await db.verify(layout.V.encode(), 'chain', 4);

  const t = bdb.key('t', ['hash256']);
  const T = bdb.key('T', ['hash', 'hash256']);
  const C = bdb.key('C', ['hash', 'hash256', 'uint32']);

  await removeKey('hash -> tx', t);
  await removeKey('addr -> tx', T);
  await removeKey('addr -> coin', C);

  console.log('Compacting database...');
  await db.compactRange();

  console.log('Updating version to %d.', 5);
  await db.del(layout.V.encode());
  await db.verify(layout.V.encode(), 'chain', 5);

  await db.close();
})().then(() => {
  console.log('Migration complete.');
  process.exit(0);
}).catch((err) => {
  console.error(err.stack);
  process.exit(1);
});
