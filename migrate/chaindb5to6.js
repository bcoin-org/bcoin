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

async function updateVersion() {
  const ver = await checkVersion();

  console.log('Updating version to %d.', ver + 1);

  const buf = Buffer.allocUnsafe(5 + 4);
  buf.write('chain', 0, 'ascii');
  buf.writeUInt32LE(6, 5, true);

  const parent = db.batch();
  parent.put(layout.V.encode(), buf);
  await parent.write();
}

async function checkVersion() {
  console.log('Checking version.');

  const data = await db.get(layout.V.encode());
  assert(data, 'No version.');

  const ver = data.readUInt32LE(5, true);

  if (ver !== 5)
    throw Error(`DB is version ${ver}.`);

  return ver;
}

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

async function migrateIndexes() {
  const t = bdb.key('t', ['hash256']);
  const T = bdb.key('T', ['hash', 'hash256']);
  const C = bdb.key('C', ['hash', 'hash256', 'uint32']);

  await removeKey('hash -> tx', t);
  await removeKey('addr -> tx', T);
  await removeKey('addr -> coin', C);
}

/*
 * Execute
 */

(async () => {
  await db.open();

  console.log('Opened %s.', process.argv[2]);

  await checkVersion();
  await migrateIndexes();
  await updateVersion();

  await db.compactRange();
  await db.close();
})().then(() => {
  console.log('Migration complete.');
  process.exit(0);
}).catch((err) => {
  console.error(err.stack);
  process.exit(1);
});
