'use strict';

const assert = require('assert');
const bdb = require('bdb');
const layout = require('../lib/blockchain/layout');

// changes:
// db version record
// deployment table v->D
// C/T key format

assert(process.argv.length > 2, 'Please pass in a database path.');

let parent = null;

const db = bdb.create({
  location: process.argv[2],
  memory: false,
  compression: true,
  cacheSize: 32 << 20,
  createIfMissing: false
});

async function updateVersion() {
  console.log('Checking version.');

  const data = await db.get(layout.V.build());
  assert(data, 'No version.');

  const ver = data.readUInt32LE(0, true);

  if (ver !== 3)
    throw Error(`DB is version ${ver}.`);

  console.log('Updating version to %d.', ver + 1);

  const buf = Buffer.allocUnsafe(5 + 4);
  buf.write('chain', 0, 'ascii');
  buf.writeUInt32LE(4, 5, true);

  parent.put(layout.V.build(), buf);
}

async function migrateKeys(id, from, to) {
  console.log('Migrating keys for %s.', String.fromCharCode(id));

  const iter = db.iterator({
    gt: Buffer.from([id]),
    lt: Buffer.from([id + 1]),
    keys: true
  });

  let batch = db.batch();
  let total = 0;
  let items = 0;

  await iter.each(async (key) => {
    batch.put(to.build(...from(key)), null);
    batch.del(key);

    total += (key.length + 80) * 2;
    items += 1;

    if (total >= (128 << 20)) {
      await batch.write();
      batch = db.batch();
      total = 0;
    }
  });

  console.log('Migrated %d keys for %s.', items, String.fromCharCode(id));

  return batch.write();
}

async function updateKeys() {
  console.log('Updating keys...');

  const v = Buffer.from('v', 'ascii');

  const table = await db.get(v);
  assert(table);

  parent.put(layout.D.build(), table);
  parent.del(v);

  const raw = await db.get(layout.O.build());
  assert(raw);

  const flags = raw.readUInt32LE(8, true);

  if (!(flags & 16)) {
    console.log('Updated keys.');
    return;
  }

  console.log('Updating address index keys...');

  await migrateKeys(0x54, parseT, layout.T); // T
  await migrateKeys(0xab, parseT, layout.T); // W + T
  await migrateKeys(0x43, parseC, layout.C); // C
  await migrateKeys(0x9a, parseC, layout.C); // W + C

  console.log('Updated keys.');
}

function parseT(key) {
  assert(Buffer.isBuffer(key));

  if (key.length === 65)
    return [key.slice(1, 33), key.slice(33, 65)];

  assert(key.length === 53);
  return [key.slice(1, 21), key.slice(21, 53)];
}

function parseC(key) {
  assert(Buffer.isBuffer(key));

  let addr, hash, index;

  if (key.length === 69) {
    addr = key.slice(1, 33);
    hash = key.slice(33, 65);
    index = key.readUInt32BE(65, 0);
  } else if (key.length === 57) {
    addr = key.slice(1, 21);
    hash = key.slice(21, 53);
    index = key.readUInt32BE(53, 0);
  } else {
    assert(false);
  }

  return [addr, hash, index];
}

/*
 * Execute
 */

(async () => {
  await db.open();

  console.log('Opened %s.', process.argv[2]);

  parent = db.batch();

  await updateVersion();
  await updateKeys();

  await parent.write();
  await db.close();
})().then(() => {
  console.log('Migration complete.');
  process.exit(0);
}).catch((err) => {
  console.error(err.stack);
  process.exit(1);
});
