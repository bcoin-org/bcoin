'use strict';

const bcoin = require('../');
const assert = require('assert');
const BufferWriter = require('../lib/utils/writer');
let file = process.argv[2];

assert(typeof file === 'string', 'Please pass in a database path.');

file = file.replace(/\.ldb\/?$/, '');

const db = bcoin.ldb({
  location: file,
  db: 'leveldb',
  compression: true,
  cacheSize: 32 << 20,
  createIfMissing: false,
  bufferKeys: true
});

function makeKey(data) {
  let height = data.readUInt32LE(1, true);
  let key = Buffer.allocUnsafe(5);
  key[0] = 0x48;
  key.writeUInt32BE(height, 1, true);
  return key;
}

async function checkVersion() {
  let data, ver;

  console.log('Checking version.');

  data = await db.get('V');

  if (!data)
    return;

  ver = data.readUInt32LE(0, true);

  if (ver !== 0)
    throw Error(`DB is version ${ver}.`);
}

async function updateState() {
  let data, hash, batch, ver, p;

  console.log('Updating chain state.');

  data = await db.get('R');

  if (!data || data.length < 32)
    throw new Error('No chain state.');

  hash = data.slice(0, 32);

  p = new BufferWriter();
  p.writeHash(hash);
  p.writeU64(0);
  p.writeU64(0);
  p.writeU64(0);
  p = p.render();

  batch = db.batch();

  batch.put('R', p);

  ver = Buffer.allocUnsafe(4);
  ver.writeUInt32LE(1, 0, true);
  batch.put('V', ver);

  await batch.write();

  console.log('Updated chain state.');
}

async function updateEndian() {
  let batch = db.batch();
  let total = 0;
  let iter, item;

  console.log('Updating endianness.');
  console.log('Iterating...');

  iter = db.iterator({
    gte: Buffer.from('4800000000', 'hex'),
    lte: Buffer.from('48ffffffff', 'hex'),
    values: true
  });

  for (;;) {
    item = await iter.next();

    if (!item)
      break;

    batch.del(item.key);
    batch.put(makeKey(item.key), item.value);
    total++;
  }

  console.log('Migrating %d items.', total);

  await batch.write();

  console.log('Migrated endianness.');
}

(async () => {
  await db.open();
  console.log('Opened %s.', file);
  await checkVersion();
  await updateState();
  await updateEndian();
})().then(() => {
  console.log('Migration complete.');
  process.exit(0);
});
