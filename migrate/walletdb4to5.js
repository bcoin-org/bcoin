'use strict';

const assert = require('assert');
const bcoin = require('../');
let file = process.argv[2];
let db, batch;

assert(typeof file === 'string', 'Please pass in a database path.');

file = file.replace(/\.ldb\/?$/, '');

db = bcoin.ldb({
  location: file,
  db: 'leveldb',
  compression: true,
  cacheSize: 32 << 20,
  createIfMissing: false,
  bufferKeys: true
});

async function updateVersion() {
  let bak = `${process.env.HOME}/walletdb-bak-${Date.now()}.ldb`;
  let data, ver;

  console.log('Checking version.');

  data = await db.get('V');
  assert(data, 'No version.');

  ver = data.readUInt32LE(0, true);

  if (ver !== 4)
    throw Error(`DB is version ${ver}.`);

  console.log('Backing up DB to: %s.', bak);

  await db.backup(bak);

  ver = Buffer.allocUnsafe(4);
  ver.writeUInt32LE(5, 0, true);
  batch.put('V', ver);
}

async function updateTXDB() {
  let i, keys, key;

  keys = await db.keys({
    gte: Buffer.from([0x00]),
    lte: Buffer.from([0xff])
  });

  for (i = 0; i < keys.length; i++) {
    key = keys[i];
    switch (key[0]) {
      case 0x62: // b
      case 0x63: // c
      case 0x65: // e
      case 0x74: // t
        batch.del(key);
        break;
    }
  }

  await batch.write();
}

(async () => {
  await db.open();
  batch = db.batch();
  console.log('Opened %s.', file);
  await updateVersion();
  await updateTXDB();
  await db.close();
})().then(() => {
  console.log('Migration complete.');
  process.exit(0);
});
