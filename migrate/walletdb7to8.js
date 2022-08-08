'use strict';

const assert = require('assert');
const bdb = require('bdb');
const bio = require('bufio');
const layouts = require('../lib/wallet/layout');
const Coin = require('../lib/primitives/coin');
const layout = layouts.wdb;
const tlayout = layouts.txdb;

// changes:
// create u bucket to only store spendable coins

let parent = null;

assert(process.argv.length > 2, 'Please pass in a database path.');

const db = bdb.create({
  location: process.argv[2],
  memory: false,
  compression: true,
  cacheSize: 32 << 20,
  createIfMissing: false
});

async function getVersion() {
  const data = await db.get(layout.V.encode());
  assert(data, 'No version.');

  return data.readUInt32LE(6);
}

async function checkVersion(version) {
  console.log('Checking version.');

  const ver = await getVersion();

  if (ver > version) {
    console.log('Already migrated');
    process.exit(0);
  }

  if (ver !== version)
    throw Error(`DB is version ${ver}.`);
}

async function updateVersion(version) {
  await checkVersion(version - 1);

  console.log('Updating version to %d.', version);

  const buf = Buffer.allocUnsafe(6 + 4);
  buf.write('wallet', 0, 'ascii');
  buf.writeUInt32LE(version, 6);

  parent.put(layout.V.encode(), buf);
  await parent.write();
}

async function updateTXDB() {
  const wids = await db.keys({
    gte: layout.w.min(),
    lte: layout.w.max(),
    keys: true,
    parse: key => layout.w.decode(key)[0]
  });

  console.log('Updating wallets...');

  let total = 0;

  for (const wid of wids) {
    const bucket = db.bucket(layout.t.encode(wid));
    const batch = bucket.wrap(parent);
    await updateCoins(bucket, batch);
    total += 1;
  }

  console.log('Updated %d wallets.', total);
}

async function updateCoins(bucket, batch) {
  const keys = await bucket.keys({
    gte: tlayout.C.min(),
    lte: tlayout.C.max(),
    parse: (key) => {
      return tlayout.C.decode(key);
    }
  });

  const promises = [];
  // key = [account, hash, index]
  for (const key of keys) {
    promises.push(bucket.get(tlayout.c.encode(key[1], key[2])));
  }

  const credits = await Promise.all(promises);

  for (let i = 0; i < keys.length; i++) {
    const [account, hash, index] = keys[i];
    const br = bio.read(credits[i]);
    const coin = Coin.fromReader(br);
    const spent = br.readU8() === 1;
    if (!spent) {
      const key = tlayout.u.encode(account, coin.value, hash, index);
      batch.put(key, credits[i]);
    }
  }

  await batch.write();
}

(async () => {
  await db.open();

  console.log('Opened %s.', process.argv[2]);

  parent = db.batch();

  await checkVersion(7);
  await updateTXDB();
  await updateVersion(8);

  await parent.write();
  await db.close();
})().then(() => {
  console.log('Migration complete.');
  process.exit(0);
}).catch((err) => {
  console.error(err.stack);
  process.exit(1);
});
