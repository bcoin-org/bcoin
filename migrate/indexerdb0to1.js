'use strict';

const assert = require('assert');
const hash256 = require('bcrypto/lib/hash256');
const Filter = require('../lib/primitives/filter');
const layout = require('../lib/indexer/layout');
const FileBlockStore = require('../lib/blockstore/file');
const bdb = require('bdb');
const path = require('path');
const fs = require('bfile');
const {filters} = require('../lib/blockstore/common');

assert(process.argv.length > 2, 'Please pass in a database path.');

// change:
// Move filter data present in ~/.../filter/ to ~/.../filter/BASIC

const location = path.resolve(process.argv[2], '../blocks');
const blockStore = new FileBlockStore({
  location: location
});

Object.assign(layout, {
  f: bdb.key('f', ['hash256'])
});

async function getVersion(db) {
  const data = await db.get(layout.V.encode());
  assert(data, 'No version.');

  return data.readUInt32LE(5, true);
}

async function updateVersion(db, version) {
  console.log('Updating version to %d.', version);

  await checkVersion(db, version - 1);

  const buf = Buffer.allocUnsafe(5 + 4);
  buf.write('index', 0, 'ascii');
  buf.writeUInt32LE(version, 5, true);

  const parent = db.batch();
  parent.put(layout.V.encode(), buf);
  await parent.write();
}

async function updateChainVersion(db, version) {
  console.log('Updating chainDB version to %d.', version);

  await checkVersion(db, version - 1);

  const buf = Buffer.allocUnsafe(5 + 4);
  buf.write('chain', 0, 'ascii');
  buf.writeUInt32LE(version, 5, true);

  const parent = db.batch();
  parent.put(layout.V.encode(), buf);
  await parent.write();
}

async function updateChainDB(chain) {
  const chainDB = bdb.create({
    location: chain,
    compression: true,
    cacheSize: 32 << 20,
    createIfMissing: false
  });

  await chainDB.open();
  console.log('Opened %s.', chain);

  const chainVersion = await getVersion(chainDB);
  if (chainVersion === 6) {
    await updateChainVersion(chainDB, 7);
  }
  await chainDB.close();
}

async function checkVersion(db, version) {
  console.log('Checking version.');

  const ver = await getVersion(db);

  if (ver !== version)
    throw Error(`DB is version ${ver}.`);

  return ver;
}

async function migrateFilter(db) {
  console.log('Migrating filters..');
  let parent  = db.batch();

  const iter = db.iterator({
    gte: layout.h.min(),
    lte: layout.h.max(),
    keys: true,
    values: true
  });

  const migratedDB = bdb.create({
    location: path.join(db.location, 'BASIC'),
    memory: false,
    compression: true,
    createIfMissing: true
  });

  await migratedDB.open();

  let parentMigratedDB = migratedDB.batch();

  let migratedFilters = 0;

  await iter.each(async (height, hash) => {
    const rawFilter = await blockStore.readFilter(hash, filters.BASIC);
    const filter = Filter.fromRaw(rawFilter);
    const filterHash = hash256.digest(filter.filter);

    parentMigratedDB.put(height, hash);
    parent.del(height);

    parentMigratedDB.put(layout.f.encode(hash), filterHash);
    parent.del(layout.f.encode(hash));

    migratedFilters += 1;

    if (migratedFilters % 10000 === 0) {
      console.log('migrated %d filters.', migratedFilters);
      await parentMigratedDB.write();
      await parent.write();

      parentMigratedDB = migratedDB.batch();
      parent = db.batch();
    }
  });

  let raw = await db.get(layout.R.encode());
  parentMigratedDB.put(layout.R.encode(), raw);
  parent.del(layout.R.encode());

  raw = await db.get(layout.O.encode());
  parentMigratedDB.put(layout.O.encode(), raw);
  parent.del(layout.O.encode());

  await updateVersion(db, 1);
  raw = await db.get(layout.V.encode());
  parentMigratedDB.put(layout.V.encode(), raw);
  parent.del(layout.V.encode());
  console.log('Filter DB updated to version 1');

  await parentMigratedDB.write();
  await parent.write();

  console.log('%d filters migrated.', migratedFilters);

  await db.close();
  await db.destroy();

  await migratedDB.close();
}

/*
 * Execute
 */

let count = 0;

(async () => {
  const indexesLocation = path.resolve(process.argv[2]);
  const indexes = ['tx', 'addr', 'filter'];

  for (const index of indexes) {
    const location = path.join(indexesLocation, index);
    if (!(await fs.exists(location))) {
      continue;
    }

    const db = bdb.create({
      location: location,
      memory: false,
      compression: true,
      createIfMissing: false
    });

    console.log('Opened %s.', location);
    try {
      await db.open();
    } catch (e) {
      continue;
    }

    const version = await getVersion(db);

    switch (version) {
      case 0:
        if (index === 'filter') {
          await blockStore.ensure();
          await blockStore.open();
          await migrateFilter(db);
          count += 1;

          await blockStore.close();
        } else {
          await updateVersion(db, 1);
          count += 1;

          await db.close();
        }
        console.log('Migration complete');
        break;
      case 1:
        console.log('Already upgraded.');
        break;
      default:
        console.log(`DB version is ${version}.`);
    }
  }

  // Updating chainDB version to ensure
  // filter indexes are not duplicated.
  const chain = path.resolve(process.argv[2], '../chain');
  if (await fs.exists(chain)) {
    await updateChainDB(chain);
  }

  // update spvChainDB if it exists
  const spvchain = path.resolve(process.argv[2], '../spvchain');
  if (await fs.exists(spvchain)) {
    await updateChainDB(spvchain);
  }
})().then(() => {
  console.log('Migrated %d databases.', count);
  process.exit(0);
}).catch((err) => {
  console.error(err.stack);
  process.exit(1);
});
