'use strict';

const assert = require('assert');
const bcoin = require('../');
const encoding = require('../lib/utils/encoding');
const WalletDB = require('../lib/wallet/walletdb');
const BufferReader = require('../lib/utils/reader');
const TX = require('../lib/primitives/tx');
const Coin = require('../lib/primitives/coin');
let file = process.argv[2];
let batch;

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

async function updateVersion() {
  const bak = `${process.env.HOME}/walletdb-bak-${Date.now()}.ldb`;

  console.log('Checking version.');

  const data = await db.get('V');
  assert(data, 'No version.');

  let ver = data.readUInt32LE(0, true);

  if (ver !== 3)
    throw Error(`DB is version ${ver}.`);

  console.log('Backing up DB to: %s.', bak);

  await db.backup(bak);

  ver = Buffer.allocUnsafe(4);
  ver.writeUInt32LE(4, 0, true);
  batch.put('V', ver);
}

async function updateTXDB() {
  let txs = {};

  const keys = await db.keys({
    gte: Buffer.from([0x00]),
    lte: Buffer.from([0xff])
  });

  for (let i = 0; i < keys.length; i++) {
    const key = keys[i];
    if (key[0] === 0x74 && key[5] === 0x74) {
      let tx = await db.get(key);
      tx = fromExtended(tx);
      const hash = tx.hash('hex');
      txs[hash] = tx;
    }
    if (key[0] === 0x74)
      batch.del(key);
  }

  txs = getValues(txs);

  await batch.write();
  await db.close();

  const walletdb = new WalletDB({
    location: file,
    db: 'leveldb',
    resolution: true,
    verify: false,
    network: process.argv[3]
  });

  await walletdb.open();

  for (let i = 0; i < txs.length; i++) {
    const tx = txs[i];
    await walletdb.addTX(tx);
  }

  await walletdb.close();
}

function fromExtended(data, saveCoins) {
  const tx = new TX();
  const p = BufferReader(data);

  tx.fromRaw(p);

  tx.height = p.readU32();
  tx.block = p.readHash('hex');
  tx.index = p.readU32();
  tx.time = p.readU32();
  tx.mtime = p.readU32();

  if (tx.block === encoding.NULL_HASH)
    tx.block = null;

  if (tx.height === 0x7fffffff)
    tx.height = -1;

  if (tx.index === 0x7fffffff)
    tx.index = -1;

  if (saveCoins) {
    const coinCount = p.readVarint();
    for (let i = 0; i < coinCount; i++) {
      let coin = p.readVarBytes();
      if (coin.length === 0)
        continue;
      coin = Coin.fromRaw(coin);
      coin.hash = tx.inputs[i].prevout.hash;
      coin.index = tx.inputs[i].prevout.index;
      tx.inputs[i].coin = coin;
    }
  }

  return tx;
}

function getValues(map) {
  const items = [];

  for (const key of Object.keys(map))
    items.push(map[key]);

  return items;
}

(async () => {
  await db.open();
  batch = db.batch();
  console.log('Opened %s.', file);
  await updateVersion();
  await updateTXDB();
})().then(() => {
  console.log('Migration complete.');
  process.exit(0);
});
