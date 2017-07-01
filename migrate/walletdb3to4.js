'use strict';

const assert = require('assert');
const bcoin = require('../');
const encoding = require('../lib/utils/encoding');
const WalletDB = require('../lib/wallet/walletdb');
const BufferReader = require('../lib/utils/reader');
const TX = require('../lib/primitives/tx');
const Coin = require('../lib/primitives/coin');
const util = require('../lib/utils/util');
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
  let i, keys, key, hash, tx, walletdb;

  keys = await db.keys({
    gte: Buffer.from([0x00]),
    lte: Buffer.from([0xff])
  });

  for (i = 0; i < keys.length; i++) {
    key = keys[i];
    if (key[0] === 0x74 && key[5] === 0x74) {
      tx = await db.get(key);
      tx = fromExtended(tx);
      hash = tx.hash('hex');
      txs[hash] = tx;
    }
    if (key[0] === 0x74)
      batch.del(key);
  }

  txs = util.values(txs);

  await batch.write();
  await db.close();

  walletdb = new WalletDB({
    location: file,
    db: 'leveldb',
    resolution: true,
    verify: false,
    network: process.argv[3]
  });

  await walletdb.open();

  for (i = 0; i < txs.length; i++) {
    tx = txs[i];
    await walletdb.addTX(tx);
  }

  await walletdb.close();
}

function fromExtended(data, saveCoins) {
  let tx = new TX();
  let p = BufferReader(data);
  let i, coinCount, coin;

  tx.fromRaw(p);

  tx.height = p.readU32();
  tx.block = p.readHash('hex');
  tx.index = p.readU32();
  tx.ts = p.readU32();
  tx.ps = p.readU32();

  if (tx.block === encoding.NULL_HASH)
    tx.block = null;

  if (tx.height === 0x7fffffff)
    tx.height = -1;

  if (tx.index === 0x7fffffff)
    tx.index = -1;

  if (saveCoins) {
    coinCount = p.readVarint();
    for (i = 0; i < coinCount; i++) {
      coin = p.readVarBytes();
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
