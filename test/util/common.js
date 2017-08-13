'use strict';

const assert = require('assert');
const fs = require('../../lib/utils/fs');
const Block = require('../../lib/primitives/block');
const MerkleBlock = require('../../lib/primitives/merkleblock');
const {CompactBlock} = require('../../lib/net/bip152');
const TX = require('../../lib/primitives/tx');
const Output = require('../../lib/primitives/output');
const CoinView = require('../../lib/coins/coinview');
const BufferReader = require('../../lib/utils/reader');
const BufferWriter = require('../../lib/utils/writer');

exports.parseTX = function parseTX(name) {
  const data = fs.readFileSync(`${__dirname}/../data/${name}.hex`, 'utf8');
  const parts = data.trim().split('\n');
  const raw = Buffer.from(parts[0], 'hex');
  const tx = TX.fromRaw(raw);
  const view = new CoinView();
  const txs = [tx];

  for (let i = 1; i < parts.length; i++) {
    const raw = Buffer.from(parts[i], 'hex');
    const prev = TX.fromRaw(raw);
    view.addTX(prev, -1);
    txs.push(prev);
  }

  return {
    tx: tx,
    view: view,
    txs: txs
  };
};

exports.readBlock = function readBlock(name) {
  const height = name.substring(5);
  const blockFile = `${__dirname}/../data/block${height}.raw`;

  if (!fs.existsSync(blockFile)) {
    const raw = fs.readFileSync(`${__dirname}/../data/${name}.raw`);
    const block = Block.fromRaw(raw);
    const view = new CoinView();
    return { raw, block, view };
  }

  const raw = fs.readFileSync(blockFile);
  const block = Block.fromRaw(raw);

  const undoFile = `${__dirname}/../data/undo${height}.raw`;

  if (!fs.existsSync(undoFile)) {
    const view = new CoinView();
    return { raw, block, view };
  }

  const undoRaw = fs.readFileSync(undoFile);
  const undo = exports.parseUndo(undoRaw);
  const view = exports.applyBlockUndo(block, undo);

  return { raw, block, view };
};

exports.readMerkle = function readMerkle(name) {
  const raw = fs.readFileSync(`${__dirname}/../data/${name}.raw`);
  const block = MerkleBlock.fromRaw(raw);
  return { raw, block };
};

exports.readCompact = function readCompact(name) {
  const raw = fs.readFileSync(`${__dirname}/../data/${name}.raw`);
  const block = CompactBlock.fromRaw(raw);
  return { raw, block };
};

exports.readTX = function readTX(name) {
  const index = name.substring(2);
  const txFile = `${__dirname}/../data/tx${index}.raw`;

  if (!fs.existsSync(txFile)) {
    const raw = fs.readFileSync(`${__dirname}/../data/${name}.raw`);
    const tx = TX.fromRaw(raw);
    const view = new CoinView();
    return { raw, tx, view };
  }

  const raw = fs.readFileSync(txFile);
  const tx = TX.fromRaw(raw);

  const undoFile = `${__dirname}/../data/utx${index}.raw`;

  if (!fs.existsSync(undoFile)) {
    const view = new CoinView();
    return { raw, tx, view };
  }

  const undoRaw = fs.readFileSync(undoFile);
  const undo = exports.parseUndo(undoRaw);
  const view = exports.applyTXUndo(tx, undo);

  return { raw, tx, view };
};

exports.parseUndo = function parseUndo(data) {
  const br = new BufferReader(data);
  const items = [];

  while (br.left()) {
    const output = Output.fromReader(br);
    items.push(output);
  }

  return items;
};

exports.applyBlockUndo = function applyBlockUndo(block, undo) {
  const view = new CoinView();
  let i = 0;

  for (const tx of block.txs) {
    if (tx.isCoinbase())
      continue;

    for (const {prevout} of tx.inputs)
      view.addOutput(prevout, undo[i++]);
  }

  assert(i === undo.length, 'Undo coins data inconsistency.');

  return view;
};

exports.applyTXUndo = function applyTXUndo(tx, undo) {
  const view = new CoinView();
  let i = 0;

  for (const {prevout} of tx.inputs)
    view.addOutput(prevout, undo[i++]);

  assert(i === undo.length, 'Undo coins data inconsistency.');

  return view;
};

exports.makeBlockUndo = function makeBlockUndo(block, view) {
  const items = [];

  for (const tx of block.txs) {
    if (tx.isCoinbase())
      continue;

    for (const {prevout} of tx.inputs) {
      const coin = view.getOutput(prevout);
      assert(coin);
      items.push(coin);
    }
  }

  return items;
};

exports.makeTXUndo = function makeTXUndo(tx, view) {
  const items = [];

  for (const {prevout} of tx.inputs) {
    const coin = view.getOutput(prevout);
    assert(coin);
    items.push(coin);
  }

  return items;
};

exports.serializeUndo = function serializeUndo(items) {
  const bw = new BufferWriter();

  for (const item of items) {
    bw.writeI64(item.value);
    bw.writeVarBytes(item.script.toRaw());
  }

  return bw.render();
};

exports.writeBlock = function writeBlock(name, block, view) {
  const height = name.substring(5);

  fs.writeFileSync(`${__dirname}/../data/block${height}.raw`, block.toRaw());

  if (!view)
    return;

  const undo = exports.makeBlockUndo(block, view);
  const undoRaw = exports.serializeUndo(undo);

  fs.writeFileSync(`${__dirname}/../data/undo${height}.raw`, undoRaw);
};

exports.writeTX = function writeTX(name, tx, view) {
  const index = name.substring(2);

  fs.writeFileSync(`${__dirname}/../data/tx${index}.raw`, tx.toRaw());

  if (!view)
    return;

  const undo = exports.makeTXUndo(tx, view);
  const undoRaw = exports.serializeUndo(undo);

  fs.writeFileSync(`${__dirname}/../data/utx${index}.raw`, undoRaw);
};
