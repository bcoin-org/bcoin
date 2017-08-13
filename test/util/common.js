'use strict';

const assert = require('assert');
const fs = require('../../lib/utils/fs');
const Block = require('../../lib/primitives/block');
const MerkleBlock = require('../../lib/primitives/merkleblock');
const Headers = require('../../lib/primitives/headers');
const {CompactBlock} = require('../../lib/net/bip152');
const TX = require('../../lib/primitives/tx');
const Output = require('../../lib/primitives/output');
const CoinView = require('../../lib/coins/coinview');
const BufferReader = require('../../lib/utils/reader');
const BufferWriter = require('../../lib/utils/writer');

exports.readBlock = function readBlock(name) {
  const height = name.substring(5);
  const blockFile = `${__dirname}/../data/block${height}.raw`;

  if (!fs.existsSync(blockFile)) {
    const raw = fs.readFileSync(`${__dirname}/../data/${name}.raw`);
    return new BlockContext(Block, raw);
  }

  const raw = fs.readFileSync(blockFile);
  const block = Block.fromRaw(raw);

  const undoFile = `${__dirname}/../data/undo${height}.raw`;

  if (!fs.existsSync(undoFile))
    return new BlockContext(Block, raw);

  const undoRaw = fs.readFileSync(undoFile);

  return new BlockContext(Block, raw, undoRaw);
};

exports.readMerkle = function readMerkle(name) {
  const raw = fs.readFileSync(`${__dirname}/../data/${name}.raw`);
  return new BlockContext(MerkleBlock, raw);
};

exports.readCompact = function readCompact(name) {
  const raw = fs.readFileSync(`${__dirname}/../data/${name}.raw`);
  return new BlockContext(CompactBlock, raw);
};

exports.readTX = function readTX(name) {
  const index = name.substring(2);
  const txFile = `${__dirname}/../data/tx${index}.raw`;

  if (!fs.existsSync(txFile)) {
    const raw = fs.readFileSync(`${__dirname}/../data/${name}.raw`);
    return new TXContext(raw);
  }

  const raw = fs.readFileSync(txFile);

  const undoFile = `${__dirname}/../data/utx${index}.raw`;

  if (!fs.existsSync(undoFile))
    return new TXContext(raw);

  const undoRaw = fs.readFileSync(undoFile);

  return new TXContext(raw, undoRaw);
};

exports.writeBlock = function writeBlock(name, block, view) {
  const height = name.substring(5);

  fs.writeFileSync(`${__dirname}/../data/block${height}.raw`, block.toRaw());

  if (!view)
    return;

  const undo = makeBlockUndo(block, view);
  const undoRaw = serializeUndo(undo);

  fs.writeFileSync(`${__dirname}/../data/undo${height}.raw`, undoRaw);
};

exports.writeTX = function writeTX(name, tx, view) {
  const index = name.substring(2);

  fs.writeFileSync(`${__dirname}/../data/tx${index}.raw`, tx.toRaw());

  if (!view)
    return;

  const undo = makeTXUndo(tx, view);
  const undoRaw = serializeUndo(undo);

  fs.writeFileSync(`${__dirname}/../data/utx${index}.raw`, undoRaw);
};

function parseUndo(data) {
  const br = new BufferReader(data);
  const items = [];

  while (br.left()) {
    const output = Output.fromReader(br);
    items.push(output);
  }

  return items;
}

function serializeUndo(items) {
  const bw = new BufferWriter();

  for (const item of items) {
    bw.writeI64(item.value);
    bw.writeVarBytes(item.script.toRaw());
  }

  return bw.render();
}

function applyBlockUndo(block, undo) {
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
}

function applyTXUndo(tx, undo) {
  const view = new CoinView();
  let i = 0;

  for (const {prevout} of tx.inputs)
    view.addOutput(prevout, undo[i++]);

  assert(i === undo.length, 'Undo coins data inconsistency.');

  return view;
}

function makeBlockUndo(block, view) {
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
}

function makeTXUndo(tx, view) {
  const items = [];

  for (const {prevout} of tx.inputs) {
    const coin = view.getOutput(prevout);
    assert(coin);
    items.push(coin);
  }

  return items;
}

class BlockContext {
  constructor(ctor, raw, undoRaw) {
    this.ctor = ctor;
    this.raw = raw;
    this.undoRaw = undoRaw || null;
  }
  getRaw() {
    return this.raw;
  }
  getBlock() {
    const Block = this.ctor;
    const block = Block.fromRaw(this.raw);

    if (!this.undoRaw) {
      const view = new CoinView();
      return [block, view];
    }

    const undo = parseUndo(this.undoRaw);
    const view = applyBlockUndo(block, undo);

    return [block, view];
  }
  getHeaders() {
    return Headers.fromHead(this.raw);
  }
}

class TXContext {
  constructor(raw, undoRaw) {
    this.raw = raw;
    this.undoRaw = undoRaw || null;
  }
  getRaw() {
    return this.raw;
  }
  getTX() {
    const tx = TX.fromRaw(this.raw);

    if (!this.undoRaw) {
      const view = new CoinView();
      return [tx, view];
    }

    const undo = parseUndo(this.undoRaw);
    const view = applyTXUndo(tx, undo);

    return [tx, view];
  }
}
