'use strict';

const assert = require('assert');
const fs = require('fs');
const TX = require('../../lib/primitives/tx');
const Output = require('../../lib/primitives/output');
const CoinView = require('../../lib/coins/coinview');
const BufferReader = require('../../lib/utils/reader');

exports.parseTX = function parseTX(file) {
  const data = fs.readFileSync(`${__dirname}/../${file}`, 'utf8');
  const parts = data.trim().split(/\n+/);
  const raw = parts[0];
  const tx = TX.fromRaw(raw.trim(), 'hex');
  const view = new CoinView();
  const txs = [tx];

  for (let i = 1; i < parts.length; i++) {
    const raw = parts[i];
    const prev = TX.fromRaw(raw.trim(), 'hex');
    view.addTX(prev, -1);
    txs.push(prev);
  }

  return {
    tx: tx,
    view: view,
    txs: txs
  };
};

exports.parseUndo = function parseUndo(data) {
  const br = new BufferReader(data);
  const undo = [];

  while (br.left()) {
    const output = Output.fromReader(br);
    undo.push(output);
  }

  return undo;
};

exports.applyUndo = function applyUndo(block, undo) {
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
