'use strict';

const fs = require('fs');
const TX = require('../../lib/primitives/tx');
const CoinView = require('../../lib/coins/coinview');

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
