'use strict';

const fs = require('fs');
const TX = require('../../lib/primitives/tx');
const CoinView = require('../../lib/coins/coinview');

exports.parseTX = function parseTX(file) {
  let data = fs.readFileSync(`${__dirname}/../${file}`, 'utf8');
  let parts = data.trim().split(/\n+/);
  let raw = parts[0];
  let tx = TX.fromRaw(raw.trim(), 'hex');
  let view = new CoinView();
  let txs = [tx];

  for (let i = 1; i < parts.length; i++) {
    let raw = parts[i];
    let prev = TX.fromRaw(raw.trim(), 'hex');
    view.addTX(prev, -1);
    txs.push(prev);
  }

  return {
    tx: tx,
    view: view,
    txs: txs
  };
};
