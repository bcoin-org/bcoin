'use strict';

var fs = require('fs');
var TX = require('../../lib/primitives/tx');
var CoinView = require('../../lib/coins/coinview');

exports.parseTX = function parseTX(file) {
  var data = fs.readFileSync(__dirname + '/../' + file, 'utf8');
  var parts = data.trim().split(/\n+/);
  var raw = parts[0];
  var tx = TX.fromRaw(raw.trim(), 'hex');
  var view = new CoinView();
  var txs = [tx];
  var i, prev;

  for (i = 1; i < parts.length; i++) {
    raw = parts[i];
    prev = TX.fromRaw(raw.trim(), 'hex');
    view.addTX(prev, -1);
    txs.push(prev);
  }

  return {
    tx: tx,
    view: view,
    txs: txs
  };
};
