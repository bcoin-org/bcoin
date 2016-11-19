'use strict';

var BN = require('bn.js');
var bcoin = require('../').set('main');
var constants = bcoin.constants;
var util = bcoin.util;
var assert = require('assert');
var bench = require('./bench');
var Mnemonic = bcoin.hd.Mnemonic;

var key = bcoin.hd.fromMnemonic();
var phrase = key.mnemonic.getPhrase();

assert.equal(Mnemonic.fromPhrase(phrase).getPhrase(), phrase);

var end = bench('fromPhrase');
for (var i = 0; i < 10000; i++)
  Mnemonic.fromPhrase(phrase);
end(i);
