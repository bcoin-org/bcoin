'use strict';

var assert = require('assert');
var bench = require('./bench');
var HD = require('../lib/hd');
var Mnemonic = require('../lib/hd/mnemonic');

var mnemonic = new Mnemonic();
HD.fromMnemonic(mnemonic);

var phrase = mnemonic.getPhrase();
var i, end;

assert.equal(Mnemonic.fromPhrase(phrase).getPhrase(), phrase);

end = bench('fromPhrase');
for (i = 0; i < 10000; i++)
  Mnemonic.fromPhrase(phrase);
end(i);
