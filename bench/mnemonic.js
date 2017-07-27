'use strict';

const assert = require('assert');
const bench = require('./bench');
const HD = require('../lib/hd');
const Mnemonic = require('../lib/hd/mnemonic');

const mnemonic = new Mnemonic();
HD.fromMnemonic(mnemonic);

const phrase = mnemonic.getPhrase();
let i, end;

assert.equal(Mnemonic.fromPhrase(phrase).getPhrase(), phrase);

end = bench('fromPhrase');
for (i = 0; i < 10000; i++)
  Mnemonic.fromPhrase(phrase);
end(i);
