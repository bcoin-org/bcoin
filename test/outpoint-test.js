/* eslint-env mocha */

'use strict';

const Outpoint = require('../lib/primitives/outpoint');
const assert = require('./util/assert');
const common = require('./util/common');

const OUTPOINT_SIZE = 36;
const tx1 = common.readTX('tx1').getRaw();
const rawOutpoint1 = tx1.slice(5, 5+OUTPOINT_SIZE);

const tx2 = common.readTX('tx2').getRaw();
const rawOutpoint2 = tx2.slice(5, 5+OUTPOINT_SIZE);

describe('Outpoint', () => {
  it('should clone the outpoint correctly', () => {
    const raw = rawOutpoint1.slice();
    const outpointObject = Outpoint.fromRaw(raw);
    const clone = outpointObject.clone();
    const equals = outpointObject.equals(clone);

    assert.strictEqual(outpointObject !== clone, true);
    assert.strictEqual(equals, true);
  });
});
