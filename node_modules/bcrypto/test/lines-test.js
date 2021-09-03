'use strict';

const assert = require('bsert');
const lines = require('../lib/encoding/lines');

const vector = '\ufeff\nhello world\r\nfoobar  \nfoobaz\r\n\nfoo\n\n';

describe('Lines', function() {
  it('should parse and format lines', () => {
    const out = [];

    for (const [index, line] of lines(vector))
      out.push([index, line]);

    assert.deepStrictEqual(out, [
      [1, 'hello world'],
      [2, 'foobar'],
      [3, 'foobaz'],
      [5, 'foo']
    ]);
  });
});
