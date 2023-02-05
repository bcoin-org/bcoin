/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('bsert');
const nfkd = require('../lib/hd/nfkd-compat');

describe('NFKD-Compat', function() {
  it('should apply compatibility normalization as expected', () => {
    // unicode char ﬀ (U+FB00) is normalized to ff (U+0066 U+0066)
    assert.equal(nfkd('\uFB00').localeCompare('\u0066\u0066'), 0);
  });

  it('should apply compatibility norm. when normalize function is undefined', () => {
    const str = '\uFB00';
    const func = str.normalize;
    delete String.prototype.normalize;
    // unicode char ﬀ (U+FB00) is normalized to ff (U+0066 U+0066)
    assert.equal(nfkd(str).localeCompare('\u0066\u0066'), 0);
    String.prototype.normalize = func;
  });
});
