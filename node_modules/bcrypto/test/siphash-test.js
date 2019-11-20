/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('assert');
const {siphash, sipmod} = require('../lib/siphash');

const vectors = [
  [1919933255, -586281423],
  [1962424773, -1814272003],
  [225214473, -643215526],
  [-2056821098, -671384019],
  [-819489568, 661751735],
  [410408292, -845568371],
  [-876001682, 1493099470],
  [-1425932043, -1962815177],
  [-1812597383, -1701632926],
  [-1644133665, 195683504],
  [2052963269, -1797408269],
  [-189583546, 577482151],
  [1964937148, -2045843973],
  [350901799, -1065075312],
  [-148649328, -1904545042],
  [-1591096735, 1237206501],
  [1059769471, 1472371675],
  [1771760117, 750667668],
  [1270985712, -1769090148],
  [-1150432995, -1485217347],
  [-1093247758, 446885528],
  [-789394512, 775645127],
  [-1823250539, -475840888],
  [-1475607668, -849555768],
  [-1196601146, -162943084],
  [-1126067490, -1970947862],
  [400045496, 1538987507],
  [791568739, 124506029],
  [-565335380, -1491220059],
  [-1499312026, -2020252303],
  [-1383619757, 1548349224],
  [853054202, -666778814],
  [1898402095, 1928494286],
  [-1477237946, -111576861],
  [316715034, -1157295560],
  [367015124, 262248366],
  [827195326, 135635892],
  [41521392, 694303105],
  [-891497243, -1628173235],
  [-1698703242, 1781756764],
  [238987627, 1392814032],
  [-1391705386, -61318766],
  [410191560, -1681779287],
  [-727315780, -210162795],
  [-113949411, -453894670],
  [-1454141692, 427120519],
  [-610611745, -177429232],
  [-798189363, 1544123883],
  [-434986037, -1630820015],
  [-949557716, -55726186],
  [-295419046, -1756168590],
  [-1584212618, -1304095142],
  [176654271, -1899268942],
  [-2118916291, 548707183],
  [2141725195, -1548555030],
  [609694145, 1017390233],
  [-1215447121, 982352829],
  [-367340187, 841619979],
  [1625693219, -1552330733],
  [1711724516, 1177037715],
  [1822747825, 1549767137],
  [-1620939359, 1553343987],
  [-451200928, -1896718505],
  [-1786105268, -351910542]
];

function toHex(expect) {
  let [hi, lo] = expect;

  hi >>>= 0;
  lo >>>= 0;

  hi = hi.toString(16);
  lo = lo.toString(16);

  while (hi.length < 8)
    hi = '0' + hi;

  while (lo.length < 8)
    lo = '0' + hi;

  return hi + lo;
}

function testHash(msg, expect) {
  const key = Buffer.from('000102030405060708090a0b0c0d0e0f', 'hex');
  assert.deepStrictEqual(siphash(msg, key), expect);
}

describe('SipHash', function() {
  it('should perform siphash with no data', () => {
    const data = Buffer.alloc(0);
    const key = Buffer.from('000102030405060708090a0b0c0d0e0f', 'hex');
    assert.deepStrictEqual(siphash(data, key), [1919933255, -586281423]);
  });

  it('should perform siphash with data', () => {
    const data = Buffer.from('0001020304050607', 'hex');
    const key = Buffer.from('000102030405060708090a0b0c0d0e0f', 'hex');
    assert.deepStrictEqual(siphash(data, key), [-1812597383, -1701632926]);
  });

  it('should perform siphash with uint256', () => {
    const data = Buffer.from(
      '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
      'hex');
    const key = Buffer.from('000102030405060708090a0b0c0d0e0f', 'hex');
    assert.deepStrictEqual(siphash(data, key), [1898402095, 1928494286]);
  });

  for (let i = 0; i < vectors.length; i++) {
    const expect = vectors[i];
    const msg = Buffer.alloc(i, 0x00);

    for (let j = 0; j < i; j++)
      msg[j] = j & 0xff;

    it(`should get siphash of ${toHex(expect)}`, () => {
      testHash(msg, expect);
    });
  }

  it('should test sipmod', () => {
    const value = Buffer.from([0xab]);
    const key = Buffer.from('9dcb553a73b4e2ae9316f6b25f848656', 'hex');

    assert.deepStrictEqual(
      sipmod(value, key, 0, 100),
      [0, 93]);

    assert.deepStrictEqual(
      sipmod(value, key, 100, 100),
      [93, -24689725]);

    assert.deepStrictEqual(
      sipmod(value, key, 0, 0x1fffffff),
      [0, 504627794]);

    assert.deepStrictEqual(
      sipmod(value, key, 0, 0xffffffff),
      [0, -257944937]);

    assert.deepStrictEqual(
      sipmod(value, key, 0x000000ff, 0xffffffff),
      [240, -1609394163]);

    assert.deepStrictEqual(
      sipmod(value, key, 0x1fffffff, 0xffffffff),
      [504627795, 30211052]);

    assert.deepStrictEqual(
      sipmod(value, key, 0xffffffff, 0xffffffff),
      [-257944936, 241688429]);
  });
});
