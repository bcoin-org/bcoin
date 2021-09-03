/* eslint no-unused-vars: "off" */

'use strict';

const assert = require('assert');
const bench = require('./bench');
const BN = require('../lib/bn');
const rounds = 1000000;

/*
 * Reduction Contexts
 */

const r192 = BN.red('p192');
const r224 = BN.red('p224');
const r256 = BN.red('k256');

/*
 * Montgomery Contexts
 */

const m192 = BN.mont('p192');
const m224 = BN.mont('p224');
const m256 = BN.mont('k256');

/*
 * Primes
 */

const p192 = new BN('fffffffffffffffffffffffffffffffeffffffffffffffff', 16);

const p224 = new BN('ffffffffffffffffffffffffffffffff000000000000000000000001',
                    16);

const k256 = new BN('ffffffffffffffffffffffffffffffff'
                  + 'fffffffffffffffffffffffefffffc2f', 16);

/*
 * Numbers
 */

const a192 = new BN('63446c7a8efffadd162c329db1697578dc3e65df4aeab1a6', 16);
const b192 = new BN('eaf382d3a06b4fde6809a3780796c92b9a3a47fcf7215331', 16);
const c192 = a192.subn(1);

const a224 = a192.ushln(32).iuor(b192);
const b224 = b192.ushln(32).iuor(a192);

const a256 = a192.ushln(64).iuor(b192);
const b256 = b192.ushln(64).iuor(a192);

/*
 * Reduced Numbers
 */

const ra192 = a192.toRed(r192);
const rb192 = b192.toRed(r192);

const ra224 = a224.toRed(r224);
const rb224 = b224.toRed(r224);

const ra256 = a256.toRed(r256);
const rb256 = b256.toRed(r256);

/*
 * Montgomery Numbers
 */

const ma192 = a192.toRed(m192);
const mb192 = b192.toRed(m192);

const ma224 = a224.toRed(m224);
const mb224 = b224.toRed(m224);

const ma256 = a256.toRed(m256);
const mb256 = b256.toRed(m256);

/*
 * Base10
 */

const dec192 = a192.toString(10);
const dec224 = a224.toString(10);
const dec256 = a256.toString(10);

/*
 * Base16
 */

const hex192 = a192.toString(16);
const hex224 = a224.toString(16);
const hex256 = a256.toString(16);

/*
 * BigInt
 */

const int192 = a192.toBigInt();
const int224 = a224.toBigInt();
const int256 = a256.toBigInt();

/*
 * Raw
 */

const raw192 = a192.encode();
const raw224 = a224.encode();
const raw256 = a256.encode();

/*
 * Benchmarks
 */

console.log('native=%d', BN.native);

// Update a bit to confuse v8.
let bit = 0;

bench('add', rounds, () => {
  const c = a192.add(b192);
  bit ^= c.isOdd();
});

bench('sub', rounds, () => {
  const c = b192.sub(a192);
  bit ^= c.isOdd();
});

bench('mul', rounds, () => {
  const c = a192.mul(b192);
  bit ^= c.isOdd();
});

bench('mul 256', rounds, () => {
  const c = a256.mul(b256);
  bit ^= c.isOdd();
});

bench('div', rounds, () => {
  const c = b192.div(a192);
  bit ^= c.isOdd();
});

bench('mod', rounds, () => {
  const c = b192.mod(a192);
  bit ^= c.isOdd();
});

bench('gcd', rounds / 100, () => {
  const c = a192.gcd(b192);
  bit ^= c.isOdd();
});

bench('egcd', rounds / 100, () => {
  const [,, c] = a192.egcd(b192);
  bit ^= c.isOdd();
});

bench('invert', rounds / 100, () => {
  const c = a192.invert(p192);
  bit ^= c.isOdd();
});

bench('fermat', rounds / 100, () => {
  const c = a192.fermat(p192);
  bit ^= c.isOdd();
});

bench('jacobi', rounds / 100, () => {
  const c = a192.jacobi(p192);
  bit ^= c;
});

bench('cmp', rounds, () => {
  const c = a192.cmp(c192);
  bit ^= c & 1;
});

bench('ucmp', rounds, () => {
  const c = a192.ucmp(c192);
  bit ^= c & 1;
});

bench('to string 10', rounds, () => {
  const c = a192.toString(10);
  bit ^= c.charCodeAt(0) & 1;
});

bench('from string 10', rounds, () => {
  const c = BN.fromString(dec192, 10);
  bit ^= c.isOdd();
});

bench('to string 16', rounds, () => {
  const c = a192.toString(16);
  bit ^= c.charCodeAt(0) & 1;
});

bench('from string 16', rounds, () => {
  const c = BN.fromString(hex192, 16);
  bit ^= c.isOdd();
});

bench('to int', rounds, () => {
  const c = a192.toBigInt();
  bit ^= Number(c & BigInt(1));
});

bench('from int', rounds, () => {
  const c = BN.fromBigInt(int192);
  bit ^= c.isOdd();
});

bench('encode', rounds, () => {
  const c = a192.encode();
  bit ^= c[0] & 1;
});

bench('decode', rounds, () => {
  const c = BN.decode(raw192);
  bit ^= c.isOdd();
});

bench('bit length', rounds, () => {
  const c = a192.bitLength();
  bit ^= c & 1;
});

bench('zero bits', rounds, () => {
  const c = a192.zeroBits();
  bit ^= c & 1;
});

bench('red add', rounds, () => {
  const c = ra192.redAdd(rb192);
  bit ^= c.isOdd();
});

bench('red sub', rounds, () => {
  const c = ra192.redSub(rb192);
  bit ^= c.isOdd();
});

bench('red mul', rounds, () => {
  const c = ra192.redMul(rb192);
  bit ^= c.isOdd();
});

bench('red muln 8', rounds, () => {
  const c = ra192.redMuln(8);
  bit ^= c.isOdd();
});

bench('red muln 5', rounds, () => {
  const c = ra192.redMuln(5);
  bit ^= c.isOdd();
});

bench('red invert', rounds / 100, () => {
  const c = ra192.redInvert();
  bit ^= c.isOdd();
});

bench('red fermat', rounds / 100, () => {
  const c = ra192.redFermat();
  bit ^= c.isOdd();
});

bench('red pow', rounds / 100, () => {
  const c = ra192.redPow(b192);
  bit ^= c.isOdd();
});

bench('red pown', rounds / 100, () => {
  const c = ra192.redPown(65537);
  bit ^= c.isOdd();
});

bench('red sqrt', rounds / 1000, () => {
  const c = ra224.redSqrt();
  bit ^= c.isOdd();
});

bench('red add 256', rounds, () => {
  const c = ra256.redAdd(rb256);
  bit ^= c.isOdd();
});

bench('red sub 256', rounds, () => {
  const c = ra256.redSub(rb256);
  bit ^= c.isOdd();
});

bench('red mul 256', rounds, () => {
  const c = ra256.redMul(rb256);
  bit ^= c.isOdd();
});

bench('red muln 8 256', rounds, () => {
  const c = ra256.redMuln(8);
  bit ^= c.isOdd();
});

bench('red muln 5 256', rounds, () => {
  const c = ra256.redMuln(5);
  bit ^= c.isOdd();
});

bench('red invert 256', rounds / 100, () => {
  const c = ra256.redInvert();
  bit ^= c.isOdd();
});

bench('red fermat 256', rounds / 100, () => {
  const c = ra256.redFermat();
  bit ^= c.isOdd();
});

bench('red pow 256', rounds / 100, () => {
  const c = ra256.redPow(b256);
  bit ^= c.isOdd();
});

bench('red pown 256', rounds / 100, () => {
  const c = ra256.redPown(65537);
  bit ^= c.isOdd();
});

bench('red sqrt 256', rounds / 1000, () => {
  const c = ra256.redSqrt();
  bit ^= c.isOdd();
});

bench('mont add', rounds, () => {
  const c = ma192.redAdd(mb192);
  bit ^= c.isOdd();
});

bench('mont sub', rounds, () => {
  const c = ma192.redSub(mb192);
  bit ^= c.isOdd();
});

bench('mont mul', rounds, () => {
  const c = ma192.redMul(mb192);
  bit ^= c.isOdd();
});

bench('mont muln 8', rounds, () => {
  const c = ma192.redMuln(8);
  bit ^= c.isOdd();
});

bench('mont muln 5', rounds, () => {
  const c = ma192.redMuln(5);
  bit ^= c.isOdd();
});

bench('mont invert', rounds / 100, () => {
  const c = ma192.redInvert();
  bit ^= c.isOdd();
});

bench('mont fermat', rounds / 100, () => {
  const c = ma192.redFermat();
  bit ^= c.isOdd();
});

bench('mont pow', rounds / 100, () => {
  const c = ma192.redPow(b192);
  bit ^= c.isOdd();
});

bench('mont pown', rounds / 100, () => {
  const c = ma192.redPown(65537);
  bit ^= c.isOdd();
});

bench('mont sqrt', rounds / 1000, () => {
  const c = ma224.redSqrt();
  bit ^= c.isOdd();
});

bench('mont mul 256', rounds, () => {
  const c = ma256.redMul(mb256);
  bit ^= c.isOdd();
});

bench('mont muln 8 256', rounds, () => {
  const c = ma256.redMuln(8);
  bit ^= c.isOdd();
});

bench('mont muln 5 256', rounds, () => {
  const c = ma256.redMuln(5);
  bit ^= c.isOdd();
});

bench('mont invert 256', rounds / 100, () => {
  const c = ma256.redInvert();
  bit ^= c.isOdd();
});

bench('mont fermat 256', rounds / 100, () => {
  const c = ma256.redFermat();
  bit ^= c.isOdd();
});

bench('mont pow 256', rounds / 100, () => {
  const c = ma256.redPow(b256);
  bit ^= c.isOdd();
});

bench('mont pown 256', rounds / 100, () => {
  const c = ma256.redPown(65537);
  bit ^= c.isOdd();
});

bench('mont sqrt 256', rounds / 1000, () => {
  const c = ma256.redSqrt();
  bit ^= c.isOdd();
});

assert(bit >= 0);
