'use strict';

const elliptic = require('../lib/js/elliptic');

require('../test/util/curves');

if (process.argv.length < 4)
  throw new Error('Must pass 2 curves.');

const curve = elliptic.curve(process.argv[2]);
const other = elliptic.curve(process.argv[3]);

if (curve.type !== 'edwards')
  throw new Error('Curve must be in Twisted Edwards form.');

const out = [];

for (const p of curve.torsion) {
  const q = other.pointFromEdwards(p);
  out.push(q.toPretty());
}

console.log(out);
