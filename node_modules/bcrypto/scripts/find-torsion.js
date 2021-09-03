'use strict';

const elliptic = require('../lib/js/elliptic');

require('../test/util/curves');

function printTorsion(curve) {
  const torsion = curve._findTorsion();
  const out = [];

  for (const p of torsion)
    out.push(p.toPretty());

  const txt = JSON.stringify(out, null, 2);

  console.log(txt.replace(/"/g, '\''));
}

function main(argv) {
  if (argv.length < 3) {
    console.error('Must enter a curve ID.');
    process.exit(1);
    return;
  }

  const curve = elliptic.curve(argv[2]);

  printTorsion(curve);
}

main(process.argv);
