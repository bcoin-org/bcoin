'use strict';

const elliptic = require('../lib/js/elliptic');

require('../test/util/curves');

function hexify(ch) {
  let c = ch.toString(16);

  if (c.length < 2)
    c = '0' + c;

  return c;
}

function fmt(x, size) {
  const buf = x.encode('be', size);

  let out = '    {\n';

  for (let i = 0; i < buf.length; i += 8) {
    const chunk = buf.slice(i, i + 8);

    out += '      ';

    for (let j = 0; j < chunk.length; j++)
      out += `0x${hexify(chunk[j])}, `;

    out = out.slice(0, -1);
    out += '\n';
  }

  out = out.slice(0, -2) + '\n';

  out += '    },\n';

  return out;
}

function printTorsion(curve) {
  const id = curve.id.toLowerCase();
  const h = curve.h.word(0);

  let out = '';

  out += `static const subgroup_def_t subgroups_${id}[${h}] = {\n`;

  for (const p of curve.torsion) {
    out += '  {\n';
    out += fmt(p.x.fromRed(), curve.fieldSize);
    out += fmt(p.y.fromRed(), curve.fieldSize);
    out += `    ${p.isInfinity() >>> 0}\n`;
    out += '  },\n';
  }

  out = out.slice(0, -2) + '\n';

  out += '};\n';

  process.stdout.write(out);
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
