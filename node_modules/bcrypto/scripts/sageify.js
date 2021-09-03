'use strict';

const assert = require('bsert');
const elliptic = require('../lib/js/elliptic');

require('../test/util/curves');

const id = process.argv[2];
const invert = process.argv.includes('--invert');
const curve = elliptic.curve(id);

function curveToSage(curve, invert = false) {
  assert(curve instanceof elliptic.Curve);
  assert(typeof invert === 'boolean');

  if (curve.type === 'short') {
    return [
      `# ${curve.id || 'Unnamed'} (short)`,
      `p = 0x${curve.p.toJSON()}`,
      'F = GF(p)',
      `a = F(0x${curve.a.fromRed().toJSON()})`,
      `b = F(0x${curve.b.fromRed().toJSON()})`,
      `n = 0x${curve.n.toJSON()}`,
      `h = ${curve.h.toString(10)}`,
      `z = F(0x${curve.z.fromRed().toJSON()})`,
      'E = EllipticCurve(F, [0, 0, 0, a, b])',
      `g = ${pointToSage(curve.g)}`,
      `assert E.j_invariant() == 0x${curve.jinv().toJSON()}`
    ].join('\n');
  }

  if (curve.type === 'mont') {
    return [
      `# ${curve.id || 'Unnamed'} (mont)`,
      `p = 0x${curve.p.toJSON()}`,
      'F = GF(p)',
      `A = F(0x${curve.a.fromRed().toJSON()})`,
      `B = F(0x${curve.b.fromRed().toJSON()})`,
      `n = 0x${curve.n.toJSON()}`,
      `h = ${curve.h.toString(10)}`,
      `z = F(0x${curve.z.fromRed().toJSON()})`,
      'E = EllipticCurve(F, [0, A / B, 0, 1 / B^2, 0])',
      `g = ${pointToSage(curve.g)}`,
      `assert E.j_invariant() == 0x${curve.jinv().toJSON()}`
    ].join('\n');
  }

  if (curve.type === 'edwards') {
    return [
      `# ${curve.id || 'Unnamed'} (edwards)`,
      invert ? '# (u, v) = ((y + 1) / (y - 1), u / x)'
             : '# (u, v) = ((1 + y) / (1 - y), u / x)',
      invert ? '# (x, y) = (u / v, (u + 1) / (u - 1))'
             : '# (x, y) = (u / v, (u - 1) / (u + 1))',
      `p = 0x${curve.p.toJSON()}`,
      'F = GF(p)',
      `a = F(0x${curve.a.fromRed().toJSON()})`,
      `d = F(0x${curve.d.fromRed().toJSON()})`,
      `n = 0x${curve.n.toJSON()}`,
      `h = ${curve.h.toString(10)}`,
      `z = F(0x${curve.z.fromRed().toJSON()})`,
      invert ? 'A = 2 * (d + a) / (d - a)'
             : 'A = 2 * (a + d) / (a - d)',
      invert ? 'B = 4 / (d - a)'
             : 'B = 4 / (a - d)',
      'E = EllipticCurve(F, [0, A / B, 0, 1 / B^2, 0])',
      `g = ${pointToSage(curve.g, invert)}`,
      `assert E.j_invariant() == 0x${curve.jinv().toJSON()}`
    ].join('\n');
  }

  throw new Error('Not implemented.');
}

function pointToSage(point, invert = false) {
  assert(point instanceof elliptic.Point);
  assert(typeof invert === 'boolean');

  if (point.curve.type === 'short') {
    if (point.inf)
      return 'E(0)';

    const x = point.x.fromRed().toJSON();
    const y = point.y.fromRed().toJSON();

    return `E(0x${x}, 0x${y})`;
  }

  if (point.curve.type === 'mont') {
    if (point.inf)
      return 'E(0)';

    const x = point.x.fromRed().toJSON();
    const y = point.y.fromRed().toJSON();

    return `E(0x${x} / B, 0x${y} / B)`;
  }

  if (point.curve.type === 'edwards') {
    if (point.isInfinity())
      return 'E(0)';

    if (point.x.isZero())
      return 'E(0, 0)';

    let uu, uz;

    if (invert) {
      uu = point.y.redAdd(point.z);
      uz = point.y.redSub(point.z);
    } else {
      uu = point.z.redAdd(point.y);
      uz = point.z.redSub(point.y);
    }

    const vv = point.z.redMul(uu);
    const vz = point.x.redMul(uz);
    const zi = uz.redMul(vz).redInvert();
    const u = uu.redMul(vz).redMul(zi);
    const v = vv.redMul(uz).redMul(zi);
    const x = u.fromRed().toJSON();
    const y = v.fromRed().toJSON();

    return `E(0x${x} / B, 0x${y} / B)`;
  }

  throw new Error('Not implemented.');
}

console.log(curveToSage(curve, invert));
