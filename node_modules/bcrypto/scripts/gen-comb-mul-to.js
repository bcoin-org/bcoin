'use strict';

function genCombMulTo(alen, blen) {
  const len = alen + blen - 1;

  const src = [
    'const a = self.words;',
    'const b = num.words;',
    'const o = out.words;'
  ];

  for (let i = 0; i < alen; i++) {
    src.push('const a' + i + ' = a[' + i + '] | 0;');
    src.push('const al' + i + ' = a' + i + ' & 0x1fff;');
    src.push('const ah' + i + ' = a' + i + ' >>> 13;');
  }

  for (let i = 0; i < blen; i++) {
    src.push('const b' + i + ' = b[' + i + '] | 0;');
    src.push('const bl' + i + ' = b' + i + ' & 0x1fff;');
    src.push('const bh' + i + ' = b' + i + ' >>> 13;');
  }

  src.push('');
  src.push('let c = 0;');
  src.push('let lo, mid, hi;');

  src.push('');
  src.push('out.negative = self.negative ^ num.negative;');
  src.push('out._alloc(' + (len + 1) + ');');
  src.push('out.length = ' + len + ';');

  for (let k = 0; k < len; k++) {
    const minJ = Math.max(0, k - alen + 1);
    const maxJ = Math.min(k, blen - 1);

    src.push('');
    src.push('\/* k = ' + k + ' *\/');
    src.push('let w' + k + ' = c;');
    src.push('c = 0;');

    for (let j = minJ; j <= maxJ; j++) {
      const i = k - j;

      src.push('lo = Math.imul(al' + i + ', bl' + j + ');');
      src.push('mid = Math.imul(al' + i + ', bh' + j + ');');
      src.push('mid = (mid + Math.imul(ah' + i + ', bl' + j + ')) | 0;');
      src.push('hi = Math.imul(ah' + i + ', bh' + j + ');');

      src.push('w' + k + ' = (w' + k + ' + lo) | 0;');
      src.push('w' + k + ' = (w' + k + ' + ((mid & 0x1fff) << 13)) | 0;');
      src.push('c = (c + hi) | 0;');
      src.push('c = (c + (mid >>> 13)) | 0;');
      src.push('c = (c + (w' + k + ' >>> 26)) | 0;');
      src.push('w' + k + ' &= 0x3ffffff;');
    }
  }

  src.push('');

  // Store in separate step for better memory access
  for (let k = 0; k < len; k++)
    src.push('o[' + k + '] = w' + k + ';');

  src.push('');
  src.push('if (c !== 0) {',
           '  o[' + len + '] = c;',
           '  out.length += 1;',
           '}',
           '',
           '// Note: we shouldn\'t need to strip here.',
           'return out;');

  return src.map(l => '  ' + l).join('\n');
}

console.log(genCombMulTo(10, 10));
