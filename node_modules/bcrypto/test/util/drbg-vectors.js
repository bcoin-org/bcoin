'use strict';

const path = require('path');
const fs = require('fs');

module.exports = function(type, alg) {
  const filename = path.resolve(__dirname, '..', 'data', `${type}.rsp`);
  const text = fs.readFileSync(filename, 'utf8');
  const vectors = [];

  let from = -1;

  for (;;) {
    from = text.indexOf(`[${alg}]`, from + 1);

    if (from === -1)
      break;

    for (let i = 0; i < 15; i++) {
      const vector = {};
      const start = text.indexOf(`COUNT = ${i}`, from);
      const end = text.indexOf('\r\n\r\n', start);
      const items = text.slice(start, end).split('\r\n');

      for (let j = 1; j < items.length; j++) {
        const key = items[j].split(' = ')[0];
        const value = Buffer.from(items[j].split(' = ')[1], 'hex');

        if (vector[key])
          vector[key] = [vector[key], value];
        else
          vector[key] = value;
      }

      vectors.push(vector);
    }
  }

  return vectors;
};
