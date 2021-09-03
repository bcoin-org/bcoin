'use strict';

const assert = require('bsert');
const fs = require('fs');
const lines = require('../../lib/encoding/lines');

function parse(text) {
  assert(typeof text === 'string');

  const line = text.trim();
  const parts = [];

  let part = '';
  let ignore = false;
  let quote = false;

  for (let i = 0; i < line.length; i++) {
    if (ignore) {
      part += line[i];
      ignore = false;
      continue;
    }

    if (line[i] === '\\') {
      ignore = true;
      continue;
    }

    if (line[i] === '"') {
      quote = !quote;
      continue;
    }

    if (quote) {
      part += line[i];
      continue;
    }

    if (line[i] === ',') {
      parts.push(part);
      part = '';
      continue;
    }

    part += line[i];
  }

  if (part || line[line.length - 1] === ',')
    parts.push(part);

  return parts;
}

function *read(file) {
  assert(typeof file === 'string');

  const csv = fs.readFileSync(file, 'utf8');

  let schema = null;

  for (const [, line] of lines(csv)) {
    if (!schema) {
      schema = parse(line);
      continue;
    }

    const parts = parse(line);

    if (parts.length !== schema.length)
      throw new Error('Invalid CSV item.');

    yield [schema, parts];
  }
}

function *asArray(file) {
  assert(typeof file === 'string');

  for (const [, parts] of read(file))
    yield parts;
}

function *asObject(file) {
  assert(typeof file === 'string');

  for (const [schema, parts] of read(file)) {
    const obj = Object.create(null);

    for (let i = 0; i < schema.length; i++) {
      const key = schema[i];
      obj[key] = parts[i];
    }

    yield obj;
  }
}

exports.read = read;
exports.asArray = asArray;
exports.asObject = asObject;
