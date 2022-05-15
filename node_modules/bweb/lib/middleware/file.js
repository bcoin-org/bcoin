/*!
 * file.js - file middleware for bweb
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bweb
 */

'use strict';

const assert = require('bsert');
const fs = require('fs');
const path = require('path');
const {call} = require('../util');
const {resolve, join, sep} = path;

/**
 * Static file middleware.
 * @param {Object|String} options
 * @returns {Function}
 */

function fileServer(options) {
  if (typeof options === 'string')
    options = { prefix: options };

  assert(options && typeof options === 'object');

  let {prefix, useIndex, jail} = options;
  let jailed = false;

  if (useIndex == null)
    useIndex = false;

  if (jail == null)
    jail = false;

  assert(typeof prefix === 'string');
  assert(typeof useIndex === 'boolean');
  assert(typeof jail === 'boolean');

  prefix = resolve(prefix);
  prefix = normalize(prefix);

  return async (req, res) => {
    if (req.method !== 'GET' && req.method !== 'HEAD')
      return;

    if (jail && !jailed) {
      prefix = await call(fs.realpath, prefix);
      prefix = normalize(prefix);
      jailed = true;
    }

    let file = join(prefix, req.pathname);
    let stat = null;

    try {
      stat = await call(fs.stat, file);
    } catch (e) {
      if (e.code === 'ENOENT')
        return;
      throw e;
    }

    if (!stat.isDirectory() && !stat.isFile()) {
      const err = new Error('Cannot access file.');
      err.statusCode = 403;
      throw err;
    }

    if (stat.isDirectory()) {
      const index = join(file, 'index.html');

      if (!useIndex || !await isFile(index)) {
        if (jail)
          await ensureJail(file, prefix);

        const title = req.pathname;
        const body = await dir2html(file, title, req.prefix());

        res.send(200, body, 'html');

        return;
      }

      file = index;
    }

    if (jail)
      await ensureJail(file, prefix);

    // eslint-disable-next-line
    return res.sendFile(file, stat);
  };
}

/*
 * Helpers
 */

async function isFile(file) {
  assert(typeof file === 'string');

  let stat;

  try {
    stat = await call(fs.stat, file);
  } catch (e) {
    return false;
  }

  return stat.isFile();
}

async function ensureJail(file, prefix) {
  assert(typeof file === 'string');
  assert(typeof prefix === 'string');

  if (isValidPath(file, prefix))
    file = await call(fs.realpath, file);

  if (!isValidPath(file, prefix)) {
    const err = new Error('Cannot access file.');
    err.statusCode = 403;
    throw err;
  }
}

function isValidPath(file, prefix) {
  file = normalize(file);

  if (file.includes('\u0000'))
    return false;

  if (file === prefix)
    return true;

  return file.startsWith(prefix + sep);
}

function normalize(file) {
  file = path.normalize(file);

  if (file.length > 1 && file[file.length - 1] === sep)
    file = file.slice(0, -1);

  return file;
}

function escapeHTML(html) {
  return html
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

async function dir2html(parent, title, prefix) {
  let body = '';

  title = escapeHTML(title);
  prefix = escapeHTML(prefix);

  body += '<!DOCTYPE html>\n';
  body += '<html lang="en">\n';
  body += '  <head>\n';
  body += `    <title>Index of ${title}</title>\n`;
  body += '    <meta charset="utf-8">\n';
  body += '  </head>\n';
  body += '  <body>\n';
  body += `    <p>Index of ${title}</p>\n`;
  body += '    <ul>\n';
  body += `      <li><a href="${prefix}..">../</a></li>\n`;

  const list = await call(fs.readdir, parent);
  const dirs = [];
  const files = [];

  for (const file of list) {
    const path = join(parent, file);
    const stat = await call(fs.lstat, path);

    if (stat.isDirectory())
      dirs.push(file);
    else
      files.push(file);
  }

  for (const file of dirs.sort()) {
    const name = escapeHTML(file);
    const href = `${prefix}${name}`;

    body += `      <li><a href="${href}">${name}/</a></li>\n`;
  }

  for (const file of files.sort()) {
    const name = escapeHTML(file);
    const href = `${prefix}${name}`;

    body += `      <li><a href="${href}">${name}</a></li>\n`;
  }

  body += '    </ul>\n';
  body += '  </body>\n';
  body += '</html>\n';

  return body;
}

/*
 * Expose
 */

module.exports = fileServer;
