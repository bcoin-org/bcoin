/*!
 * file.js - file middleware for bweb
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bweb
 */

'use strict';

const assert = require('bsert');
const fs = require('fs');
const Path = require('path');

/**
 * Static file middleware.
 * @param {String} prefix
 * @returns {Function}
 */

function fileServer(prefix) {
  assert(typeof prefix === 'string');

  return async (req, res) => {
    if (req.method !== 'GET' && req.method !== 'HEAD')
      return;

    const file = Path.join(prefix, req.pathname);

    let stat = null;

    try {
      stat = await fsStat(file);
    } catch (e) {
      if (e.code === 'ENOENT')
        return;
      throw e;
    }

    if (stat.isDirectory()) {
      const title = req.pathname;
      const body = await dir2html(file, title, req.prefix());
      res.send(200, body, 'html');
      return;
    }

    try {
      await res.sendFile(file);
    } catch (e) {
      throw wrapError(e);
    }
  };
}

/*
 * Helpers
 */

function fsStat(file) {
  return new Promise((resolve, reject) => {
    fs.stat(file, (err, result) => {
      if (err) {
        reject(wrapError(err));
        return;
      }
      resolve(result);
    });
  });
}

function fsReaddir(file) {
  return new Promise((resolve, reject) => {
    fs.readdir(file, (err, result) => {
      if (err) {
        reject(wrapError(err));
        return;
      }
      resolve(result);
    });
  });
}

function wrapError(e) {
  if (!e.code) {
    const err = new Error('Internal server error.');
    err.statusCode = 500;
    return err;
  }

  switch (e.code) {
    case 'ENOENT':
    case 'ENAMETOOLONG':
    case 'ENOTDIR':
    case 'EISDIR': {
      const err = new Error('File not found.');
      err.code = e.code;
      err.syscall = e.syscall;
      err.statusCode = 404;
      return err;
    }
    case 'EACCES':
    case 'EPERM': {
      const err = new Error('Cannot access file.');
      err.code = e.code;
      err.syscall = e.syscall;
      err.statusCode = 403;
      return err;
    }
    case 'EMFILE': {
      const err = new Error('Too many open files.');
      err.code = e.code;
      err.syscall = e.syscall;
      err.statusCode = 500;
      return err;
    }
    default: {
      const err = new Error('Cannot access file.');
      err.code = e.code;
      err.syscall = e.syscall;
      err.statusCode = 500;
      return err;
    }
  }
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

  const list = await fsReaddir(parent);
  const dirs = [];
  const files = [];

  for (const file of list) {
    const path = Path.join(parent, file);
    const stat = await fsStat(path);

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
