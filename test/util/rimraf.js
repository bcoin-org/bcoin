'use strict';

const path = require('path');
const fs = require('fs');

const allowed = new RegExp('^\/tmp\/(.*)$');

function wrapAsync(fn) {
  return async (p) => {
    return new Promise((resolve, reject) => {
      fn(p, (err, result) => {
        if (err && err.code !== 'ENOENT')
          return reject(err);
        resolve(result);
      });
    });
  };
}

const rmdir = wrapAsync(fs.rmdir);
const readdir = wrapAsync(fs.readdir);
const stat = wrapAsync(fs.stat);
const unlink = wrapAsync(fs.unlink);

async function rmdirdeep(p) {
  const files = await readdir(p);

  for (let i = 0; i < files.length; i++)
    await rimraf(path.join(p, files[i]));

  return await rmdir(p);
}

async function rimraf(p) {
  if (!allowed.test(p))
    throw new Error(`rimraf path not allowed: ${p}`);

  const stats = await stat(p);

  if (stats && stats.isDirectory())
    return await rmdirdeep(p);

  return await unlink(p);
}

module.exports = rimraf;
