'use strict';

const fs = require('fs');

const wrap = (func) => {
  return (...args) => {
    return new Promise((resolve, reject) => {
      const cb = (err, res) => {
        if (func === fs.exists) {
          resolve(err);
          return;
        }

        if (err)
          reject(err);
        else
          resolve(res);
      };

      args.push(cb);

      try {
        func(...args);
      } catch (e) {
        reject(e);
      }
    });
  };
};

module.exports = wrap;
