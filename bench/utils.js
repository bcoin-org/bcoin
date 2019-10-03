/*!
 * bench/utils.js - benchmark utils for bcoin
 * Copyright (c) 2019, Braydon Fuller (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

function processArgs(argv, config) {
  const args = {};

  for (const key in config)
    args[key] = config[key].fallback;

  for (let i = 2; i < process.argv.length; i++) {
    const arg = process.argv[i];
    const match = arg.match(/^(\-){1,2}([a-z]+)(\=)?(.*)?$/);

    if (!match) {
      throw new Error(`Unexpected argument: ${arg}.`);
    } else {
      const key = match[2];
      let value = match[4];

      if (!config[key])
        throw new Error(`Invalid argument: ${arg}.`);

      if (config[key].value && !value) {
        value = process.argv[i + 1];
        i++;
      } else if (!config[key].value && !value) {
        value = true;
      } else if (!config[key].value && value) {
        throw new Error(`Unexpected value: ${key}=${value}`);
      }

      if (config[key].parse)
        value = config[key].parse(value);

      if (value)
        args[key] = value;

      if (!config[key].valid(args[key]))
        throw new Error(`Invalid value: ${key}=${value}`);
    }
  }

  return args;
}

function hrToMicro(time) {
  return (time[0] * 1000000) + (time[1] / 1000);
}

function hrToSeconds(time) {
  return hrToMicro(time) / 1000000;
}

module.exports = {
  processArgs,
  hrToMicro,
  hrToSeconds
};
