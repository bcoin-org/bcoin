'use strict';

const assert = require('bsert');
const URL = require('url');

exports.parseURL = function parseURL(url) {
  if (url.indexOf('://') === -1)
    url = `ws://${url}`;

  const data = URL.parse(url);

  if (data.protocol !== 'http:'
      && data.protocol !== 'https:'
      && data.protocol !== 'ws:'
      && data.protocol !== 'wss:') {
    throw new Error('Invalid protocol for websocket URL.');
  }

  if (!data.hostname)
    throw new Error('Malformed URL.');

  const host = data.hostname;

  let port = 80;
  let ssl = false;

  if (data.protocol === 'https:' || data.protocol === 'wss:') {
    port = 443;
    ssl = true;
  }

  if (data.port) {
    port = parseInt(data.port, 10);
    assert((port & 0xffff) === port);
    assert(port !== 0);
  }

  return [port, host, ssl];
};
