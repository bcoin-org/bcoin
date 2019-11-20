'use strict';

/* eslint-env worker */

onmessage = function({data}) {
  postMessage(data + ' world');
};
