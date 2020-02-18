'use strict';

/* global Notification */

const {errorify} = require('../../bmocha');

/*
 * Error Handling
 */

function addListener(event, handler) {
  if (global.addEventListener)
    global.addEventListener(event, handler, false);
  else if (global.attachEvent)
    global.attachEvent(`on${event}`, handler);
  else
    global[`on${event}`] = handler;
}

function removeListener(event, handler) {
  if (global.removeEventListener)
    global.removeEventListener(event, handler, false);
  else if (global.detachEvent)
    global.detachEvent(`on${event}`, handler);
  else
    global[`on${event}`] = null;
}

function catcher(reject) {
  const formatEvent = (event) => {
    if (event instanceof Error)
      return event;

    if (event.error instanceof Error)
      return event.error;

    if (event.message == null && event.filename == null)
      return new Error(String(event.type || 'unknown'));

    return new Error(`${event.message} `
                   + `(${event.filename}`
                   + `:${event.lineno}`
                   + `:${event.colno})`);
  };

  const onError = (event) => {
    event.preventDefault();
    event.stopPropagation();

    const err = formatEvent(event);

    err.uncaught = true;
    err.exception = true;

    reject(err);
  };

  const onRejection = (event) => {
    const {reason} = event;

    event.preventDefault();
    event.stopPropagation();

    const err = errorify(reason);

    err.uncaught = true;
    err.rejection = true;

    reject(err);
  };

  addListener('error', onError);
  addListener('unhandledrejection', onRejection);

  return () => {
    removeListener('error', onError);
    removeListener('unhandledrejection', onRejection);
  };
}

/*
 * Notifications
 */

async function canNotify() {
  if (typeof Notification !== 'function')
    return false;

  switch (Notification.permission) {
    case 'default':
      return (await Notification.requestPermission()) === 'granted';
    case 'granted':
      return true;
    case 'denied':
      return false;
    default:
      return false;
  }
}

async function notify(stats) {
  if (!await canNotify())
    return false;

  let msg, body, title;

  if (stats.failures > 0) {
    msg = `${stats.failures} of ${stats.total} tests failed`;
    body = `\u274c ${msg}`;
    title = 'Failed';
  } else {
    msg = `${stats.passes} tests passed in ${stats.duration}ms`;
    body = `\u2705 ${msg}`;
    title = 'Passed';
  }

  const {protocol, port} = global.location;
  const logo = `${protocol}//localhost:${port}/favicon.ico`;

  const note = new Notification(title, {
    badge: logo,
    body: body,
    dir: 'ltr',
    icon: logo,
    lang: 'en-US',
    name: 'bmocha',
    requireInteraction: false,
    timestamp: Date.now()
  });

  const close = () => note.close();

  setTimeout(close, 4000);

  global.onbeforeunload = close;
  global.onunload = close;

  return true;
}

/*
 * Expose
 */

exports.addListener = addListener;
exports.removeListener = removeListener;
exports.catcher = catcher;
exports.canNotify = canNotify;
exports.notify = notify;
