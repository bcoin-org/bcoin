# blgr

Node.js logger (used for bcoin).

## Usage

``` js
const blgr = require('blgr');
const logger = blgr.logger('debug');

logger.info('Hello');
logger.warning('world');
logger.error('!');
```

## Changelog

The `shrink` property has been removed, as well as the `truncate()` function.
Instead of deleting historical information from the log file at open, logger
will now "rotate" the log file when the file size reaches `MAX_FILE_SIZE`
(default about 20 MB). At that time, the file will be rotated out and
timestamped, and a new log file will be created. When the number of archival log
files reaches `MAX_ARCHIVAL_FILES` (default 10), the oldest archival files will
be removed from disk.

## Contribution and License Agreement

If you contribute code to this project, you are implicitly allowing your code
to be distributed under the MIT license. You are also implicitly verifying that
all code is your original work. `</legalese>`

## License

- Copyright (c) 2017, Christopher Jeffrey (MIT License).

See LICENSE for more info.
