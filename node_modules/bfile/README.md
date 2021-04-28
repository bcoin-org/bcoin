# bfile

Filesystem wrapper for node.js. Provides a promisified API, along with a
consistent interface accross node.js versions. All changes to the node.js fs
API are tracked and accounted for in:

- [lib/features.js]
- [lib/legacy.js]
- [lib/compat.js]

bfile will wrap older implementations to modernize them. Supports node@8.0.0
and up.

## Usage

``` js
const fs = require('bfile');

(async () => {
  await fs.writeFile('./foobar', 'Hello world!');

  console.log(await fs.readFile('./foobar'));

  for await (const [file] of fs.walk('.'))
    console.log(`Found file: ${file}`);
})();
```

## Extras

In addition to the default FS API, bfile provides some extra helpers.

### API

#### Methods

- `fs.copy(src, [options])` (async) - Recursively copy file or directory to
  `dest`.
- `fs.copySync(src, dest, [filter(path, stat)])` - Synchronous `fs.copy`.
- `fs.empty(path, [mode])` (async) - Ensure an empty directory at `path`.
- `fs.emptySync(path, [mode])` - Synchronous `fs.empty`.
- `fs.exists(path, [mode])` (async) - A fixed version of `fs.exists`. Basically
  a wrapper around `fs.access` which returns false on `ENOENT` or `EACCESS`.
  Accepts `fs.access` flags as the second argument.
- `fs.existsSync(path, [mode])` - Synchronous `fs.exists`.
- `fs.lstatTry(path, [options])` (async) - A version of `fs.lstat` which
  returns `null` on `ENOENT` or `EACCES`.
- `fs.lstatTrySync(path, [options])` - Synchronous `fs.lstatTry`.
- `fs.move(src, dest)` (async) - Try to rename file. Recursively copies across
  devices, deleting the original, if necessary.
- `fs.moveSync(path, [mode])` - Synchronous `fs.move`.
- `fs.outputFile(path, data, [options])` (async) - Output file while ensuring
  the preceding directory structure exists. Basically a `mkdirp` wrapper around
  `writeFile()`.
- `fs.outputFileSync(path, data, [options])` - Synchronous `fs.outputFile`.
- `fs.mkdirp(path, [mode])` (async) - Alias to
  `fs.mkdir(path, { recursive: true })`.
- `fs.mkdirpSync(path, [mode])` - Synchronous `fs.mkdirp`.
- `fs.readJSON(path, [options])` (async) - Read a JSON file. Returns parsed
  JSON.
- `fs.readJSONSync(path, [options])` - Synchronous `fs.readJSON`.
- `fs.remove(path, [options])` (async) - Recursively remove `path`.
- `fs.removeSync(path, [options])` - Synchronous `fs.rimraf`.
- `fs.statTry(path, [options])` (async) - A version of `fs.stat` which returns
  `null` on `ENOENT` or `EACCES`.
- `fs.statTrySync(path, [options])` - Synchronous `fs.statTry`.
- `fs.stats(path, [options])` (async) - A stat function which will attempt to
  call `fs.lstat` if `fs.stat` fails with `ENOENT` or `EACCES` (depending on
  options). This is useful for detecting broken symlinks and getting their
  appropriate stat object. Accepts options in the form of
  `{ follow: [boolean], bigint: [boolean] }`.
- `fs.statsSync(path, [options])` - Synchronous `fs.stats`.
- `fs.statsTry(path, [options])` (async) - A version of `fs.stats` which
  returns `null` on `ENOENT` or `EACCES`.
- `fs.statsTrySync(path, [options])` - Synchronous `fs.statsTry`.
- `fs.traverse(paths, [options], callback)` (async) - Callback version of
  `fs.walk`.
- `fs.traverseSync(paths, [options], callback)` - Synchronous `fs.traverse`.
- `fs.walk(paths, [options])` - An async iterator which recursively walks the
  target path/paths.  Returns entries in the form of `[path, stat, depth]`.
  Note that `stat` may be `null` in the event of an `EACCES`, `EPERM`, or
  `ELOOP` if `options.throws` is false.
- `fs.walkSync(paths, [options])` - Synchronous `fs.walk`.
- `fs.writeJSON(path, json, [options])` (async) - Write a JSON file
  (stringifies `json`).
- `fs.writeJSONSync(path, json, [options])` - Synchronous `fs.writeJSON`.

#### Options

##### `fs.copy` options

- `flags` (number) - A bitfield to be passed to `fs.copyFile{,Sync}` as flags
  (default: `0`).
- `filter(path, stat, depth)` (function) - A callback to filter determine which
  files are copied (default: `null`).
- `follow` (boolean) - Whether to follow symlinks for `src` (default: `false`).
- `overwrite` (boolean) - Whether to overwrite existing files at the
  destination (default: `false`).
- `timestamps` (boolean) - Whether to preserve file timestamps (default:
  `false`).

##### `fs.readJSON` options

Options are the standard `fs.readFile` options with some extras:

- `reviver(key, value)` (function) - Reviver function for JSON parsing
  (default: `null`).

Options may also be a function as an alias for the `reviver` option.

##### `fs.remove` options

- `filter(path, stat, depth)` (function) - A callback to filter determine which
  files are removed (default: `null`).
- `maxRetries` (number) - Number of retries for `EBUSY`, `EMFILE`, `ENFILE`,
  `ENOTEMPTY`, or `EPERM` (default: `3`).
- `retryDelay` (number) - Number of milliseconds to wait in between retries.

Options may also be a function as an alias for the `filter` option.

##### `fs.stats` options

`fs.stats` and `fs.statsSync` accept an object with properties:

- `follow` (boolean) - Whether to attempt calling `fs.stat` before
  `fs.lstat`. If false, behavior is identical to `fs.lstat` (default: `true`).
- `bigint` (boolean) - Whether to use `BigInt`s on the `fs.Stats` struct
  (default: `false`).

Options may also be a boolean as an alias for the `follow` option.

##### `fs.{traverse,walk}` options

`fs.traverse`, `fs.traverseSync`, `fs.walk`, and `fs.walkSync` accept an object
with properties:

- `bigint` (boolean) - Whether to use `BigInt`s on the `fs.Stats` struct
  (default: `false`).
- `dirs` (boolean) - Whether to return directories in the iterated results
  (default: `false`).
- `files` (boolean) - Whether to return non-directory files in the iterated
  results (default: `false`).
- `filter(path, stat, depth)` (function) - A callback to filter determine which
  directories are entered and which files are returned. Note that `stat` may be
  `null` if `options.throws` is false (default: `null`).
- `follow` (boolean) - Whether to follow symlinks. Note that the walking
  functions are smart enough to avoid recursive symlink loops (default:
  `true`).
- `maxDepth` (number) - Maximum depth to traverse. For reference, `paths` are
  depth `0`.  Set to `-1` for no limit (default: `-1`).
- `throws` (boolean) - Whether to throw on stat failure (default: `false`).

##### `fs.writeJSON` options

Options are the standard `fs.writeFile` options with some extras:

- `replacer(key, value)` (function) - Replacer function for JSON
  stringification (default: `null`).
- `spaces` (number) - Number of spaces to indent by (default: `2`).
- `eol` (string) - Line ending to use for the output text (default: `\n`).

Options may also be a function as an alias for the `reviver` option, or a
number for the `spaces` option.

#### Detecting broken symlinks with `fs.stats` and `fs.{traverse,walk}`

`fs.stats` and the walking functions allow you to detect broken symlinks easily
when the `follow` option is on:

``` js
const stat = await fs.statsTry('./foobar');

if (!stat) // ENOENT or EACCES
  throw new Error('File not found.');

if (stat.isSymbolicLink()) // A symlink we couldn't resolve
  throw new Error('Broken symlink detected.');
```

## Contribution and License Agreement

If you contribute code to this project, you are implicitly allowing your code
to be distributed under the MIT license. You are also implicitly verifying that
all code is your original work. `</legalese>`

## License

- Copyright (c) 2014-2019, Christopher Jeffrey (MIT License).

See LICENSE for more info.

[lib/features.js]: https://github.com/bcoin-org/bfile/blob/master/lib/features.js
[lib/legacy.js]: https://github.com/bcoin-org/bfile/blob/master/lib/legacy.js
[lib/compat.js]: https://github.com/bcoin-org/bfile/blob/master/lib/compat.js
