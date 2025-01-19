/******/ (() => {
  // webpackBootstrap
  /******/ var __webpack_modules__ = {
    /***/ 1924: /***/ (
      module,
      __unused_webpack_exports,
      __webpack_require__,
    ) => {
      'use strict';
      /*!
       * send
       * Copyright(c) 2012 TJ Holowaychuk
       * Copyright(c) 2014-2022 Douglas Christopher Wilson
       * MIT Licensed
       */

      /**
       * Module dependencies.
       * @private
       */
      const isUtf8MimeType = __webpack_require__(7205).isUtf8MimeType;
      const mime = __webpack_require__(2360);
      const SendStream = __webpack_require__(7164);

      /**
       * Return a `SendStream` for `req` and `path`.
       *
       * @param {object} req
       * @param {string} path
       * @param {object} [options]
       * @return {SendStream}
       * @public
       */

      function send(req, path, options) {
        return new SendStream(req, path, options);
      }

      /**
       * Module exports.
       * @public
       */

      module.exports = send;
      module.exports['default'] = send;
      module.exports.send = send;
      module.exports.SendStream = SendStream;

      module.exports.isUtf8MimeType = isUtf8MimeType;
      module.exports.mime = mime;

      /***/
    },

    /***/ 7164: /***/ (
      module,
      __unused_webpack_exports,
      __webpack_require__,
    ) => {
      'use strict';
      /*!
       * send
       * Copyright(c) 2012 TJ Holowaychuk
       * Copyright(c) 2014-2022 Douglas Christopher Wilson
       * MIT Licensed
       */

      const fs = __webpack_require__(3024);
      const path = __webpack_require__(6760);
      const Stream = __webpack_require__(7075);
      const util = __webpack_require__(7975);
      const debug = __webpack_require__(7975).debuglog('send');

      const decode = __webpack_require__(8493);
      const escapeHtml = __webpack_require__(6725);
      const mime = __webpack_require__(2360);
      const ms = __webpack_require__(8374);

      const { clearHeaders } = __webpack_require__(9215);
      const { collapseLeadingSlashes } = __webpack_require__(2);
      const { containsDotFile } = __webpack_require__(8866);
      const { contentRange } = __webpack_require__(6708);
      const { createHtmlDocument } = __webpack_require__(6674);
      const { createHttpError } = __webpack_require__(6274);
      const { isUtf8MimeType } = __webpack_require__(7205);
      const { normalizeList } = __webpack_require__(2075);
      const { parseBytesRange } = __webpack_require__(8803);
      const { parseTokenList } = __webpack_require__(8030);
      const { setHeaders } = __webpack_require__(5376);

      /**
       * Path function references.
       * @private
       */

      const extname = path.extname;
      const join = path.join;
      const normalize = path.normalize;
      const resolve = path.resolve;
      const sep = path.sep;

      /**
       * Regular expression for identifying a bytes Range header.
       * @private
       */

      const BYTES_RANGE_REGEXP = /^ *bytes=/;

      /**
       * Maximum value allowed for the max age.
       * @private
       */

      const MAX_MAXAGE = 60 * 60 * 24 * 365 * 1000; // 1 year

      /**
       * Regular expression to match a path with a directory up component.
       * @private
       */

      const UP_PATH_REGEXP = /(?:^|[\\/])\.\.(?:[\\/]|$)/;

      const ERROR_RESPONSES = {
        400: createHtmlDocument('Error', 'Bad Request'),
        403: createHtmlDocument('Error', 'Forbidden'),
        404: createHtmlDocument('Error', 'Not Found'),
        412: createHtmlDocument('Error', 'Precondition Failed'),
        416: createHtmlDocument('Error', 'Range Not Satisfiable'),
        500: createHtmlDocument('Error', 'Internal Server Error'),
      };

      const validDotFilesOptions = ['allow', 'ignore', 'deny'];

      /**
       * Initialize a `SendStream` with the given `path`.
       *
       * @param {Request} req
       * @param {String} path
       * @param {object} [options]
       * @private
       */

      function SendStream(req, path, options) {
        if (!new.target) {
          return new SendStream(req, path, options);
        }
        Stream.call(this);

        const opts = options || {};

        this.options = opts;
        this.path = path;
        this.req = req;

        this._acceptRanges =
          opts.acceptRanges !== undefined ? Boolean(opts.acceptRanges) : true;

        this._cacheControl =
          opts.cacheControl !== undefined ? Boolean(opts.cacheControl) : true;

        this._etag = opts.etag !== undefined ? Boolean(opts.etag) : true;

        this._dotfiles =
          opts.dotfiles !== undefined
            ? validDotFilesOptions.indexOf(opts.dotfiles)
            : 1; // 'ignore'

        if (this._dotfiles === -1) {
          throw new TypeError(
            'dotfiles option must be "allow", "deny", or "ignore"',
          );
        }

        this._extensions =
          opts.extensions !== undefined
            ? normalizeList(opts.extensions, 'extensions option')
            : [];

        this._immutable =
          opts.immutable !== undefined ? Boolean(opts.immutable) : false;

        this._index =
          opts.index !== undefined
            ? normalizeList(opts.index, 'index option')
            : ['index.html'];

        this._lastModified =
          opts.lastModified !== undefined ? Boolean(opts.lastModified) : true;

        this._maxage = opts.maxAge || opts.maxage;
        this._maxage =
          typeof this._maxage === 'string'
            ? ms.parse(this._maxage)
            : Number(this._maxage);
        // eslint-disable-next-line no-self-compare
        this._maxage =
          this._maxage === this._maxage // fast path of isNaN(number)
            ? Math.min(Math.max(0, this._maxage), MAX_MAXAGE)
            : 0;

        this._root = opts.root ? resolve(opts.root) : null;
      }

      /**
       * Inherits from `Stream`.
       */

      util.inherits(SendStream, Stream);

      /**
       * Set root `path`.
       *
       * @param {String} path
       * @return {SendStream}
       * @api private
       */

      SendStream.prototype.root = function root(path) {
        this._root = resolve(String(path));
        debug('root %s', this._root);
        return this;
      };

      /**
       * Emit error with `status`.
       *
       * @memberof SendStream
       * @param {number} status
       * @param {Error} [err]
       * @this {Stream}
       * @private
       */

      SendStream.prototype.error = function error(status, err) {
        // emit if listeners instead of responding
        if (this.listenerCount('error') > 0) {
          return this.emit('error', createHttpError(status, err));
        }

        const res = this.res;

        // clear existing headers
        clearHeaders(res);

        // add error headers
        if (err && err.headers) {
          setHeaders(res, err.headers);
        }

        const doc = ERROR_RESPONSES[status];

        // send basic response
        res.statusCode = status;
        res.setHeader('Content-Type', 'text/html; charset=UTF-8');
        res.setHeader('Content-Length', doc[1]);
        res.setHeader('Content-Security-Policy', "default-src 'none'");
        res.setHeader('X-Content-Type-Options', 'nosniff');
        res.end(doc[0]);
      };

      /**
       * Check if the pathname ends with "/".
       *
       * @return {boolean}
       * @private
       */

      SendStream.prototype.hasTrailingSlash = function hasTrailingSlash() {
        return this.path[this.path.length - 1] === '/';
      };

      /**
       * Check if this is a conditional GET request.
       *
       * @return {Boolean}
       * @api private
       */

      SendStream.prototype.isConditionalGET = function isConditionalGET() {
        return (
          this.req.headers['if-match'] ||
          this.req.headers['if-unmodified-since'] ||
          this.req.headers['if-none-match'] ||
          this.req.headers['if-modified-since']
        );
      };

      SendStream.prototype.isNotModifiedFailure =
        function isNotModifiedFailure() {
          const req = this.req;
          const res = this.res;

          // Always return stale when Cache-Control: no-cache
          // to support end-to-end reload requests
          // https://tools.ietf.org/html/rfc2616#section-14.9.4
          if (
            'cache-control' in req.headers &&
            req.headers['cache-control'].indexOf('no-cache') !== -1
          ) {
            return false;
          }

          // if-none-match
          if ('if-none-match' in req.headers) {
            const ifNoneMatch = req.headers['if-none-match'];

            if (ifNoneMatch === '*') {
              return true;
            }

            const etag = res.getHeader('etag');

            if (typeof etag !== 'string') {
              return false;
            }

            const etagL = etag.length;
            const isMatching = parseTokenList(ifNoneMatch, function (match) {
              const mL = match.length;

              if (
                (etagL === mL && match === etag) ||
                (etagL > mL && 'W/' + match === etag)
              ) {
                return true;
              }
            });

            if (isMatching) {
              return true;
            }

            /**
             * A recipient MUST ignore If-Modified-Since if the request contains an
             * If-None-Match header field; the condition in If-None-Match is considered
             * to be a more accurate replacement for the condition in If-Modified-Since,
             * and the two are only combined for the sake of interoperating with older
             * intermediaries that might not implement If-None-Match.
             *
             * @see RFC 9110 section 13.1.3
             */
            return false;
          }

          // if-modified-since
          if ('if-modified-since' in req.headers) {
            const ifModifiedSince = req.headers['if-modified-since'];
            const lastModified = res.getHeader('last-modified');

            if (
              !lastModified ||
              Date.parse(lastModified) <= Date.parse(ifModifiedSince)
            ) {
              return true;
            }
          }

          return false;
        };

      /**
       * Check if the request preconditions failed.
       *
       * @return {boolean}
       * @private
       */

      SendStream.prototype.isPreconditionFailure =
        function isPreconditionFailure() {
          const req = this.req;
          const res = this.res;

          // if-match
          const ifMatch = req.headers['if-match'];
          if (ifMatch) {
            const etag = res.getHeader('ETag');

            if (ifMatch !== '*') {
              const isMatching =
                parseTokenList(ifMatch, function (match) {
                  if (match === etag || 'W/' + match === etag) {
                    return true;
                  }
                }) || false;

              if (isMatching !== true) {
                return true;
              }
            }
          }

          // if-unmodified-since
          if ('if-unmodified-since' in req.headers) {
            const ifUnmodifiedSince = req.headers['if-unmodified-since'];
            const unmodifiedSince = Date.parse(ifUnmodifiedSince);
            // eslint-disable-next-line no-self-compare
            if (unmodifiedSince === unmodifiedSince) {
              // fast path of isNaN(number)
              const lastModified = Date.parse(res.getHeader('Last-Modified'));
              if (
                // eslint-disable-next-line no-self-compare
                lastModified !== lastModified || // fast path of isNaN(number)
                lastModified > unmodifiedSince
              ) {
                return true;
              }
            }
          }

          return false;
        };

      /**
       * Strip various content header fields for a change in entity.
       *
       * @private
       */

      SendStream.prototype.removeContentHeaderFields =
        function removeContentHeaderFields() {
          const res = this.res;

          res.removeHeader('Content-Encoding');
          res.removeHeader('Content-Language');
          res.removeHeader('Content-Length');
          res.removeHeader('Content-Range');
          res.removeHeader('Content-Type');
        };

      /**
       * Respond with 304 not modified.
       *
       * @api private
       */

      SendStream.prototype.notModified = function notModified() {
        const res = this.res;
        debug('not modified');
        this.removeContentHeaderFields();
        res.statusCode = 304;
        res.end();
      };

      /**
       * Raise error that headers already sent.
       *
       * @api private
       */

      SendStream.prototype.headersAlreadySent = function headersAlreadySent() {
        const err = new Error("Can't set headers after they are sent.");
        debug('headers already sent');
        this.error(500, err);
      };

      /**
       * Check if the request is cacheable, aka
       * responded with 2xx or 304 (see RFC 2616 section 14.2{5,6}).
       *
       * @return {Boolean}
       * @api private
       */

      SendStream.prototype.isCachable = function isCachable() {
        const statusCode = this.res.statusCode;
        return (statusCode >= 200 && statusCode < 300) || statusCode === 304;
      };

      /**
       * Handle stat() error.
       *
       * @param {Error} error
       * @private
       */

      SendStream.prototype.onStatError = function onStatError(error) {
        // POSIX throws ENAMETOOLONG and ENOTDIR, Windows only ENOENT
        /* istanbul ignore next */
        switch (error.code) {
          case 'ENAMETOOLONG':
          case 'ENOTDIR':
          case 'ENOENT':
            this.error(404, error);
            break;
          default:
            this.error(500, error);
            break;
        }
      };

      /**
       * Check if the range is fresh.
       *
       * @return {Boolean}
       * @api private
       */

      SendStream.prototype.isRangeFresh = function isRangeFresh() {
        if (!('if-range' in this.req.headers)) {
          return true;
        }

        const ifRange = this.req.headers['if-range'];

        // if-range as etag
        if (ifRange.indexOf('"') !== -1) {
          const etag = this.res.getHeader('ETag');
          return (etag && ifRange.indexOf(etag) !== -1) || false;
        }

        const ifRangeTimestamp = Date.parse(ifRange);
        // eslint-disable-next-line no-self-compare
        if (ifRangeTimestamp !== ifRangeTimestamp) {
          // fast path of isNaN(number)
          return false;
        }

        // if-range as modified date
        const lastModified = Date.parse(this.res.getHeader('Last-Modified'));

        return (
          // eslint-disable-next-line no-self-compare
          lastModified !== lastModified || // fast path of isNaN(number)
          lastModified <= ifRangeTimestamp
        );
      };

      /**
       * Redirect to path.
       *
       * @param {string} path
       * @private
       */

      SendStream.prototype.redirect = function redirect(path) {
        const res = this.res;

        if (this.listenerCount('directory') > 0) {
          this.emit('directory', res, path);
          return;
        }

        if (this.hasTrailingSlash()) {
          this.error(403);
          return;
        }

        const loc = encodeURI(collapseLeadingSlashes(this.path + '/'));
        const doc = createHtmlDocument(
          'Redirecting',
          'Redirecting to <a href="' +
            escapeHtml(loc) +
            '">' +
            escapeHtml(loc) +
            '</a>',
        );

        // redirect
        res.statusCode = 301;
        res.setHeader('Content-Type', 'text/html; charset=UTF-8');
        res.setHeader('Content-Length', doc[1]);
        res.setHeader('Content-Security-Policy', "default-src 'none'");
        res.setHeader('X-Content-Type-Options', 'nosniff');
        res.setHeader('Location', loc);
        res.end(doc[0]);
      };

      /**
       * Pipe to `res.
       *
       * @param {Stream} res
       * @return {Stream} res
       * @api public
       */

      SendStream.prototype.pipe = function pipe(res) {
        // root path
        const root = this._root;

        // references
        this.res = res;

        // decode the path
        let path = decode(this.path);
        if (path === null) {
          this.error(400);
          return res;
        }

        // null byte(s)
        if (~path.indexOf('\0')) {
          this.error(400);
          return res;
        }

        let parts;
        if (root !== null) {
          // normalize
          if (path) {
            path = normalize('.' + sep + path);
          }

          // malicious path
          if (UP_PATH_REGEXP.test(path)) {
            debug('malicious path "%s"', path);
            this.error(403);
            return res;
          }

          // explode path parts
          parts = path.split(sep);

          // join / normalize from optional root dir
          path = normalize(join(root, path));
        } else {
          // ".." is malicious without "root"
          if (UP_PATH_REGEXP.test(path)) {
            debug('malicious path "%s"', path);
            this.error(403);
            return res;
          }

          // explode path parts
          parts = normalize(path).split(sep);

          // resolve the path
          path = resolve(path);
        }

        // dotfile handling
        if (
          (debug.enabled || // if debugging is enabled, then check for all cases to log allow case
            this._dotfiles !== 0) && // if debugging is not enabled, then only check if 'deny' or 'ignore' is set
          containsDotFile(parts)
        ) {
          switch (this._dotfiles) {
            /* istanbul ignore next: unreachable, because NODE_DEBUG can not be set after process is running */
            case 0: // 'allow'
              debug('allow dotfile "%s"', path);
              break;
            case 2: // 'deny'
              debug('deny dotfile "%s"', path);
              this.error(403);
              return res;
            case 1: // 'ignore'
            default:
              debug('ignore dotfile "%s"', path);
              this.error(404);
              return res;
          }
        }

        // index file support
        if (this._index.length && this.hasTrailingSlash()) {
          this.sendIndex(path);
          return res;
        }

        this.sendFile(path);
        return res;
      };

      /**
       * Transfer `path`.
       *
       * @param {String} path
       * @api public
       */

      SendStream.prototype.send = function send(path, stat) {
        let len = stat.size;
        const options = this.options;
        const opts = {};
        const res = this.res;
        const req = this.req;
        let offset = options.start || 0;

        if (res.headersSent) {
          // impossible to send now
          this.headersAlreadySent();
          return;
        }

        debug('pipe "%s"', path);

        // set header fields
        this.setHeader(path, stat);

        // set content-type
        this.type(path);

        // conditional GET support
        if (this.isConditionalGET()) {
          if (this.isPreconditionFailure()) {
            this.error(412);
            return;
          }

          if (this.isCachable() && this.isNotModifiedFailure()) {
            this.notModified();
            return;
          }
        }

        // adjust len to start/end options
        len = Math.max(0, len - offset);
        if (options.end !== undefined) {
          const bytes = options.end - offset + 1;
          if (len > bytes) len = bytes;
        }

        // Range support
        if (this._acceptRanges) {
          const rangeHeader = req.headers.range;

          if (
            rangeHeader !== undefined &&
            BYTES_RANGE_REGEXP.test(rangeHeader)
          ) {
            // If-Range support
            if (this.isRangeFresh()) {
              // parse
              const ranges = parseBytesRange(len, rangeHeader);

              // unsatisfiable
              if (ranges.length === 0) {
                debug('range unsatisfiable');

                // Content-Range
                res.setHeader('Content-Range', contentRange('bytes', len));

                // 416 Requested Range Not Satisfiable
                return this.error(416, {
                  headers: { 'Content-Range': res.getHeader('Content-Range') },
                });
                // valid (syntactically invalid/multiple ranges are treated as a regular response)
              } else if (ranges.length === 1) {
                debug('range %j', ranges);

                // Content-Range
                res.statusCode = 206;
                res.setHeader(
                  'Content-Range',
                  contentRange('bytes', len, ranges[0]),
                );

                // adjust for requested range
                offset += ranges[0].start;
                len = ranges[0].end - ranges[0].start + 1;
              }
            } else {
              debug('range stale');
            }
          }
        }

        // clone options
        for (const prop in options) {
          opts[prop] = options[prop];
        }

        // set read options
        opts.start = offset;
        opts.end = Math.max(offset, offset + len - 1);

        // content-length
        res.setHeader('Content-Length', len);

        // HEAD support
        if (req.method === 'HEAD') {
          res.end();
          return;
        }

        this.stream(path, opts);
      };

      /**
       * Transfer file for `path`.
       *
       * @param {String} path
       * @api private
       */
      SendStream.prototype.sendFile = function sendFile(path) {
        let i = 0;
        const self = this;

        debug('stat "%s"', path);
        fs.stat(path, function onstat(err, stat) {
          if (
            err &&
            err.code === 'ENOENT' &&
            !extname(path) &&
            path[path.length - 1] !== sep
          ) {
            // not found, check extensions
            return next(err);
          }
          if (err) return self.onStatError(err);
          if (stat.isDirectory()) return self.redirect(path);
          self.emit('file', path, stat);
          self.send(path, stat);
        });

        function next(err) {
          if (self._extensions.length <= i) {
            return err ? self.onStatError(err) : self.error(404);
          }

          const p = path + '.' + self._extensions[i++];

          debug('stat "%s"', p);
          fs.stat(p, function (err, stat) {
            if (err) return next(err);
            if (stat.isDirectory()) return next();
            self.emit('file', p, stat);
            self.send(p, stat);
          });
        }
      };

      /**
       * Transfer index for `path`.
       *
       * @param {String} path
       * @api private
       */
      SendStream.prototype.sendIndex = function sendIndex(path) {
        let i = -1;
        const self = this;

        function next(err) {
          if (++i >= self._index.length) {
            if (err) return self.onStatError(err);
            return self.error(404);
          }

          const p = join(path, self._index[i]);

          debug('stat "%s"', p);
          fs.stat(p, function (err, stat) {
            if (err) return next(err);
            if (stat.isDirectory()) return next();
            self.emit('file', p, stat);
            self.send(p, stat);
          });
        }

        next();
      };

      /**
       * Stream `path` to the response.
       *
       * @param {String} path
       * @param {Object} options
       * @api private
       */

      SendStream.prototype.stream = function stream(path, options) {
        const self = this;
        const res = this.res;

        // pipe
        const stream = fs.createReadStream(path, options);
        this.emit('stream', stream);
        stream.pipe(res);

        let destroyed = false;

        // destroy piped stream
        function destroy() {
          if (destroyed) {
            return;
          }
          destroyed = true;
          stream.destroy();
        }

        res.once('finish', destroy);

        // error handling
        stream.on('error', function onerror(err) {
          // clean up stream early
          destroy();

          // error
          self.onStatError(err);
        });

        // end
        stream.on('end', function onend() {
          self.emit('end');
        });
      };

      /**
       * Set content-type based on `path`
       * if it hasn't been explicitly set.
       *
       * @param {String} path
       * @api private
       */

      SendStream.prototype.type = function type(path) {
        const res = this.res;

        if (res.getHeader('Content-Type')) return;

        const type = mime.getType(path) || mime.default_type;

        if (!type) {
          debug('no content-type');
          return;
        }

        debug('content-type %s', type);
        if (isUtf8MimeType(type)) {
          res.setHeader('Content-Type', type + '; charset=UTF-8');
        } else {
          res.setHeader('Content-Type', type);
        }
      };

      /**
       * Set response header fields, most
       * fields may be pre-defined.
       *
       * @param {String} path
       * @param {Object} stat
       * @api private
       */

      SendStream.prototype.setHeader = function setHeader(path, stat) {
        const res = this.res;

        this.emit('headers', res, path, stat);

        if (this._acceptRanges && !res.getHeader('Accept-Ranges')) {
          debug('accept ranges');
          res.setHeader('Accept-Ranges', 'bytes');
        }

        if (this._cacheControl && !res.getHeader('Cache-Control')) {
          let cacheControl =
            'public, max-age=' + Math.floor(this._maxage / 1000);

          if (this._immutable) {
            cacheControl += ', immutable';
          }

          debug('cache-control %s', cacheControl);
          res.setHeader('Cache-Control', cacheControl);
        }

        if (this._lastModified && !res.getHeader('Last-Modified')) {
          const modified = stat.mtime.toUTCString();
          debug('modified %s', modified);
          res.setHeader('Last-Modified', modified);
        }

        if (this._etag && !res.getHeader('ETag')) {
          const etag =
            'W/"' +
            stat.size.toString(16) +
            '-' +
            stat.mtime.getTime().toString(16) +
            '"';
          debug('etag %s', etag);
          res.setHeader('ETag', etag);
        }
      };

      /**
       * Module exports.
       * @public
       */

      module.exports = SendStream;

      /***/
    },

    /***/ 9215: /***/ (__unused_webpack_module, exports) => {
      'use strict';
      /*!
       * send
       * Copyright(c) 2012 TJ Holowaychuk
       * Copyright(c) 2014-2022 Douglas Christopher Wilson
       * MIT Licensed
       */

      /**
       * Clear all headers from a response.
       *
       * @param {object} res
       * @private
       */
      function clearHeaders(res) {
        const headers = res.getHeaderNames();

        for (let i = 0; i < headers.length; i++) {
          res.removeHeader(headers[i]);
        }
      }
      exports.clearHeaders = clearHeaders;

      /***/
    },

    /***/ 2: /***/ (module) => {
      'use strict';

      /**
       * Collapse all leading slashes into a single slash
       *
       * @param {string} str
       * @private
       */

      function collapseLeadingSlashes(str) {
        if (str[0] !== '/' || str[1] !== '/') {
          return str;
        }
        for (let i = 2, il = str.length; i < il; ++i) {
          if (str[i] !== '/') {
            return str.slice(i - 1);
          }
        }
      }

      module.exports.collapseLeadingSlashes = collapseLeadingSlashes;

      /***/
    },

    /***/ 8866: /***/ (module) => {
      'use strict';
      /*!
       * send
       * Copyright(c) 2012 TJ Holowaychuk
       * Copyright(c) 2014-2022 Douglas Christopher Wilson
       * MIT Licensed
       */

      /**
       * Determine if path parts contain a dotfile.
       *
       * @api private
       */
      function containsDotFile(parts) {
        for (let i = 0, il = parts.length; i < il; ++i) {
          if (parts[i].length !== 1 && parts[i][0] === '.') {
            return true;
          }
        }

        return false;
      }

      module.exports.containsDotFile = containsDotFile;

      /***/
    },

    /***/ 6708: /***/ (__unused_webpack_module, exports) => {
      'use strict';
      /*!
       * send
       * Copyright(c) 2012 TJ Holowaychuk
       * Copyright(c) 2014-2022 Douglas Christopher Wilson
       * MIT Licensed
       */

      /**
       * Create a Content-Range header.
       *
       * @param {string} type
       * @param {number} size
       * @param {array} [range]
       */
      function contentRange(type, size, range) {
        return (
          type +
          ' ' +
          (range ? range.start + '-' + range.end : '*') +
          '/' +
          size
        );
      }
      exports.contentRange = contentRange;

      /***/
    },

    /***/ 6674: /***/ (__unused_webpack_module, exports) => {
      'use strict';
      /*!
       * send
       * Copyright(c) 2012 TJ Holowaychuk
       * Copyright(c) 2014-2022 Douglas Christopher Wilson
       * MIT Licensed
       */

      /**
       * Create a minimal HTML document.
       *
       * @param {string} title
       * @param {string} body
       * @private
       */
      function createHtmlDocument(title, body) {
        const html =
          '<!DOCTYPE html>\n' +
          '<html lang="en">\n' +
          '<head>\n' +
          '<meta charset="utf-8">\n' +
          '<title>' +
          title +
          '</title>\n' +
          '</head>\n' +
          '<body>\n' +
          '<pre>' +
          body +
          '</pre>\n' +
          '</body>\n' +
          '</html>\n';

        return [html, Buffer.byteLength(html)];
      }
      exports.createHtmlDocument = createHtmlDocument;

      /***/
    },

    /***/ 6274: /***/ (
      module,
      __unused_webpack_exports,
      __webpack_require__,
    ) => {
      'use strict';

      const createError = __webpack_require__(1771);

      /**
       * Create a HttpError object from simple arguments.
       *
       * @param {number} status
       * @param {Error|object} err
       * @private
       */

      function createHttpError(status, err) {
        if (!err) {
          return createError(status);
        }

        return err instanceof Error
          ? createError(status, err, { expose: false })
          : createError(status, err);
      }

      module.exports.createHttpError = createHttpError;

      /***/
    },

    /***/ 7205: /***/ (module) => {
      'use strict';

      function isUtf8MimeType(value) {
        const len = value.length;
        return (
          (len > 21 && value.indexOf('application/javascript') === 0) ||
          (len > 14 && value.indexOf('application/json') === 0) ||
          (len > 5 && value.indexOf('text/') === 0)
        );
      }

      module.exports.isUtf8MimeType = isUtf8MimeType;

      /***/
    },

    /***/ 2075: /***/ (module) => {
      'use strict';

      /**
       * Normalize the index option into an array.
       *
       * @param {boolean|string|array} val
       * @param {string} name
       * @private
       */

      function normalizeList(val, name) {
        if (typeof val === 'string') {
          return [val];
        } else if (val === false) {
          return [];
        } else if (Array.isArray(val)) {
          for (let i = 0, il = val.length; i < il; ++i) {
            if (typeof val[i] !== 'string') {
              throw new TypeError(name + ' must be array of strings or false');
            }
          }
          return val;
        } else {
          throw new TypeError(name + ' must be array of strings or false');
        }
      }

      module.exports.normalizeList = normalizeList;

      /***/
    },

    /***/ 8803: /***/ (module) => {
      'use strict';

      /*!
       * Based on range-parser
       *
       * Copyright(c) 2012-2014 TJ Holowaychuk
       * Copyright(c) 2015-2016 Douglas Christopher Wilson
       * MIT Licensed
       */

      /**
       * Parse "Range" header `str` relative to the given file `size`.
       *
       * @param {Number} size
       * @param {String} str
       * @return {Array}
       * @public
       */

      function parseBytesRange(size, str) {
        // split the range string
        const values = str.slice(str.indexOf('=') + 1);
        const ranges = [];

        const len = values.length;
        let i = 0;
        let il = 0;
        let j = 0;
        let start;
        let end;
        let commaIdx = values.indexOf(',');
        let dashIdx = values.indexOf('-');
        let prevIdx = -1;

        // parse all ranges
        while (true) {
          commaIdx === -1 && (commaIdx = len);
          start = parseInt(values.slice(prevIdx + 1, dashIdx), 10);
          end = parseInt(values.slice(dashIdx + 1, commaIdx), 10);

          // -nnn
          // eslint-disable-next-line no-self-compare
          if (start !== start) {
            // fast path of isNaN(number)
            start = size - end;
            end = size - 1;
            // nnn-
            // eslint-disable-next-line no-self-compare
          } else if (end !== end) {
            // fast path of isNaN(number)
            end = size - 1;
            // limit last-byte-pos to current length
          } else if (end > size - 1) {
            end = size - 1;
          }

          // add range only on valid ranges
          if (
            // eslint-disable-next-line no-self-compare
            start === start && // fast path of isNaN(number)
            // eslint-disable-next-line no-self-compare
            end === end && // fast path of isNaN(number)
            start > -1 &&
            start <= end
          ) {
            // add range
            ranges.push({
              start,
              end,
              index: j++,
            });
          }

          if (commaIdx === len) {
            break;
          }
          prevIdx = commaIdx++;
          dashIdx = values.indexOf('-', commaIdx);
          commaIdx = values.indexOf(',', commaIdx);
        }

        // unsatisfiable
        if (j < 2) {
          return ranges;
        }

        ranges.sort(sortByRangeStart);

        il = j;
        j = 0;
        i = 1;
        while (i < il) {
          const range = ranges[i++];
          const current = ranges[j];

          if (range.start > current.end + 1) {
            // next range
            ranges[++j] = range;
          } else if (range.end > current.end) {
            // extend range
            current.end = range.end;
            current.index > range.index && (current.index = range.index);
          }
        }

        // trim ordered array
        ranges.length = j + 1;

        // generate combined range
        ranges.sort(sortByRangeIndex);

        return ranges;
      }

      /**
       * Sort function to sort ranges by index.
       * @private
       */

      function sortByRangeIndex(a, b) {
        return a.index - b.index;
      }

      /**
       * Sort function to sort ranges by start position.
       * @private
       */

      function sortByRangeStart(a, b) {
        return a.start - b.start;
      }

      module.exports.parseBytesRange = parseBytesRange;

      /***/
    },

    /***/ 8030: /***/ (module) => {
      'use strict';

      /**
       * Parse a HTTP token list.
       *
       * @param {string} str
       * @private
       */

      const slice = String.prototype.slice;

      function parseTokenList(str, cb) {
        let end = 0;
        let start = 0;
        let result;

        // gather tokens
        for (let i = 0, len = str.length; i < len; i++) {
          switch (str.charCodeAt(i)) {
            case 0x20 /*   */:
              if (start === end) {
                start = end = i + 1;
              }
              break;
            case 0x2c /* , */:
              if (start !== end) {
                result = cb(slice.call(str, start, end));
                if (result !== undefined) {
                  return result;
                }
              }
              start = end = i + 1;
              break;
            default:
              end = i + 1;
              break;
          }
        }

        // final token
        if (start !== end) {
          return cb(slice.call(str, start, end));
        }
      }

      module.exports.parseTokenList = parseTokenList;

      /***/
    },

    /***/ 5376: /***/ (module) => {
      'use strict';

      /**
       * Set an object of headers on a response.
       *
       * @param {object} res
       * @param {object} headers
       * @private
       */

      function setHeaders(res, headers) {
        const keys = Object.keys(headers);

        for (let i = 0; i < keys.length; i++) {
          const key = keys[i];
          res.setHeader(key, headers[key]);
        }
      }

      module.exports.setHeaders = setHeaders;

      /***/
    },

    /***/ 8374: /***/ (__unused_webpack_module, exports) => {
      var RGX =
          /^(-?(?:\d+)?\.?\d+) *(m(?:illiseconds?|s(?:ecs?)?))?(s(?:ec(?:onds?|s)?)?)?(m(?:in(?:utes?|s)?)?)?(h(?:ours?|rs?)?)?(d(?:ays?)?)?(w(?:eeks?|ks?)?)?(y(?:ears?|rs?)?)?$/,
        SEC = 1e3,
        MIN = SEC * 60,
        HOUR = MIN * 60,
        DAY = HOUR * 24,
        YEAR = DAY * 365.25;

      function parse(val) {
        var num,
          arr = val.toLowerCase().match(RGX);
        if (arr != null && (num = parseFloat(arr[1]))) {
          if (arr[3] != null) return num * SEC;
          if (arr[4] != null) return num * MIN;
          if (arr[5] != null) return num * HOUR;
          if (arr[6] != null) return num * DAY;
          if (arr[7] != null) return num * DAY * 7;
          if (arr[8] != null) return num * YEAR;
          return num;
        }
      }

      function fmt(val, pfx, str, long) {
        var num = (val | 0) === val ? val : ~~(val + 0.5);
        return pfx + num + (long ? ' ' + str + (num != 1 ? 's' : '') : str[0]);
      }

      function format(num, long) {
        var pfx = num < 0 ? '-' : '',
          abs = num < 0 ? -num : num;
        if (abs < SEC) return num + (long ? ' ms' : 'ms');
        if (abs < MIN) return fmt(abs / SEC, pfx, 'second', long);
        if (abs < HOUR) return fmt(abs / MIN, pfx, 'minute', long);
        if (abs < DAY) return fmt(abs / HOUR, pfx, 'hour', long);
        if (abs < YEAR) return fmt(abs / DAY, pfx, 'day', long);
        return fmt(abs / YEAR, pfx, 'year', long);
      }

      exports.format = format;
      exports.parse = parse;

      /***/
    },

    /***/ 4484: /***/ (module) => {
      'use strict';

      module.exports = balanced;
      function balanced(a, b, str) {
        if (a instanceof RegExp) a = maybeMatch(a, str);
        if (b instanceof RegExp) b = maybeMatch(b, str);

        var r = range(a, b, str);

        return (
          r && {
            start: r[0],
            end: r[1],
            pre: str.slice(0, r[0]),
            body: str.slice(r[0] + a.length, r[1]),
            post: str.slice(r[1] + b.length),
          }
        );
      }

      function maybeMatch(reg, str) {
        var m = str.match(reg);
        return m ? m[0] : null;
      }

      balanced.range = range;
      function range(a, b, str) {
        var begs, beg, left, right, result;
        var ai = str.indexOf(a);
        var bi = str.indexOf(b, ai + 1);
        var i = ai;

        if (ai >= 0 && bi > 0) {
          if (a === b) {
            return [ai, bi];
          }
          begs = [];
          left = str.length;

          while (i >= 0 && !result) {
            if (i == ai) {
              begs.push(i);
              ai = str.indexOf(a, i + 1);
            } else if (begs.length == 1) {
              result = [begs.pop(), bi];
            } else {
              beg = begs.pop();
              if (beg < left) {
                left = beg;
                right = bi;
              }

              bi = str.indexOf(b, i + 1);
            }

            i = ai < bi && ai >= 0 ? ai : bi;
          }

          if (begs.length) {
            result = [left, right];
          }
        }

        return result;
      }

      /***/
    },

    /***/ 1716: /***/ (
      module,
      __unused_webpack_exports,
      __webpack_require__,
    ) => {
      var balanced = __webpack_require__(4484);

      module.exports = expandTop;

      var escSlash = '\0SLASH' + Math.random() + '\0';
      var escOpen = '\0OPEN' + Math.random() + '\0';
      var escClose = '\0CLOSE' + Math.random() + '\0';
      var escComma = '\0COMMA' + Math.random() + '\0';
      var escPeriod = '\0PERIOD' + Math.random() + '\0';

      function numeric(str) {
        return parseInt(str, 10) == str ? parseInt(str, 10) : str.charCodeAt(0);
      }

      function escapeBraces(str) {
        return str
          .split('\\\\')
          .join(escSlash)
          .split('\\{')
          .join(escOpen)
          .split('\\}')
          .join(escClose)
          .split('\\,')
          .join(escComma)
          .split('\\.')
          .join(escPeriod);
      }

      function unescapeBraces(str) {
        return str
          .split(escSlash)
          .join('\\')
          .split(escOpen)
          .join('{')
          .split(escClose)
          .join('}')
          .split(escComma)
          .join(',')
          .split(escPeriod)
          .join('.');
      }

      // Basically just str.split(","), but handling cases
      // where we have nested braced sections, which should be
      // treated as individual members, like {a,{b,c},d}
      function parseCommaParts(str) {
        if (!str) return [''];

        var parts = [];
        var m = balanced('{', '}', str);

        if (!m) return str.split(',');

        var pre = m.pre;
        var body = m.body;
        var post = m.post;
        var p = pre.split(',');

        p[p.length - 1] += '{' + body + '}';
        var postParts = parseCommaParts(post);
        if (post.length) {
          p[p.length - 1] += postParts.shift();
          p.push.apply(p, postParts);
        }

        parts.push.apply(parts, p);

        return parts;
      }

      function expandTop(str) {
        if (!str) return [];

        // I don't know why Bash 4.3 does this, but it does.
        // Anything starting with {} will have the first two bytes preserved
        // but *only* at the top level, so {},a}b will not expand to anything,
        // but a{},b}c will be expanded to [a}c,abc].
        // One could argue that this is a bug in Bash, but since the goal of
        // this module is to match Bash's rules, we escape a leading {}
        if (str.substr(0, 2) === '{}') {
          str = '\\{\\}' + str.substr(2);
        }

        return expand(escapeBraces(str), true).map(unescapeBraces);
      }

      function embrace(str) {
        return '{' + str + '}';
      }
      function isPadded(el) {
        return /^-?0\d/.test(el);
      }

      function lte(i, y) {
        return i <= y;
      }
      function gte(i, y) {
        return i >= y;
      }

      function expand(str, isTop) {
        var expansions = [];

        var m = balanced('{', '}', str);
        if (!m) return [str];

        // no need to expand pre, since it is guaranteed to be free of brace-sets
        var pre = m.pre;
        var post = m.post.length ? expand(m.post, false) : [''];

        if (/\$$/.test(m.pre)) {
          for (var k = 0; k < post.length; k++) {
            var expansion = pre + '{' + m.body + '}' + post[k];
            expansions.push(expansion);
          }
        } else {
          var isNumericSequence = /^-?\d+\.\.-?\d+(?:\.\.-?\d+)?$/.test(m.body);
          var isAlphaSequence = /^[a-zA-Z]\.\.[a-zA-Z](?:\.\.-?\d+)?$/.test(
            m.body,
          );
          var isSequence = isNumericSequence || isAlphaSequence;
          var isOptions = m.body.indexOf(',') >= 0;
          if (!isSequence && !isOptions) {
            // {a},b}
            if (m.post.match(/,.*\}/)) {
              str = m.pre + '{' + m.body + escClose + m.post;
              return expand(str);
            }
            return [str];
          }

          var n;
          if (isSequence) {
            n = m.body.split(/\.\./);
          } else {
            n = parseCommaParts(m.body);
            if (n.length === 1) {
              // x{{a,b}}y ==> x{a}y x{b}y
              n = expand(n[0], false).map(embrace);
              if (n.length === 1) {
                return post.map(function (p) {
                  return m.pre + n[0] + p;
                });
              }
            }
          }

          // at this point, n is the parts, and we know it's not a comma set
          // with a single entry.
          var N;

          if (isSequence) {
            var x = numeric(n[0]);
            var y = numeric(n[1]);
            var width = Math.max(n[0].length, n[1].length);
            var incr = n.length == 3 ? Math.abs(numeric(n[2])) : 1;
            var test = lte;
            var reverse = y < x;
            if (reverse) {
              incr *= -1;
              test = gte;
            }
            var pad = n.some(isPadded);

            N = [];

            for (var i = x; test(i, y); i += incr) {
              var c;
              if (isAlphaSequence) {
                c = String.fromCharCode(i);
                if (c === '\\') c = '';
              } else {
                c = String(i);
                if (pad) {
                  var need = width - c.length;
                  if (need > 0) {
                    var z = new Array(need + 1).join('0');
                    if (i < 0) c = '-' + z + c.slice(1);
                    else c = z + c;
                  }
                }
              }
              N.push(c);
            }
          } else {
            N = [];

            for (var j = 0; j < n.length; j++) {
              N.push.apply(N, expand(n[j], false));
            }
          }

          for (var j = 0; j < N.length; j++) {
            for (var k = 0; k < post.length; k++) {
              var expansion = pre + N[j] + post[k];
              if (!isTop || isSequence || expansion) expansions.push(expansion);
            }
          }
        }

        return expansions;
      }

      /***/
    },

    /***/ 3570: /***/ (
      module,
      __unused_webpack_exports,
      __webpack_require__,
    ) => {
      'use strict';
      /*!
       * content-disposition
       * Copyright(c) 2014-2017 Douglas Christopher Wilson
       * MIT Licensed
       */

      /**
       * Module exports.
       * @public
       */

      module.exports = contentDisposition;
      module.exports.parse = parse;

      /**
       * Module dependencies.
       * @private
       */

      var basename = __webpack_require__(6928).basename;
      var Buffer = __webpack_require__(6671).Buffer;

      /**
       * RegExp to match non attr-char, *after* encodeURIComponent (i.e. not including "%")
       * @private
       */

      var ENCODE_URL_ATTR_CHAR_REGEXP = /[\x00-\x20"'()*,/:;<=>?@[\\\]{}\x7f]/g; // eslint-disable-line no-control-regex

      /**
       * RegExp to match percent encoding escape.
       * @private
       */

      var HEX_ESCAPE_REGEXP = /%[0-9A-Fa-f]{2}/;
      var HEX_ESCAPE_REPLACE_REGEXP = /%([0-9A-Fa-f]{2})/g;

      /**
       * RegExp to match non-latin1 characters.
       * @private
       */

      var NON_LATIN1_REGEXP = /[^\x20-\x7e\xa0-\xff]/g;

      /**
       * RegExp to match quoted-pair in RFC 2616
       *
       * quoted-pair = "\" CHAR
       * CHAR        = <any US-ASCII character (octets 0 - 127)>
       * @private
       */

      var QESC_REGEXP = /\\([\u0000-\u007f])/g; // eslint-disable-line no-control-regex

      /**
       * RegExp to match chars that must be quoted-pair in RFC 2616
       * @private
       */

      var QUOTE_REGEXP = /([\\"])/g;

      /**
       * RegExp for various RFC 2616 grammar
       *
       * parameter     = token "=" ( token | quoted-string )
       * token         = 1*<any CHAR except CTLs or separators>
       * separators    = "(" | ")" | "<" | ">" | "@"
       *               | "," | ";" | ":" | "\" | <">
       *               | "/" | "[" | "]" | "?" | "="
       *               | "{" | "}" | SP | HT
       * quoted-string = ( <"> *(qdtext | quoted-pair ) <"> )
       * qdtext        = <any TEXT except <">>
       * quoted-pair   = "\" CHAR
       * CHAR          = <any US-ASCII character (octets 0 - 127)>
       * TEXT          = <any OCTET except CTLs, but including LWS>
       * LWS           = [CRLF] 1*( SP | HT )
       * CRLF          = CR LF
       * CR            = <US-ASCII CR, carriage return (13)>
       * LF            = <US-ASCII LF, linefeed (10)>
       * SP            = <US-ASCII SP, space (32)>
       * HT            = <US-ASCII HT, horizontal-tab (9)>
       * CTL           = <any US-ASCII control character (octets 0 - 31) and DEL (127)>
       * OCTET         = <any 8-bit sequence of data>
       * @private
       */

      var PARAM_REGEXP =
        /;[\x09\x20]*([!#$%&'*+.0-9A-Z^_`a-z|~-]+)[\x09\x20]*=[\x09\x20]*("(?:[\x20!\x23-\x5b\x5d-\x7e\x80-\xff]|\\[\x20-\x7e])*"|[!#$%&'*+.0-9A-Z^_`a-z|~-]+)[\x09\x20]*/g; // eslint-disable-line no-control-regex
      var TEXT_REGEXP = /^[\x20-\x7e\x80-\xff]+$/;
      var TOKEN_REGEXP = /^[!#$%&'*+.0-9A-Z^_`a-z|~-]+$/;

      /**
       * RegExp for various RFC 5987 grammar
       *
       * ext-value     = charset  "'" [ language ] "'" value-chars
       * charset       = "UTF-8" / "ISO-8859-1" / mime-charset
       * mime-charset  = 1*mime-charsetc
       * mime-charsetc = ALPHA / DIGIT
       *               / "!" / "#" / "$" / "%" / "&"
       *               / "+" / "-" / "^" / "_" / "`"
       *               / "{" / "}" / "~"
       * language      = ( 2*3ALPHA [ extlang ] )
       *               / 4ALPHA
       *               / 5*8ALPHA
       * extlang       = *3( "-" 3ALPHA )
       * value-chars   = *( pct-encoded / attr-char )
       * pct-encoded   = "%" HEXDIG HEXDIG
       * attr-char     = ALPHA / DIGIT
       *               / "!" / "#" / "$" / "&" / "+" / "-" / "."
       *               / "^" / "_" / "`" / "|" / "~"
       * @private
       */

      var EXT_VALUE_REGEXP =
        /^([A-Za-z0-9!#$%&+\-^_`{}~]+)'(?:[A-Za-z]{2,3}(?:-[A-Za-z]{3}){0,3}|[A-Za-z]{4,8}|)'((?:%[0-9A-Fa-f]{2}|[A-Za-z0-9!#$&+.^_`|~-])+)$/;

      /**
       * RegExp for various RFC 6266 grammar
       *
       * disposition-type = "inline" | "attachment" | disp-ext-type
       * disp-ext-type    = token
       * disposition-parm = filename-parm | disp-ext-parm
       * filename-parm    = "filename" "=" value
       *                  | "filename*" "=" ext-value
       * disp-ext-parm    = token "=" value
       *                  | ext-token "=" ext-value
       * ext-token        = <the characters in token, followed by "*">
       * @private
       */

      var DISPOSITION_TYPE_REGEXP =
        /^([!#$%&'*+.0-9A-Z^_`a-z|~-]+)[\x09\x20]*(?:$|;)/; // eslint-disable-line no-control-regex

      /**
       * Create an attachment Content-Disposition header.
       *
       * @param {string} [filename]
       * @param {object} [options]
       * @param {string} [options.type=attachment]
       * @param {string|boolean} [options.fallback=true]
       * @return {string}
       * @public
       */

      function contentDisposition(filename, options) {
        var opts = options || {};

        // get type
        var type = opts.type || 'attachment';

        // get parameters
        var params = createparams(filename, opts.fallback);

        // format into string
        return format(new ContentDisposition(type, params));
      }

      /**
       * Create parameters object from filename and fallback.
       *
       * @param {string} [filename]
       * @param {string|boolean} [fallback=true]
       * @return {object}
       * @private
       */

      function createparams(filename, fallback) {
        if (filename === undefined) {
          return;
        }

        var params = {};

        if (typeof filename !== 'string') {
          throw new TypeError('filename must be a string');
        }

        // fallback defaults to true
        if (fallback === undefined) {
          fallback = true;
        }

        if (typeof fallback !== 'string' && typeof fallback !== 'boolean') {
          throw new TypeError('fallback must be a string or boolean');
        }

        if (typeof fallback === 'string' && NON_LATIN1_REGEXP.test(fallback)) {
          throw new TypeError('fallback must be ISO-8859-1 string');
        }

        // restrict to file base name
        var name = basename(filename);

        // determine if name is suitable for quoted string
        var isQuotedString = TEXT_REGEXP.test(name);

        // generate fallback name
        var fallbackName =
          typeof fallback !== 'string'
            ? fallback && getlatin1(name)
            : basename(fallback);
        var hasFallback =
          typeof fallbackName === 'string' && fallbackName !== name;

        // set extended filename parameter
        if (hasFallback || !isQuotedString || HEX_ESCAPE_REGEXP.test(name)) {
          params['filename*'] = name;
        }

        // set filename parameter
        if (isQuotedString || hasFallback) {
          params.filename = hasFallback ? fallbackName : name;
        }

        return params;
      }

      /**
       * Format object to Content-Disposition header.
       *
       * @param {object} obj
       * @param {string} obj.type
       * @param {object} [obj.parameters]
       * @return {string}
       * @private
       */

      function format(obj) {
        var parameters = obj.parameters;
        var type = obj.type;

        if (!type || typeof type !== 'string' || !TOKEN_REGEXP.test(type)) {
          throw new TypeError('invalid type');
        }

        // start with normalized type
        var string = String(type).toLowerCase();

        // append parameters
        if (parameters && typeof parameters === 'object') {
          var param;
          var params = Object.keys(parameters).sort();

          for (var i = 0; i < params.length; i++) {
            param = params[i];

            var val =
              param.substr(-1) === '*'
                ? ustring(parameters[param])
                : qstring(parameters[param]);

            string += '; ' + param + '=' + val;
          }
        }

        return string;
      }

      /**
       * Decode a RFC 5987 field value (gracefully).
       *
       * @param {string} str
       * @return {string}
       * @private
       */

      function decodefield(str) {
        var match = EXT_VALUE_REGEXP.exec(str);

        if (!match) {
          throw new TypeError('invalid extended field value');
        }

        var charset = match[1].toLowerCase();
        var encoded = match[2];
        var value;

        // to binary string
        var binary = encoded.replace(HEX_ESCAPE_REPLACE_REGEXP, pdecode);

        switch (charset) {
          case 'iso-8859-1':
            value = getlatin1(binary);
            break;
          case 'utf-8':
            value = Buffer.from(binary, 'binary').toString('utf8');
            break;
          default:
            throw new TypeError('unsupported charset in extended field');
        }

        return value;
      }

      /**
       * Get ISO-8859-1 version of string.
       *
       * @param {string} val
       * @return {string}
       * @private
       */

      function getlatin1(val) {
        // simple Unicode -> ISO-8859-1 transformation
        return String(val).replace(NON_LATIN1_REGEXP, '?');
      }

      /**
       * Parse Content-Disposition header string.
       *
       * @param {string} string
       * @return {object}
       * @public
       */

      function parse(string) {
        if (!string || typeof string !== 'string') {
          throw new TypeError('argument string is required');
        }

        var match = DISPOSITION_TYPE_REGEXP.exec(string);

        if (!match) {
          throw new TypeError('invalid type format');
        }

        // normalize type
        var index = match[0].length;
        var type = match[1].toLowerCase();

        var key;
        var names = [];
        var params = {};
        var value;

        // calculate index to start at
        index = PARAM_REGEXP.lastIndex =
          match[0].substr(-1) === ';' ? index - 1 : index;

        // match parameters
        while ((match = PARAM_REGEXP.exec(string))) {
          if (match.index !== index) {
            throw new TypeError('invalid parameter format');
          }

          index += match[0].length;
          key = match[1].toLowerCase();
          value = match[2];

          if (names.indexOf(key) !== -1) {
            throw new TypeError('invalid duplicate parameter');
          }

          names.push(key);

          if (key.indexOf('*') + 1 === key.length) {
            // decode extended value
            key = key.slice(0, -1);
            value = decodefield(value);

            // overwrite existing value
            params[key] = value;
            continue;
          }

          if (typeof params[key] === 'string') {
            continue;
          }

          if (value[0] === '"') {
            // remove quotes and escapes
            value = value
              .substr(1, value.length - 2)
              .replace(QESC_REGEXP, '$1');
          }

          params[key] = value;
        }

        if (index !== -1 && index !== string.length) {
          throw new TypeError('invalid parameter format');
        }

        return new ContentDisposition(type, params);
      }

      /**
       * Percent decode a single character.
       *
       * @param {string} str
       * @param {string} hex
       * @return {string}
       * @private
       */

      function pdecode(str, hex) {
        return String.fromCharCode(parseInt(hex, 16));
      }

      /**
       * Percent encode a single character.
       *
       * @param {string} char
       * @return {string}
       * @private
       */

      function pencode(char) {
        return '%' + String(char).charCodeAt(0).toString(16).toUpperCase();
      }

      /**
       * Quote a string for HTTP.
       *
       * @param {string} val
       * @return {string}
       * @private
       */

      function qstring(val) {
        var str = String(val);

        return '"' + str.replace(QUOTE_REGEXP, '\\$1') + '"';
      }

      /**
       * Encode a Unicode string for HTTP (RFC 5987).
       *
       * @param {string} val
       * @return {string}
       * @private
       */

      function ustring(val) {
        var str = String(val);

        // percent encode as UTF-8
        var encoded = encodeURIComponent(str).replace(
          ENCODE_URL_ATTR_CHAR_REGEXP,
          pencode,
        );

        return "UTF-8''" + encoded;
      }

      /**
       * Class for parsed Content-Disposition header for v8 optimization
       *
       * @public
       * @param {string} type
       * @param {object} parameters
       * @constructor
       */

      function ContentDisposition(type, parameters) {
        this.type = type;
        this.parameters = parameters;
      }

      /***/
    },

    /***/ 1295: /***/ (
      module,
      __unused_webpack_exports,
      __webpack_require__,
    ) => {
      /*!
       * depd
       * Copyright(c) 2014-2018 Douglas Christopher Wilson
       * MIT Licensed
       */

      /**
       * Module dependencies.
       */

      var relative = __webpack_require__(6928).relative;

      /**
       * Module exports.
       */

      module.exports = depd;

      /**
       * Get the path to base files on.
       */

      var basePath = process.cwd();

      /**
       * Determine if namespace is contained in the string.
       */

      function containsNamespace(str, namespace) {
        var vals = str.split(/[ ,]+/);
        var ns = String(namespace).toLowerCase();

        for (var i = 0; i < vals.length; i++) {
          var val = vals[i];

          // namespace contained
          if (val && (val === '*' || val.toLowerCase() === ns)) {
            return true;
          }
        }

        return false;
      }

      /**
       * Convert a data descriptor to accessor descriptor.
       */

      function convertDataDescriptorToAccessor(obj, prop, message) {
        var descriptor = Object.getOwnPropertyDescriptor(obj, prop);
        var value = descriptor.value;

        descriptor.get = function getter() {
          return value;
        };

        if (descriptor.writable) {
          descriptor.set = function setter(val) {
            return (value = val);
          };
        }

        delete descriptor.value;
        delete descriptor.writable;

        Object.defineProperty(obj, prop, descriptor);

        return descriptor;
      }

      /**
       * Create arguments string to keep arity.
       */

      function createArgumentsString(arity) {
        var str = '';

        for (var i = 0; i < arity; i++) {
          str += ', arg' + i;
        }

        return str.substr(2);
      }

      /**
       * Create stack string from stack.
       */

      function createStackString(stack) {
        var str = this.name + ': ' + this.namespace;

        if (this.message) {
          str += ' deprecated ' + this.message;
        }

        for (var i = 0; i < stack.length; i++) {
          str += '\n    at ' + stack[i].toString();
        }

        return str;
      }

      /**
       * Create deprecate for namespace in caller.
       */

      function depd(namespace) {
        if (!namespace) {
          throw new TypeError('argument namespace is required');
        }

        var stack = getStack();
        var site = callSiteLocation(stack[1]);
        var file = site[0];

        function deprecate(message) {
          // call to self as log
          log.call(deprecate, message);
        }

        deprecate._file = file;
        deprecate._ignored = isignored(namespace);
        deprecate._namespace = namespace;
        deprecate._traced = istraced(namespace);
        deprecate._warned = Object.create(null);

        deprecate.function = wrapfunction;
        deprecate.property = wrapproperty;

        return deprecate;
      }

      /**
       * Determine if event emitter has listeners of a given type.
       *
       * The way to do this check is done three different ways in Node.js >= 0.8
       * so this consolidates them into a minimal set using instance methods.
       *
       * @param {EventEmitter} emitter
       * @param {string} type
       * @returns {boolean}
       * @private
       */

      function eehaslisteners(emitter, type) {
        var count =
          typeof emitter.listenerCount !== 'function'
            ? emitter.listeners(type).length
            : emitter.listenerCount(type);

        return count > 0;
      }

      /**
       * Determine if namespace is ignored.
       */

      function isignored(namespace) {
        if (process.noDeprecation) {
          // --no-deprecation support
          return true;
        }

        var str = process.env.NO_DEPRECATION || '';

        // namespace ignored
        return containsNamespace(str, namespace);
      }

      /**
       * Determine if namespace is traced.
       */

      function istraced(namespace) {
        if (process.traceDeprecation) {
          // --trace-deprecation support
          return true;
        }

        var str = process.env.TRACE_DEPRECATION || '';

        // namespace traced
        return containsNamespace(str, namespace);
      }

      /**
       * Display deprecation message.
       */

      function log(message, site) {
        var haslisteners = eehaslisteners(process, 'deprecation');

        // abort early if no destination
        if (!haslisteners && this._ignored) {
          return;
        }

        var caller;
        var callFile;
        var callSite;
        var depSite;
        var i = 0;
        var seen = false;
        var stack = getStack();
        var file = this._file;

        if (site) {
          // provided site
          depSite = site;
          callSite = callSiteLocation(stack[1]);
          callSite.name = depSite.name;
          file = callSite[0];
        } else {
          // get call site
          i = 2;
          depSite = callSiteLocation(stack[i]);
          callSite = depSite;
        }

        // get caller of deprecated thing in relation to file
        for (; i < stack.length; i++) {
          caller = callSiteLocation(stack[i]);
          callFile = caller[0];

          if (callFile === file) {
            seen = true;
          } else if (callFile === this._file) {
            file = this._file;
          } else if (seen) {
            break;
          }
        }

        var key = caller
          ? depSite.join(':') + '__' + caller.join(':')
          : undefined;

        if (key !== undefined && key in this._warned) {
          // already warned
          return;
        }

        this._warned[key] = true;

        // generate automatic message from call site
        var msg = message;
        if (!msg) {
          msg =
            callSite === depSite || !callSite.name
              ? defaultMessage(depSite)
              : defaultMessage(callSite);
        }

        // emit deprecation if listeners exist
        if (haslisteners) {
          var err = DeprecationError(this._namespace, msg, stack.slice(i));
          process.emit('deprecation', err);
          return;
        }

        // format and write message
        var format = process.stderr.isTTY ? formatColor : formatPlain;
        var output = format.call(this, msg, caller, stack.slice(i));
        process.stderr.write(output + '\n', 'utf8');
      }

      /**
       * Get call site location as array.
       */

      function callSiteLocation(callSite) {
        var file = callSite.getFileName() || '<anonymous>';
        var line = callSite.getLineNumber();
        var colm = callSite.getColumnNumber();

        if (callSite.isEval()) {
          file = callSite.getEvalOrigin() + ', ' + file;
        }

        var site = [file, line, colm];

        site.callSite = callSite;
        site.name = callSite.getFunctionName();

        return site;
      }

      /**
       * Generate a default message from the site.
       */

      function defaultMessage(site) {
        var callSite = site.callSite;
        var funcName = site.name;

        // make useful anonymous name
        if (!funcName) {
          funcName = '<anonymous@' + formatLocation(site) + '>';
        }

        var context = callSite.getThis();
        var typeName = context && callSite.getTypeName();

        // ignore useless type name
        if (typeName === 'Object') {
          typeName = undefined;
        }

        // make useful type name
        if (typeName === 'Function') {
          typeName = context.name || typeName;
        }

        return typeName && callSite.getMethodName()
          ? typeName + '.' + funcName
          : funcName;
      }

      /**
       * Format deprecation message without color.
       */

      function formatPlain(msg, caller, stack) {
        var timestamp = new Date().toUTCString();

        var formatted =
          timestamp + ' ' + this._namespace + ' deprecated ' + msg;

        // add stack trace
        if (this._traced) {
          for (var i = 0; i < stack.length; i++) {
            formatted += '\n    at ' + stack[i].toString();
          }

          return formatted;
        }

        if (caller) {
          formatted += ' at ' + formatLocation(caller);
        }

        return formatted;
      }

      /**
       * Format deprecation message with color.
       */

      function formatColor(msg, caller, stack) {
        var formatted =
          '\x1b[36;1m' +
          this._namespace +
          '\x1b[22;39m' + // bold cyan
          ' \x1b[33;1mdeprecated\x1b[22;39m' + // bold yellow
          ' \x1b[0m' +
          msg +
          '\x1b[39m'; // reset

        // add stack trace
        if (this._traced) {
          for (var i = 0; i < stack.length; i++) {
            formatted += '\n    \x1b[36mat ' + stack[i].toString() + '\x1b[39m'; // cyan
          }

          return formatted;
        }

        if (caller) {
          formatted += ' \x1b[36m' + formatLocation(caller) + '\x1b[39m'; // cyan
        }

        return formatted;
      }

      /**
       * Format call site location.
       */

      function formatLocation(callSite) {
        return (
          relative(basePath, callSite[0]) +
          ':' +
          callSite[1] +
          ':' +
          callSite[2]
        );
      }

      /**
       * Get the stack as array of call sites.
       */

      function getStack() {
        var limit = Error.stackTraceLimit;
        var obj = {};
        var prep = Error.prepareStackTrace;

        Error.prepareStackTrace = prepareObjectStackTrace;
        Error.stackTraceLimit = Math.max(10, limit);

        // capture the stack
        Error.captureStackTrace(obj);

        // slice this function off the top
        var stack = obj.stack.slice(1);

        Error.prepareStackTrace = prep;
        Error.stackTraceLimit = limit;

        return stack;
      }

      /**
       * Capture call site stack from v8.
       */

      function prepareObjectStackTrace(obj, stack) {
        return stack;
      }

      /**
       * Return a wrapped function in a deprecation message.
       */

      function wrapfunction(fn, message) {
        if (typeof fn !== 'function') {
          throw new TypeError('argument fn must be a function');
        }

        var args = createArgumentsString(fn.length);
        var stack = getStack();
        var site = callSiteLocation(stack[1]);

        site.name = fn.name;

        // eslint-disable-next-line no-new-func
        var deprecatedfn = new Function(
          'fn',
          'log',
          'deprecate',
          'message',
          'site',
          '"use strict"\n' +
            'return function (' +
            args +
            ') {' +
            'log.call(deprecate, message, site)\n' +
            'return fn.apply(this, arguments)\n' +
            '}',
        )(fn, log, this, message, site);

        return deprecatedfn;
      }

      /**
       * Wrap property in a deprecation message.
       */

      function wrapproperty(obj, prop, message) {
        if (!obj || (typeof obj !== 'object' && typeof obj !== 'function')) {
          throw new TypeError('argument obj must be object');
        }

        var descriptor = Object.getOwnPropertyDescriptor(obj, prop);

        if (!descriptor) {
          throw new TypeError('must call property on owner object');
        }

        if (!descriptor.configurable) {
          throw new TypeError('property must be configurable');
        }

        var deprecate = this;
        var stack = getStack();
        var site = callSiteLocation(stack[1]);

        // set site name
        site.name = prop;

        // convert data descriptor
        if ('value' in descriptor) {
          descriptor = convertDataDescriptorToAccessor(obj, prop, message);
        }

        var get = descriptor.get;
        var set = descriptor.set;

        // wrap getter
        if (typeof get === 'function') {
          descriptor.get = function getter() {
            log.call(deprecate, message, site);
            return get.apply(this, arguments);
          };
        }

        // wrap setter
        if (typeof set === 'function') {
          descriptor.set = function setter() {
            log.call(deprecate, message, site);
            return set.apply(this, arguments);
          };
        }

        Object.defineProperty(obj, prop, descriptor);
      }

      /**
       * Create DeprecationError for deprecation
       */

      function DeprecationError(namespace, message, stack) {
        var error = new Error();
        var stackString;

        Object.defineProperty(error, 'constructor', {
          value: DeprecationError,
        });

        Object.defineProperty(error, 'message', {
          configurable: true,
          enumerable: false,
          value: message,
          writable: true,
        });

        Object.defineProperty(error, 'name', {
          enumerable: false,
          configurable: true,
          value: 'DeprecationError',
          writable: true,
        });

        Object.defineProperty(error, 'namespace', {
          configurable: true,
          enumerable: false,
          value: namespace,
          writable: true,
        });

        Object.defineProperty(error, 'stack', {
          configurable: true,
          enumerable: false,
          get: function () {
            if (stackString !== undefined) {
              return stackString;
            }

            // prepare stack trace
            return (stackString = createStackString.call(this, stack));
          },
          set: function setter(val) {
            stackString = val;
          },
        });

        return error;
      }

      /***/
    },

    /***/ 6725: /***/ (module) => {
      'use strict';
      /*!
       * escape-html
       * Copyright(c) 2012-2013 TJ Holowaychuk
       * Copyright(c) 2015 Andreas Lubbe
       * Copyright(c) 2015 Tiancheng "Timothy" Gu
       * MIT Licensed
       */

      /**
       * Module variables.
       * @private
       */

      var matchHtmlRegExp = /["'&<>]/;

      /**
       * Module exports.
       * @public
       */

      module.exports = escapeHtml;

      /**
       * Escape special characters in the given string of html.
       *
       * @param  {string} string The string to escape for inserting into HTML
       * @return {string}
       * @public
       */

      function escapeHtml(string) {
        var str = '' + string;
        var match = matchHtmlRegExp.exec(str);

        if (!match) {
          return str;
        }

        var escape;
        var html = '';
        var index = 0;
        var lastIndex = 0;

        for (index = match.index; index < str.length; index++) {
          switch (str.charCodeAt(index)) {
            case 34: // "
              escape = '&quot;';
              break;
            case 38: // &
              escape = '&amp;';
              break;
            case 39: // '
              escape = '&#39;';
              break;
            case 60: // <
              escape = '&lt;';
              break;
            case 62: // >
              escape = '&gt;';
              break;
            default:
              continue;
          }

          if (lastIndex !== index) {
            html += str.substring(lastIndex, index);
          }

          lastIndex = index + 1;
          html += escape;
        }

        return lastIndex !== index
          ? html + str.substring(lastIndex, index)
          : html;
      }

      /***/
    },

    /***/ 8493: /***/ (module) => {
      'use strict';

      var UTF8_ACCEPT = 12;
      var UTF8_REJECT = 0;
      var UTF8_DATA = [
        // The first part of the table maps bytes to character to a transition.
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3, 3, 3,
        3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
        4, 4, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
        5, 5, 5, 5, 5, 5, 5, 5, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 8, 7, 7,
        10, 9, 9, 9, 11, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,

        // The second part of the table maps a state to a new state when adding a
        // transition.
        0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 12, 0, 0, 0, 0, 24, 36, 48, 60, 72, 84,
        96, 0, 12, 12, 12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 24, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 24, 24, 24, 0, 0, 0, 0, 0, 0, 0, 0, 0, 24, 24, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 48, 48, 48, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 48, 48, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 48, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,

        // The third part maps the current transition to a mask that needs to apply
        // to the byte.
        0x7f,
        0x3f, 0x3f, 0x3f, 0x00, 0x1f, 0x0f, 0x0f, 0x0f, 0x07, 0x07, 0x07,
      ];

      function decodeURIComponent(uri) {
        var percentPosition = uri.indexOf('%');
        if (percentPosition === -1) return uri;

        var length = uri.length;
        var decoded = '';
        var last = 0;
        var codepoint = 0;
        var startOfOctets = percentPosition;
        var state = UTF8_ACCEPT;

        while (percentPosition > -1 && percentPosition < length) {
          var high = hexCodeToInt(uri[percentPosition + 1], 4);
          var low = hexCodeToInt(uri[percentPosition + 2], 0);
          var byte = high | low;
          var type = UTF8_DATA[byte];
          state = UTF8_DATA[256 + state + type];
          codepoint = (codepoint << 6) | (byte & UTF8_DATA[364 + type]);

          if (state === UTF8_ACCEPT) {
            decoded += uri.slice(last, startOfOctets);

            decoded +=
              codepoint <= 0xffff
                ? String.fromCharCode(codepoint)
                : String.fromCharCode(
                    0xd7c0 + (codepoint >> 10),
                    0xdc00 + (codepoint & 0x3ff),
                  );

            codepoint = 0;
            last = percentPosition + 3;
            percentPosition = startOfOctets = uri.indexOf('%', last);
          } else if (state === UTF8_REJECT) {
            return null;
          } else {
            percentPosition += 3;
            if (
              percentPosition < length &&
              uri.charCodeAt(percentPosition) === 37
            )
              continue;
            return null;
          }
        }

        return decoded + uri.slice(last);
      }

      var HEX = {
        0: 0,
        1: 1,
        2: 2,
        3: 3,
        4: 4,
        5: 5,
        6: 6,
        7: 7,
        8: 8,
        9: 9,
        a: 10,
        A: 10,
        b: 11,
        B: 11,
        c: 12,
        C: 12,
        d: 13,
        D: 13,
        e: 14,
        E: 14,
        f: 15,
        F: 15,
      };

      function hexCodeToInt(c, shift) {
        var i = HEX[c];
        return i === undefined ? 255 : i << shift;
      }

      module.exports = decodeURIComponent;

      /***/
    },

    /***/ 877: /***/ (module) => {
      'use strict';

      const fpStackTracePattern = /at\s{1}(?:.*\.)?plugin\s{1}.*\n\s*(.*)/;
      const fileNamePattern = /(\w*(\.\w*)*)\..*/;

      module.exports = function getPluginName(fn) {
        if (fn.name.length > 0) return fn.name;

        const stackTraceLimit = Error.stackTraceLimit;
        Error.stackTraceLimit = 10;
        try {
          throw new Error('anonymous function');
        } catch (e) {
          Error.stackTraceLimit = stackTraceLimit;
          return extractPluginName(e.stack);
        }
      };

      function extractPluginName(stack) {
        const m = stack.match(fpStackTracePattern);

        // get last section of path and match for filename
        return m
          ? m[1].split(/[/\\]/).slice(-1)[0].match(fileNamePattern)[1]
          : 'anonymous';
      }
      module.exports.extractPluginName = extractPluginName;

      /***/
    },

    /***/ 1864: /***/ (module) => {
      'use strict';

      module.exports = function toCamelCase(name) {
        if (name[0] === '@') {
          name = name.slice(1).replace('/', '-');
        }
        const newName = name.replace(/-(.)/g, function (match, g1) {
          return g1.toUpperCase();
        });
        return newName;
      };

      /***/
    },

    /***/ 3462: /***/ (
      module,
      __unused_webpack_exports,
      __webpack_require__,
    ) => {
      'use strict';

      const getPluginName = __webpack_require__(877);
      const toCamelCase = __webpack_require__(1864);

      let count = 0;

      function plugin(fn, options = {}) {
        let autoName = false;

        if (typeof fn.default !== 'undefined') {
          // Support for 'export default' behaviour in transpiled ECMAScript module
          fn = fn.default;
        }

        if (typeof fn !== 'function') {
          throw new TypeError(
            `fastify-plugin expects a function, instead got a '${typeof fn}'`,
          );
        }

        if (typeof options === 'string') {
          options = {
            fastify: options,
          };
        }

        if (
          typeof options !== 'object' ||
          Array.isArray(options) ||
          options === null
        ) {
          throw new TypeError('The options object should be an object');
        }

        if (
          options.fastify !== undefined &&
          typeof options.fastify !== 'string'
        ) {
          throw new TypeError(
            `fastify-plugin expects a version string, instead got '${typeof options.fastify}'`,
          );
        }

        if (!options.name) {
          autoName = true;
          options.name = getPluginName(fn) + '-auto-' + count++;
        }

        fn[Symbol.for('skip-override')] = options.encapsulate !== true;
        fn[Symbol.for('fastify.display-name')] = options.name;
        fn[Symbol.for('plugin-meta')] = options;

        // Faux modules support
        if (!fn.default) {
          fn.default = fn;
        }

        // TypeScript support for named imports
        // See https://github.com/fastify/fastify/issues/2404 for more details
        // The type definitions would have to be update to match this.
        const camelCase = toCamelCase(options.name);
        if (!autoName && !fn[camelCase]) {
          fn[camelCase] = fn;
        }

        return fn;
      }

      module.exports = plugin;
      module.exports['default'] = plugin;
      module.exports.fastifyPlugin = plugin;

      /***/
    },

    /***/ 1086: /***/ (
      module,
      __unused_webpack_exports,
      __webpack_require__,
    ) => {
      'use strict';

      /* eslint-disable no-var */

      var reusify = __webpack_require__(9691);

      function fastqueue(context, worker, _concurrency) {
        if (typeof context === 'function') {
          _concurrency = worker;
          worker = context;
          context = null;
        }

        if (!(_concurrency >= 1)) {
          throw new Error(
            'fastqueue concurrency must be equal to or greater than 1',
          );
        }

        var cache = reusify(Task);
        var queueHead = null;
        var queueTail = null;
        var _running = 0;
        var errorHandler = null;

        var self = {
          push: push,
          drain: noop,
          saturated: noop,
          pause: pause,
          paused: false,

          get concurrency() {
            return _concurrency;
          },
          set concurrency(value) {
            if (!(value >= 1)) {
              throw new Error(
                'fastqueue concurrency must be equal to or greater than 1',
              );
            }
            _concurrency = value;

            if (self.paused) return;
            for (; queueHead && _running < _concurrency; ) {
              _running++;
              release();
            }
          },

          running: running,
          resume: resume,
          idle: idle,
          length: length,
          getQueue: getQueue,
          unshift: unshift,
          empty: noop,
          kill: kill,
          killAndDrain: killAndDrain,
          error: error,
        };

        return self;

        function running() {
          return _running;
        }

        function pause() {
          self.paused = true;
        }

        function length() {
          var current = queueHead;
          var counter = 0;

          while (current) {
            current = current.next;
            counter++;
          }

          return counter;
        }

        function getQueue() {
          var current = queueHead;
          var tasks = [];

          while (current) {
            tasks.push(current.value);
            current = current.next;
          }

          return tasks;
        }

        function resume() {
          if (!self.paused) return;
          self.paused = false;
          if (queueHead === null) {
            _running++;
            release();
            return;
          }
          for (; queueHead && _running < _concurrency; ) {
            _running++;
            release();
          }
        }

        function idle() {
          return _running === 0 && self.length() === 0;
        }

        function push(value, done) {
          var current = cache.get();

          current.context = context;
          current.release = release;
          current.value = value;
          current.callback = done || noop;
          current.errorHandler = errorHandler;

          if (_running >= _concurrency || self.paused) {
            if (queueTail) {
              queueTail.next = current;
              queueTail = current;
            } else {
              queueHead = current;
              queueTail = current;
              self.saturated();
            }
          } else {
            _running++;
            worker.call(context, current.value, current.worked);
          }
        }

        function unshift(value, done) {
          var current = cache.get();

          current.context = context;
          current.release = release;
          current.value = value;
          current.callback = done || noop;
          current.errorHandler = errorHandler;

          if (_running >= _concurrency || self.paused) {
            if (queueHead) {
              current.next = queueHead;
              queueHead = current;
            } else {
              queueHead = current;
              queueTail = current;
              self.saturated();
            }
          } else {
            _running++;
            worker.call(context, current.value, current.worked);
          }
        }

        function release(holder) {
          if (holder) {
            cache.release(holder);
          }
          var next = queueHead;
          if (next && _running <= _concurrency) {
            if (!self.paused) {
              if (queueTail === queueHead) {
                queueTail = null;
              }
              queueHead = next.next;
              next.next = null;
              worker.call(context, next.value, next.worked);
              if (queueTail === null) {
                self.empty();
              }
            } else {
              _running--;
            }
          } else if (--_running === 0) {
            self.drain();
          }
        }

        function kill() {
          queueHead = null;
          queueTail = null;
          self.drain = noop;
        }

        function killAndDrain() {
          queueHead = null;
          queueTail = null;
          self.drain();
          self.drain = noop;
        }

        function error(handler) {
          errorHandler = handler;
        }
      }

      function noop() {}

      function Task() {
        this.value = null;
        this.callback = noop;
        this.next = null;
        this.release = noop;
        this.context = null;
        this.errorHandler = null;

        var self = this;

        this.worked = function worked(err, result) {
          var callback = self.callback;
          var errorHandler = self.errorHandler;
          var val = self.value;
          self.value = null;
          self.callback = noop;
          if (self.errorHandler) {
            errorHandler(err, val);
          }
          callback.call(self.context, err, result);
          self.release(self);
        };
      }

      function queueAsPromised(context, worker, _concurrency) {
        if (typeof context === 'function') {
          _concurrency = worker;
          worker = context;
          context = null;
        }

        function asyncWrapper(arg, cb) {
          worker.call(this, arg).then(function (res) {
            cb(null, res);
          }, cb);
        }

        var queue = fastqueue(context, asyncWrapper, _concurrency);

        var pushCb = queue.push;
        var unshiftCb = queue.unshift;

        queue.push = push;
        queue.unshift = unshift;
        queue.drained = drained;

        return queue;

        function push(value) {
          var p = new Promise(function (resolve, reject) {
            pushCb(value, function (err, result) {
              if (err) {
                reject(err);
                return;
              }
              resolve(result);
            });
          });

          // Let's fork the promise chain to
          // make the error bubble up to the user but
          // not lead to a unhandledRejection
          p.catch(noop);

          return p;
        }

        function unshift(value) {
          var p = new Promise(function (resolve, reject) {
            unshiftCb(value, function (err, result) {
              if (err) {
                reject(err);
                return;
              }
              resolve(result);
            });
          });

          // Let's fork the promise chain to
          // make the error bubble up to the user but
          // not lead to a unhandledRejection
          p.catch(noop);

          return p;
        }

        function drained() {
          if (queue.idle()) {
            return new Promise(function (resolve) {
              resolve();
            });
          }

          var previousDrain = queue.drain;

          var p = new Promise(function (resolve) {
            queue.drain = function () {
              previousDrain();
              resolve();
            };
          });

          return p;
        }
      }

      module.exports = fastqueue;
      module.exports.promise = queueAsPromised;

      /***/
    },

    /***/ 1771: /***/ (
      module,
      __unused_webpack_exports,
      __webpack_require__,
    ) => {
      'use strict';
      /*!
       * http-errors
       * Copyright(c) 2014 Jonathan Ong
       * Copyright(c) 2016 Douglas Christopher Wilson
       * MIT Licensed
       */

      /**
       * Module dependencies.
       * @private
       */

      var deprecate = __webpack_require__(1295)('http-errors');
      var setPrototypeOf = __webpack_require__(4144);
      var statuses = __webpack_require__(9216);
      var inherits = __webpack_require__(7835);
      var toIdentifier = __webpack_require__(5237);

      /**
       * Module exports.
       * @public
       */

      module.exports = createError;
      module.exports.HttpError = createHttpErrorConstructor();
      module.exports.isHttpError = createIsHttpErrorFunction(
        module.exports.HttpError,
      );

      // Populate exports for all constructors
      populateConstructorExports(
        module.exports,
        statuses.codes,
        module.exports.HttpError,
      );

      /**
       * Get the code class of a status code.
       * @private
       */

      function codeClass(status) {
        return Number(String(status).charAt(0) + '00');
      }

      /**
       * Create a new HTTP Error.
       *
       * @returns {Error}
       * @public
       */

      function createError() {
        // so much arity going on ~_~
        var err;
        var msg;
        var status = 500;
        var props = {};
        for (var i = 0; i < arguments.length; i++) {
          var arg = arguments[i];
          var type = typeof arg;
          if (type === 'object' && arg instanceof Error) {
            err = arg;
            status = err.status || err.statusCode || status;
          } else if (type === 'number' && i === 0) {
            status = arg;
          } else if (type === 'string') {
            msg = arg;
          } else if (type === 'object') {
            props = arg;
          } else {
            throw new TypeError(
              'argument #' + (i + 1) + ' unsupported type ' + type,
            );
          }
        }

        if (typeof status === 'number' && (status < 400 || status >= 600)) {
          deprecate('non-error status code; use only 4xx or 5xx status codes');
        }

        if (
          typeof status !== 'number' ||
          (!statuses.message[status] && (status < 400 || status >= 600))
        ) {
          status = 500;
        }

        // constructor
        var HttpError = createError[status] || createError[codeClass(status)];

        if (!err) {
          // create error
          err = HttpError
            ? new HttpError(msg)
            : new Error(msg || statuses.message[status]);
          Error.captureStackTrace(err, createError);
        }

        if (
          !HttpError ||
          !(err instanceof HttpError) ||
          err.status !== status
        ) {
          // add properties to generic error
          err.expose = status < 500;
          err.status = err.statusCode = status;
        }

        for (var key in props) {
          if (key !== 'status' && key !== 'statusCode') {
            err[key] = props[key];
          }
        }

        return err;
      }

      /**
       * Create HTTP error abstract base class.
       * @private
       */

      function createHttpErrorConstructor() {
        function HttpError() {
          throw new TypeError('cannot construct abstract class');
        }

        inherits(HttpError, Error);

        return HttpError;
      }

      /**
       * Create a constructor for a client error.
       * @private
       */

      function createClientErrorConstructor(HttpError, name, code) {
        var className = toClassName(name);

        function ClientError(message) {
          // create the error object
          var msg = message != null ? message : statuses.message[code];
          var err = new Error(msg);

          // capture a stack trace to the construction point
          Error.captureStackTrace(err, ClientError);

          // adjust the [[Prototype]]
          setPrototypeOf(err, ClientError.prototype);

          // redefine the error message
          Object.defineProperty(err, 'message', {
            enumerable: true,
            configurable: true,
            value: msg,
            writable: true,
          });

          // redefine the error name
          Object.defineProperty(err, 'name', {
            enumerable: false,
            configurable: true,
            value: className,
            writable: true,
          });

          return err;
        }

        inherits(ClientError, HttpError);
        nameFunc(ClientError, className);

        ClientError.prototype.status = code;
        ClientError.prototype.statusCode = code;
        ClientError.prototype.expose = true;

        return ClientError;
      }

      /**
       * Create function to test is a value is a HttpError.
       * @private
       */

      function createIsHttpErrorFunction(HttpError) {
        return function isHttpError(val) {
          if (!val || typeof val !== 'object') {
            return false;
          }

          if (val instanceof HttpError) {
            return true;
          }

          return (
            val instanceof Error &&
            typeof val.expose === 'boolean' &&
            typeof val.statusCode === 'number' &&
            val.status === val.statusCode
          );
        };
      }

      /**
       * Create a constructor for a server error.
       * @private
       */

      function createServerErrorConstructor(HttpError, name, code) {
        var className = toClassName(name);

        function ServerError(message) {
          // create the error object
          var msg = message != null ? message : statuses.message[code];
          var err = new Error(msg);

          // capture a stack trace to the construction point
          Error.captureStackTrace(err, ServerError);

          // adjust the [[Prototype]]
          setPrototypeOf(err, ServerError.prototype);

          // redefine the error message
          Object.defineProperty(err, 'message', {
            enumerable: true,
            configurable: true,
            value: msg,
            writable: true,
          });

          // redefine the error name
          Object.defineProperty(err, 'name', {
            enumerable: false,
            configurable: true,
            value: className,
            writable: true,
          });

          return err;
        }

        inherits(ServerError, HttpError);
        nameFunc(ServerError, className);

        ServerError.prototype.status = code;
        ServerError.prototype.statusCode = code;
        ServerError.prototype.expose = false;

        return ServerError;
      }

      /**
       * Set the name of a function, if possible.
       * @private
       */

      function nameFunc(func, name) {
        var desc = Object.getOwnPropertyDescriptor(func, 'name');

        if (desc && desc.configurable) {
          desc.value = name;
          Object.defineProperty(func, 'name', desc);
        }
      }

      /**
       * Populate the exports object with constructors for every error class.
       * @private
       */

      function populateConstructorExports(exports, codes, HttpError) {
        codes.forEach(function forEachCode(code) {
          var CodeError;
          var name = toIdentifier(statuses.message[code]);

          switch (codeClass(code)) {
            case 400:
              CodeError = createClientErrorConstructor(HttpError, name, code);
              break;
            case 500:
              CodeError = createServerErrorConstructor(HttpError, name, code);
              break;
          }

          if (CodeError) {
            // export the constructor
            exports[code] = CodeError;
            exports[name] = CodeError;
          }
        });
      }

      /**
       * Get a class name from a name identifier.
       * @private
       */

      function toClassName(name) {
        return name.substr(-5) !== 'Error' ? name + 'Error' : name;
      }

      /***/
    },

    /***/ 7835: /***/ (
      module,
      __unused_webpack_exports,
      __webpack_require__,
    ) => {
      try {
        var util = __webpack_require__(9023);
        /* istanbul ignore next */
        if (typeof util.inherits !== 'function') throw '';
        module.exports = util.inherits;
      } catch (e) {
        /* istanbul ignore next */
        module.exports = __webpack_require__(6192);
      }

      /***/
    },

    /***/ 6192: /***/ (module) => {
      if (typeof Object.create === 'function') {
        // implementation from standard node.js 'util' module
        module.exports = function inherits(ctor, superCtor) {
          if (superCtor) {
            ctor.super_ = superCtor;
            ctor.prototype = Object.create(superCtor.prototype, {
              constructor: {
                value: ctor,
                enumerable: false,
                writable: true,
                configurable: true,
              },
            });
          }
        };
      } else {
        // old school shim for old browsers
        module.exports = function inherits(ctor, superCtor) {
          if (superCtor) {
            ctor.super_ = superCtor;
            var TempCtor = function () {};
            TempCtor.prototype = superCtor.prototype;
            ctor.prototype = new TempCtor();
            ctor.prototype.constructor = ctor;
          }
        };
      }

      /***/
    },

    /***/ 2494: /***/ (module) => {
      'use strict';

      /**
       * @param typeMap [Object] Map of MIME type -> Array[extensions]
       * @param ...
       */
      function Mime() {
        this._types = Object.create(null);
        this._extensions = Object.create(null);

        for (let i = 0; i < arguments.length; i++) {
          this.define(arguments[i]);
        }

        this.define = this.define.bind(this);
        this.getType = this.getType.bind(this);
        this.getExtension = this.getExtension.bind(this);
      }

      /**
       * Define mimetype -> extension mappings.  Each key is a mime-type that maps
       * to an array of extensions associated with the type.  The first extension is
       * used as the default extension for the type.
       *
       * e.g. mime.define({'audio/ogg', ['oga', 'ogg', 'spx']});
       *
       * If a type declares an extension that has already been defined, an error will
       * be thrown.  To suppress this error and force the extension to be associated
       * with the new type, pass `force`=true.  Alternatively, you may prefix the
       * extension with "*" to map the type to extension, without mapping the
       * extension to the type.
       *
       * e.g. mime.define({'audio/wav', ['wav']}, {'audio/x-wav', ['*wav']});
       *
       *
       * @param map (Object) type definitions
       * @param force (Boolean) if true, force overriding of existing definitions
       */
      Mime.prototype.define = function (typeMap, force) {
        for (let type in typeMap) {
          let extensions = typeMap[type].map(function (t) {
            return t.toLowerCase();
          });
          type = type.toLowerCase();

          for (let i = 0; i < extensions.length; i++) {
            const ext = extensions[i];

            // '*' prefix = not the preferred type for this extension.  So fixup the
            // extension, and skip it.
            if (ext[0] === '*') {
              continue;
            }

            if (!force && ext in this._types) {
              throw new Error(
                'Attempt to change mapping for "' +
                  ext +
                  '" extension from "' +
                  this._types[ext] +
                  '" to "' +
                  type +
                  '". Pass `force=true` to allow this, otherwise remove "' +
                  ext +
                  '" from the list of extensions for "' +
                  type +
                  '".',
              );
            }

            this._types[ext] = type;
          }

          // Use first extension as default
          if (force || !this._extensions[type]) {
            const ext = extensions[0];
            this._extensions[type] = ext[0] !== '*' ? ext : ext.substr(1);
          }
        }
      };

      /**
       * Lookup a mime type based on extension
       */
      Mime.prototype.getType = function (path) {
        path = String(path);
        let last = path.replace(/^.*[/\\]/, '').toLowerCase();
        let ext = last.replace(/^.*\./, '').toLowerCase();

        let hasPath = last.length < path.length;
        let hasDot = ext.length < last.length - 1;

        return ((hasDot || !hasPath) && this._types[ext]) || null;
      };

      /**
       * Return file extension associated with a mime type
       */
      Mime.prototype.getExtension = function (type) {
        type = /^\s*([^;\s]*)/.test(type) && RegExp.$1;
        return (type && this._extensions[type.toLowerCase()]) || null;
      };

      module.exports = Mime;

      /***/
    },

    /***/ 2360: /***/ (
      module,
      __unused_webpack_exports,
      __webpack_require__,
    ) => {
      'use strict';

      let Mime = __webpack_require__(2494);
      module.exports = new Mime(
        __webpack_require__(6521),
        __webpack_require__(1936),
      );

      /***/
    },

    /***/ 1936: /***/ (module) => {
      module.exports = {
        'application/prs.cww': ['cww'],
        'application/vnd.1000minds.decision-model+xml': ['1km'],
        'application/vnd.3gpp.pic-bw-large': ['plb'],
        'application/vnd.3gpp.pic-bw-small': ['psb'],
        'application/vnd.3gpp.pic-bw-var': ['pvb'],
        'application/vnd.3gpp2.tcap': ['tcap'],
        'application/vnd.3m.post-it-notes': ['pwn'],
        'application/vnd.accpac.simply.aso': ['aso'],
        'application/vnd.accpac.simply.imp': ['imp'],
        'application/vnd.acucobol': ['acu'],
        'application/vnd.acucorp': ['atc', 'acutc'],
        'application/vnd.adobe.air-application-installer-package+zip': ['air'],
        'application/vnd.adobe.formscentral.fcdt': ['fcdt'],
        'application/vnd.adobe.fxp': ['fxp', 'fxpl'],
        'application/vnd.adobe.xdp+xml': ['xdp'],
        'application/vnd.adobe.xfdf': ['xfdf'],
        'application/vnd.ahead.space': ['ahead'],
        'application/vnd.airzip.filesecure.azf': ['azf'],
        'application/vnd.airzip.filesecure.azs': ['azs'],
        'application/vnd.amazon.ebook': ['azw'],
        'application/vnd.americandynamics.acc': ['acc'],
        'application/vnd.amiga.ami': ['ami'],
        'application/vnd.android.package-archive': ['apk'],
        'application/vnd.anser-web-certificate-issue-initiation': ['cii'],
        'application/vnd.anser-web-funds-transfer-initiation': ['fti'],
        'application/vnd.antix.game-component': ['atx'],
        'application/vnd.apple.installer+xml': ['mpkg'],
        'application/vnd.apple.keynote': ['key'],
        'application/vnd.apple.mpegurl': ['m3u8'],
        'application/vnd.apple.numbers': ['numbers'],
        'application/vnd.apple.pages': ['pages'],
        'application/vnd.apple.pkpass': ['pkpass'],
        'application/vnd.aristanetworks.swi': ['swi'],
        'application/vnd.astraea-software.iota': ['iota'],
        'application/vnd.audiograph': ['aep'],
        'application/vnd.balsamiq.bmml+xml': ['bmml'],
        'application/vnd.blueice.multipass': ['mpm'],
        'application/vnd.bmi': ['bmi'],
        'application/vnd.businessobjects': ['rep'],
        'application/vnd.chemdraw+xml': ['cdxml'],
        'application/vnd.chipnuts.karaoke-mmd': ['mmd'],
        'application/vnd.cinderella': ['cdy'],
        'application/vnd.citationstyles.style+xml': ['csl'],
        'application/vnd.claymore': ['cla'],
        'application/vnd.cloanto.rp9': ['rp9'],
        'application/vnd.clonk.c4group': ['c4g', 'c4d', 'c4f', 'c4p', 'c4u'],
        'application/vnd.cluetrust.cartomobile-config': ['c11amc'],
        'application/vnd.cluetrust.cartomobile-config-pkg': ['c11amz'],
        'application/vnd.commonspace': ['csp'],
        'application/vnd.contact.cmsg': ['cdbcmsg'],
        'application/vnd.cosmocaller': ['cmc'],
        'application/vnd.crick.clicker': ['clkx'],
        'application/vnd.crick.clicker.keyboard': ['clkk'],
        'application/vnd.crick.clicker.palette': ['clkp'],
        'application/vnd.crick.clicker.template': ['clkt'],
        'application/vnd.crick.clicker.wordbank': ['clkw'],
        'application/vnd.criticaltools.wbs+xml': ['wbs'],
        'application/vnd.ctc-posml': ['pml'],
        'application/vnd.cups-ppd': ['ppd'],
        'application/vnd.curl.car': ['car'],
        'application/vnd.curl.pcurl': ['pcurl'],
        'application/vnd.dart': ['dart'],
        'application/vnd.data-vision.rdz': ['rdz'],
        'application/vnd.dbf': ['dbf'],
        'application/vnd.dece.data': ['uvf', 'uvvf', 'uvd', 'uvvd'],
        'application/vnd.dece.ttml+xml': ['uvt', 'uvvt'],
        'application/vnd.dece.unspecified': ['uvx', 'uvvx'],
        'application/vnd.dece.zip': ['uvz', 'uvvz'],
        'application/vnd.denovo.fcselayout-link': ['fe_launch'],
        'application/vnd.dna': ['dna'],
        'application/vnd.dolby.mlp': ['mlp'],
        'application/vnd.dpgraph': ['dpg'],
        'application/vnd.dreamfactory': ['dfac'],
        'application/vnd.ds-keypoint': ['kpxx'],
        'application/vnd.dvb.ait': ['ait'],
        'application/vnd.dvb.service': ['svc'],
        'application/vnd.dynageo': ['geo'],
        'application/vnd.ecowin.chart': ['mag'],
        'application/vnd.enliven': ['nml'],
        'application/vnd.epson.esf': ['esf'],
        'application/vnd.epson.msf': ['msf'],
        'application/vnd.epson.quickanime': ['qam'],
        'application/vnd.epson.salt': ['slt'],
        'application/vnd.epson.ssf': ['ssf'],
        'application/vnd.eszigno3+xml': ['es3', 'et3'],
        'application/vnd.ezpix-album': ['ez2'],
        'application/vnd.ezpix-package': ['ez3'],
        'application/vnd.fdf': ['fdf'],
        'application/vnd.fdsn.mseed': ['mseed'],
        'application/vnd.fdsn.seed': ['seed', 'dataless'],
        'application/vnd.flographit': ['gph'],
        'application/vnd.fluxtime.clip': ['ftc'],
        'application/vnd.framemaker': ['fm', 'frame', 'maker', 'book'],
        'application/vnd.frogans.fnc': ['fnc'],
        'application/vnd.frogans.ltf': ['ltf'],
        'application/vnd.fsc.weblaunch': ['fsc'],
        'application/vnd.fujitsu.oasys': ['oas'],
        'application/vnd.fujitsu.oasys2': ['oa2'],
        'application/vnd.fujitsu.oasys3': ['oa3'],
        'application/vnd.fujitsu.oasysgp': ['fg5'],
        'application/vnd.fujitsu.oasysprs': ['bh2'],
        'application/vnd.fujixerox.ddd': ['ddd'],
        'application/vnd.fujixerox.docuworks': ['xdw'],
        'application/vnd.fujixerox.docuworks.binder': ['xbd'],
        'application/vnd.fuzzysheet': ['fzs'],
        'application/vnd.genomatix.tuxedo': ['txd'],
        'application/vnd.geogebra.file': ['ggb'],
        'application/vnd.geogebra.tool': ['ggt'],
        'application/vnd.geometry-explorer': ['gex', 'gre'],
        'application/vnd.geonext': ['gxt'],
        'application/vnd.geoplan': ['g2w'],
        'application/vnd.geospace': ['g3w'],
        'application/vnd.gmx': ['gmx'],
        'application/vnd.google-apps.document': ['gdoc'],
        'application/vnd.google-apps.presentation': ['gslides'],
        'application/vnd.google-apps.spreadsheet': ['gsheet'],
        'application/vnd.google-earth.kml+xml': ['kml'],
        'application/vnd.google-earth.kmz': ['kmz'],
        'application/vnd.grafeq': ['gqf', 'gqs'],
        'application/vnd.groove-account': ['gac'],
        'application/vnd.groove-help': ['ghf'],
        'application/vnd.groove-identity-message': ['gim'],
        'application/vnd.groove-injector': ['grv'],
        'application/vnd.groove-tool-message': ['gtm'],
        'application/vnd.groove-tool-template': ['tpl'],
        'application/vnd.groove-vcard': ['vcg'],
        'application/vnd.hal+xml': ['hal'],
        'application/vnd.handheld-entertainment+xml': ['zmm'],
        'application/vnd.hbci': ['hbci'],
        'application/vnd.hhe.lesson-player': ['les'],
        'application/vnd.hp-hpgl': ['hpgl'],
        'application/vnd.hp-hpid': ['hpid'],
        'application/vnd.hp-hps': ['hps'],
        'application/vnd.hp-jlyt': ['jlt'],
        'application/vnd.hp-pcl': ['pcl'],
        'application/vnd.hp-pclxl': ['pclxl'],
        'application/vnd.hydrostatix.sof-data': ['sfd-hdstx'],
        'application/vnd.ibm.minipay': ['mpy'],
        'application/vnd.ibm.modcap': ['afp', 'listafp', 'list3820'],
        'application/vnd.ibm.rights-management': ['irm'],
        'application/vnd.ibm.secure-container': ['sc'],
        'application/vnd.iccprofile': ['icc', 'icm'],
        'application/vnd.igloader': ['igl'],
        'application/vnd.immervision-ivp': ['ivp'],
        'application/vnd.immervision-ivu': ['ivu'],
        'application/vnd.insors.igm': ['igm'],
        'application/vnd.intercon.formnet': ['xpw', 'xpx'],
        'application/vnd.intergeo': ['i2g'],
        'application/vnd.intu.qbo': ['qbo'],
        'application/vnd.intu.qfx': ['qfx'],
        'application/vnd.ipunplugged.rcprofile': ['rcprofile'],
        'application/vnd.irepository.package+xml': ['irp'],
        'application/vnd.is-xpr': ['xpr'],
        'application/vnd.isac.fcs': ['fcs'],
        'application/vnd.jam': ['jam'],
        'application/vnd.jcp.javame.midlet-rms': ['rms'],
        'application/vnd.jisp': ['jisp'],
        'application/vnd.joost.joda-archive': ['joda'],
        'application/vnd.kahootz': ['ktz', 'ktr'],
        'application/vnd.kde.karbon': ['karbon'],
        'application/vnd.kde.kchart': ['chrt'],
        'application/vnd.kde.kformula': ['kfo'],
        'application/vnd.kde.kivio': ['flw'],
        'application/vnd.kde.kontour': ['kon'],
        'application/vnd.kde.kpresenter': ['kpr', 'kpt'],
        'application/vnd.kde.kspread': ['ksp'],
        'application/vnd.kde.kword': ['kwd', 'kwt'],
        'application/vnd.kenameaapp': ['htke'],
        'application/vnd.kidspiration': ['kia'],
        'application/vnd.kinar': ['kne', 'knp'],
        'application/vnd.koan': ['skp', 'skd', 'skt', 'skm'],
        'application/vnd.kodak-descriptor': ['sse'],
        'application/vnd.las.las+xml': ['lasxml'],
        'application/vnd.llamagraphics.life-balance.desktop': ['lbd'],
        'application/vnd.llamagraphics.life-balance.exchange+xml': ['lbe'],
        'application/vnd.lotus-1-2-3': ['123'],
        'application/vnd.lotus-approach': ['apr'],
        'application/vnd.lotus-freelance': ['pre'],
        'application/vnd.lotus-notes': ['nsf'],
        'application/vnd.lotus-organizer': ['org'],
        'application/vnd.lotus-screencam': ['scm'],
        'application/vnd.lotus-wordpro': ['lwp'],
        'application/vnd.macports.portpkg': ['portpkg'],
        'application/vnd.mapbox-vector-tile': ['mvt'],
        'application/vnd.mcd': ['mcd'],
        'application/vnd.medcalcdata': ['mc1'],
        'application/vnd.mediastation.cdkey': ['cdkey'],
        'application/vnd.mfer': ['mwf'],
        'application/vnd.mfmp': ['mfm'],
        'application/vnd.micrografx.flo': ['flo'],
        'application/vnd.micrografx.igx': ['igx'],
        'application/vnd.mif': ['mif'],
        'application/vnd.mobius.daf': ['daf'],
        'application/vnd.mobius.dis': ['dis'],
        'application/vnd.mobius.mbk': ['mbk'],
        'application/vnd.mobius.mqy': ['mqy'],
        'application/vnd.mobius.msl': ['msl'],
        'application/vnd.mobius.plc': ['plc'],
        'application/vnd.mobius.txf': ['txf'],
        'application/vnd.mophun.application': ['mpn'],
        'application/vnd.mophun.certificate': ['mpc'],
        'application/vnd.mozilla.xul+xml': ['xul'],
        'application/vnd.ms-artgalry': ['cil'],
        'application/vnd.ms-cab-compressed': ['cab'],
        'application/vnd.ms-excel': ['xls', 'xlm', 'xla', 'xlc', 'xlt', 'xlw'],
        'application/vnd.ms-excel.addin.macroenabled.12': ['xlam'],
        'application/vnd.ms-excel.sheet.binary.macroenabled.12': ['xlsb'],
        'application/vnd.ms-excel.sheet.macroenabled.12': ['xlsm'],
        'application/vnd.ms-excel.template.macroenabled.12': ['xltm'],
        'application/vnd.ms-fontobject': ['eot'],
        'application/vnd.ms-htmlhelp': ['chm'],
        'application/vnd.ms-ims': ['ims'],
        'application/vnd.ms-lrm': ['lrm'],
        'application/vnd.ms-officetheme': ['thmx'],
        'application/vnd.ms-outlook': ['msg'],
        'application/vnd.ms-pki.seccat': ['cat'],
        'application/vnd.ms-pki.stl': ['*stl'],
        'application/vnd.ms-powerpoint': ['ppt', 'pps', 'pot'],
        'application/vnd.ms-powerpoint.addin.macroenabled.12': ['ppam'],
        'application/vnd.ms-powerpoint.presentation.macroenabled.12': ['pptm'],
        'application/vnd.ms-powerpoint.slide.macroenabled.12': ['sldm'],
        'application/vnd.ms-powerpoint.slideshow.macroenabled.12': ['ppsm'],
        'application/vnd.ms-powerpoint.template.macroenabled.12': ['potm'],
        'application/vnd.ms-project': ['mpp', 'mpt'],
        'application/vnd.ms-word.document.macroenabled.12': ['docm'],
        'application/vnd.ms-word.template.macroenabled.12': ['dotm'],
        'application/vnd.ms-works': ['wps', 'wks', 'wcm', 'wdb'],
        'application/vnd.ms-wpl': ['wpl'],
        'application/vnd.ms-xpsdocument': ['xps'],
        'application/vnd.mseq': ['mseq'],
        'application/vnd.musician': ['mus'],
        'application/vnd.muvee.style': ['msty'],
        'application/vnd.mynfc': ['taglet'],
        'application/vnd.neurolanguage.nlu': ['nlu'],
        'application/vnd.nitf': ['ntf', 'nitf'],
        'application/vnd.noblenet-directory': ['nnd'],
        'application/vnd.noblenet-sealer': ['nns'],
        'application/vnd.noblenet-web': ['nnw'],
        'application/vnd.nokia.n-gage.ac+xml': ['*ac'],
        'application/vnd.nokia.n-gage.data': ['ngdat'],
        'application/vnd.nokia.n-gage.symbian.install': ['n-gage'],
        'application/vnd.nokia.radio-preset': ['rpst'],
        'application/vnd.nokia.radio-presets': ['rpss'],
        'application/vnd.novadigm.edm': ['edm'],
        'application/vnd.novadigm.edx': ['edx'],
        'application/vnd.novadigm.ext': ['ext'],
        'application/vnd.oasis.opendocument.chart': ['odc'],
        'application/vnd.oasis.opendocument.chart-template': ['otc'],
        'application/vnd.oasis.opendocument.database': ['odb'],
        'application/vnd.oasis.opendocument.formula': ['odf'],
        'application/vnd.oasis.opendocument.formula-template': ['odft'],
        'application/vnd.oasis.opendocument.graphics': ['odg'],
        'application/vnd.oasis.opendocument.graphics-template': ['otg'],
        'application/vnd.oasis.opendocument.image': ['odi'],
        'application/vnd.oasis.opendocument.image-template': ['oti'],
        'application/vnd.oasis.opendocument.presentation': ['odp'],
        'application/vnd.oasis.opendocument.presentation-template': ['otp'],
        'application/vnd.oasis.opendocument.spreadsheet': ['ods'],
        'application/vnd.oasis.opendocument.spreadsheet-template': ['ots'],
        'application/vnd.oasis.opendocument.text': ['odt'],
        'application/vnd.oasis.opendocument.text-master': ['odm'],
        'application/vnd.oasis.opendocument.text-template': ['ott'],
        'application/vnd.oasis.opendocument.text-web': ['oth'],
        'application/vnd.olpc-sugar': ['xo'],
        'application/vnd.oma.dd2+xml': ['dd2'],
        'application/vnd.openblox.game+xml': ['obgx'],
        'application/vnd.openofficeorg.extension': ['oxt'],
        'application/vnd.openstreetmap.data+xml': ['osm'],
        'application/vnd.openxmlformats-officedocument.presentationml.presentation':
          ['pptx'],
        'application/vnd.openxmlformats-officedocument.presentationml.slide': [
          'sldx',
        ],
        'application/vnd.openxmlformats-officedocument.presentationml.slideshow':
          ['ppsx'],
        'application/vnd.openxmlformats-officedocument.presentationml.template':
          ['potx'],
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': [
          'xlsx',
        ],
        'application/vnd.openxmlformats-officedocument.spreadsheetml.template':
          ['xltx'],
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document':
          ['docx'],
        'application/vnd.openxmlformats-officedocument.wordprocessingml.template':
          ['dotx'],
        'application/vnd.osgeo.mapguide.package': ['mgp'],
        'application/vnd.osgi.dp': ['dp'],
        'application/vnd.osgi.subsystem': ['esa'],
        'application/vnd.palm': ['pdb', 'pqa', 'oprc'],
        'application/vnd.pawaafile': ['paw'],
        'application/vnd.pg.format': ['str'],
        'application/vnd.pg.osasli': ['ei6'],
        'application/vnd.picsel': ['efif'],
        'application/vnd.pmi.widget': ['wg'],
        'application/vnd.pocketlearn': ['plf'],
        'application/vnd.powerbuilder6': ['pbd'],
        'application/vnd.previewsystems.box': ['box'],
        'application/vnd.proteus.magazine': ['mgz'],
        'application/vnd.publishare-delta-tree': ['qps'],
        'application/vnd.pvi.ptid1': ['ptid'],
        'application/vnd.quark.quarkxpress': [
          'qxd',
          'qxt',
          'qwd',
          'qwt',
          'qxl',
          'qxb',
        ],
        'application/vnd.rar': ['rar'],
        'application/vnd.realvnc.bed': ['bed'],
        'application/vnd.recordare.musicxml': ['mxl'],
        'application/vnd.recordare.musicxml+xml': ['musicxml'],
        'application/vnd.rig.cryptonote': ['cryptonote'],
        'application/vnd.rim.cod': ['cod'],
        'application/vnd.rn-realmedia': ['rm'],
        'application/vnd.rn-realmedia-vbr': ['rmvb'],
        'application/vnd.route66.link66+xml': ['link66'],
        'application/vnd.sailingtracker.track': ['st'],
        'application/vnd.seemail': ['see'],
        'application/vnd.sema': ['sema'],
        'application/vnd.semd': ['semd'],
        'application/vnd.semf': ['semf'],
        'application/vnd.shana.informed.formdata': ['ifm'],
        'application/vnd.shana.informed.formtemplate': ['itp'],
        'application/vnd.shana.informed.interchange': ['iif'],
        'application/vnd.shana.informed.package': ['ipk'],
        'application/vnd.simtech-mindmapper': ['twd', 'twds'],
        'application/vnd.smaf': ['mmf'],
        'application/vnd.smart.teacher': ['teacher'],
        'application/vnd.software602.filler.form+xml': ['fo'],
        'application/vnd.solent.sdkm+xml': ['sdkm', 'sdkd'],
        'application/vnd.spotfire.dxp': ['dxp'],
        'application/vnd.spotfire.sfs': ['sfs'],
        'application/vnd.stardivision.calc': ['sdc'],
        'application/vnd.stardivision.draw': ['sda'],
        'application/vnd.stardivision.impress': ['sdd'],
        'application/vnd.stardivision.math': ['smf'],
        'application/vnd.stardivision.writer': ['sdw', 'vor'],
        'application/vnd.stardivision.writer-global': ['sgl'],
        'application/vnd.stepmania.package': ['smzip'],
        'application/vnd.stepmania.stepchart': ['sm'],
        'application/vnd.sun.wadl+xml': ['wadl'],
        'application/vnd.sun.xml.calc': ['sxc'],
        'application/vnd.sun.xml.calc.template': ['stc'],
        'application/vnd.sun.xml.draw': ['sxd'],
        'application/vnd.sun.xml.draw.template': ['std'],
        'application/vnd.sun.xml.impress': ['sxi'],
        'application/vnd.sun.xml.impress.template': ['sti'],
        'application/vnd.sun.xml.math': ['sxm'],
        'application/vnd.sun.xml.writer': ['sxw'],
        'application/vnd.sun.xml.writer.global': ['sxg'],
        'application/vnd.sun.xml.writer.template': ['stw'],
        'application/vnd.sus-calendar': ['sus', 'susp'],
        'application/vnd.svd': ['svd'],
        'application/vnd.symbian.install': ['sis', 'sisx'],
        'application/vnd.syncml+xml': ['xsm'],
        'application/vnd.syncml.dm+wbxml': ['bdm'],
        'application/vnd.syncml.dm+xml': ['xdm'],
        'application/vnd.syncml.dmddf+xml': ['ddf'],
        'application/vnd.tao.intent-module-archive': ['tao'],
        'application/vnd.tcpdump.pcap': ['pcap', 'cap', 'dmp'],
        'application/vnd.tmobile-livetv': ['tmo'],
        'application/vnd.trid.tpt': ['tpt'],
        'application/vnd.triscape.mxs': ['mxs'],
        'application/vnd.trueapp': ['tra'],
        'application/vnd.ufdl': ['ufd', 'ufdl'],
        'application/vnd.uiq.theme': ['utz'],
        'application/vnd.umajin': ['umj'],
        'application/vnd.unity': ['unityweb'],
        'application/vnd.uoml+xml': ['uoml'],
        'application/vnd.vcx': ['vcx'],
        'application/vnd.visio': ['vsd', 'vst', 'vss', 'vsw'],
        'application/vnd.visionary': ['vis'],
        'application/vnd.vsf': ['vsf'],
        'application/vnd.wap.wbxml': ['wbxml'],
        'application/vnd.wap.wmlc': ['wmlc'],
        'application/vnd.wap.wmlscriptc': ['wmlsc'],
        'application/vnd.webturbo': ['wtb'],
        'application/vnd.wolfram.player': ['nbp'],
        'application/vnd.wordperfect': ['wpd'],
        'application/vnd.wqd': ['wqd'],
        'application/vnd.wt.stf': ['stf'],
        'application/vnd.xara': ['xar'],
        'application/vnd.xfdl': ['xfdl'],
        'application/vnd.yamaha.hv-dic': ['hvd'],
        'application/vnd.yamaha.hv-script': ['hvs'],
        'application/vnd.yamaha.hv-voice': ['hvp'],
        'application/vnd.yamaha.openscoreformat': ['osf'],
        'application/vnd.yamaha.openscoreformat.osfpvg+xml': ['osfpvg'],
        'application/vnd.yamaha.smaf-audio': ['saf'],
        'application/vnd.yamaha.smaf-phrase': ['spf'],
        'application/vnd.yellowriver-custom-menu': ['cmp'],
        'application/vnd.zul': ['zir', 'zirz'],
        'application/vnd.zzazz.deck+xml': ['zaz'],
        'application/x-7z-compressed': ['7z'],
        'application/x-abiword': ['abw'],
        'application/x-ace-compressed': ['ace'],
        'application/x-apple-diskimage': ['*dmg'],
        'application/x-arj': ['arj'],
        'application/x-authorware-bin': ['aab', 'x32', 'u32', 'vox'],
        'application/x-authorware-map': ['aam'],
        'application/x-authorware-seg': ['aas'],
        'application/x-bcpio': ['bcpio'],
        'application/x-bdoc': ['*bdoc'],
        'application/x-bittorrent': ['torrent'],
        'application/x-blorb': ['blb', 'blorb'],
        'application/x-bzip': ['bz'],
        'application/x-bzip2': ['bz2', 'boz'],
        'application/x-cbr': ['cbr', 'cba', 'cbt', 'cbz', 'cb7'],
        'application/x-cdlink': ['vcd'],
        'application/x-cfs-compressed': ['cfs'],
        'application/x-chat': ['chat'],
        'application/x-chess-pgn': ['pgn'],
        'application/x-chrome-extension': ['crx'],
        'application/x-cocoa': ['cco'],
        'application/x-conference': ['nsc'],
        'application/x-cpio': ['cpio'],
        'application/x-csh': ['csh'],
        'application/x-debian-package': ['*deb', 'udeb'],
        'application/x-dgc-compressed': ['dgc'],
        'application/x-director': [
          'dir',
          'dcr',
          'dxr',
          'cst',
          'cct',
          'cxt',
          'w3d',
          'fgd',
          'swa',
        ],
        'application/x-doom': ['wad'],
        'application/x-dtbncx+xml': ['ncx'],
        'application/x-dtbook+xml': ['dtb'],
        'application/x-dtbresource+xml': ['res'],
        'application/x-dvi': ['dvi'],
        'application/x-envoy': ['evy'],
        'application/x-eva': ['eva'],
        'application/x-font-bdf': ['bdf'],
        'application/x-font-ghostscript': ['gsf'],
        'application/x-font-linux-psf': ['psf'],
        'application/x-font-pcf': ['pcf'],
        'application/x-font-snf': ['snf'],
        'application/x-font-type1': ['pfa', 'pfb', 'pfm', 'afm'],
        'application/x-freearc': ['arc'],
        'application/x-futuresplash': ['spl'],
        'application/x-gca-compressed': ['gca'],
        'application/x-glulx': ['ulx'],
        'application/x-gnumeric': ['gnumeric'],
        'application/x-gramps-xml': ['gramps'],
        'application/x-gtar': ['gtar'],
        'application/x-hdf': ['hdf'],
        'application/x-httpd-php': ['php'],
        'application/x-install-instructions': ['install'],
        'application/x-iso9660-image': ['*iso'],
        'application/x-iwork-keynote-sffkey': ['*key'],
        'application/x-iwork-numbers-sffnumbers': ['*numbers'],
        'application/x-iwork-pages-sffpages': ['*pages'],
        'application/x-java-archive-diff': ['jardiff'],
        'application/x-java-jnlp-file': ['jnlp'],
        'application/x-keepass2': ['kdbx'],
        'application/x-latex': ['latex'],
        'application/x-lua-bytecode': ['luac'],
        'application/x-lzh-compressed': ['lzh', 'lha'],
        'application/x-makeself': ['run'],
        'application/x-mie': ['mie'],
        'application/x-mobipocket-ebook': ['prc', 'mobi'],
        'application/x-ms-application': ['application'],
        'application/x-ms-shortcut': ['lnk'],
        'application/x-ms-wmd': ['wmd'],
        'application/x-ms-wmz': ['wmz'],
        'application/x-ms-xbap': ['xbap'],
        'application/x-msaccess': ['mdb'],
        'application/x-msbinder': ['obd'],
        'application/x-mscardfile': ['crd'],
        'application/x-msclip': ['clp'],
        'application/x-msdos-program': ['*exe'],
        'application/x-msdownload': ['*exe', '*dll', 'com', 'bat', '*msi'],
        'application/x-msmediaview': ['mvb', 'm13', 'm14'],
        'application/x-msmetafile': ['*wmf', '*wmz', '*emf', 'emz'],
        'application/x-msmoney': ['mny'],
        'application/x-mspublisher': ['pub'],
        'application/x-msschedule': ['scd'],
        'application/x-msterminal': ['trm'],
        'application/x-mswrite': ['wri'],
        'application/x-netcdf': ['nc', 'cdf'],
        'application/x-ns-proxy-autoconfig': ['pac'],
        'application/x-nzb': ['nzb'],
        'application/x-perl': ['pl', 'pm'],
        'application/x-pilot': ['*prc', '*pdb'],
        'application/x-pkcs12': ['p12', 'pfx'],
        'application/x-pkcs7-certificates': ['p7b', 'spc'],
        'application/x-pkcs7-certreqresp': ['p7r'],
        'application/x-rar-compressed': ['*rar'],
        'application/x-redhat-package-manager': ['rpm'],
        'application/x-research-info-systems': ['ris'],
        'application/x-sea': ['sea'],
        'application/x-sh': ['sh'],
        'application/x-shar': ['shar'],
        'application/x-shockwave-flash': ['swf'],
        'application/x-silverlight-app': ['xap'],
        'application/x-sql': ['sql'],
        'application/x-stuffit': ['sit'],
        'application/x-stuffitx': ['sitx'],
        'application/x-subrip': ['srt'],
        'application/x-sv4cpio': ['sv4cpio'],
        'application/x-sv4crc': ['sv4crc'],
        'application/x-t3vm-image': ['t3'],
        'application/x-tads': ['gam'],
        'application/x-tar': ['tar'],
        'application/x-tcl': ['tcl', 'tk'],
        'application/x-tex': ['tex'],
        'application/x-tex-tfm': ['tfm'],
        'application/x-texinfo': ['texinfo', 'texi'],
        'application/x-tgif': ['*obj'],
        'application/x-ustar': ['ustar'],
        'application/x-virtualbox-hdd': ['hdd'],
        'application/x-virtualbox-ova': ['ova'],
        'application/x-virtualbox-ovf': ['ovf'],
        'application/x-virtualbox-vbox': ['vbox'],
        'application/x-virtualbox-vbox-extpack': ['vbox-extpack'],
        'application/x-virtualbox-vdi': ['vdi'],
        'application/x-virtualbox-vhd': ['vhd'],
        'application/x-virtualbox-vmdk': ['vmdk'],
        'application/x-wais-source': ['src'],
        'application/x-web-app-manifest+json': ['webapp'],
        'application/x-x509-ca-cert': ['der', 'crt', 'pem'],
        'application/x-xfig': ['fig'],
        'application/x-xliff+xml': ['*xlf'],
        'application/x-xpinstall': ['xpi'],
        'application/x-xz': ['xz'],
        'application/x-zmachine': [
          'z1',
          'z2',
          'z3',
          'z4',
          'z5',
          'z6',
          'z7',
          'z8',
        ],
        'audio/vnd.dece.audio': ['uva', 'uvva'],
        'audio/vnd.digital-winds': ['eol'],
        'audio/vnd.dra': ['dra'],
        'audio/vnd.dts': ['dts'],
        'audio/vnd.dts.hd': ['dtshd'],
        'audio/vnd.lucent.voice': ['lvp'],
        'audio/vnd.ms-playready.media.pya': ['pya'],
        'audio/vnd.nuera.ecelp4800': ['ecelp4800'],
        'audio/vnd.nuera.ecelp7470': ['ecelp7470'],
        'audio/vnd.nuera.ecelp9600': ['ecelp9600'],
        'audio/vnd.rip': ['rip'],
        'audio/x-aac': ['aac'],
        'audio/x-aiff': ['aif', 'aiff', 'aifc'],
        'audio/x-caf': ['caf'],
        'audio/x-flac': ['flac'],
        'audio/x-m4a': ['*m4a'],
        'audio/x-matroska': ['mka'],
        'audio/x-mpegurl': ['m3u'],
        'audio/x-ms-wax': ['wax'],
        'audio/x-ms-wma': ['wma'],
        'audio/x-pn-realaudio': ['ram', 'ra'],
        'audio/x-pn-realaudio-plugin': ['rmp'],
        'audio/x-realaudio': ['*ra'],
        'audio/x-wav': ['*wav'],
        'chemical/x-cdx': ['cdx'],
        'chemical/x-cif': ['cif'],
        'chemical/x-cmdf': ['cmdf'],
        'chemical/x-cml': ['cml'],
        'chemical/x-csml': ['csml'],
        'chemical/x-xyz': ['xyz'],
        'image/prs.btif': ['btif'],
        'image/prs.pti': ['pti'],
        'image/vnd.adobe.photoshop': ['psd'],
        'image/vnd.airzip.accelerator.azv': ['azv'],
        'image/vnd.dece.graphic': ['uvi', 'uvvi', 'uvg', 'uvvg'],
        'image/vnd.djvu': ['djvu', 'djv'],
        'image/vnd.dvb.subtitle': ['*sub'],
        'image/vnd.dwg': ['dwg'],
        'image/vnd.dxf': ['dxf'],
        'image/vnd.fastbidsheet': ['fbs'],
        'image/vnd.fpx': ['fpx'],
        'image/vnd.fst': ['fst'],
        'image/vnd.fujixerox.edmics-mmr': ['mmr'],
        'image/vnd.fujixerox.edmics-rlc': ['rlc'],
        'image/vnd.microsoft.icon': ['ico'],
        'image/vnd.ms-dds': ['dds'],
        'image/vnd.ms-modi': ['mdi'],
        'image/vnd.ms-photo': ['wdp'],
        'image/vnd.net-fpx': ['npx'],
        'image/vnd.pco.b16': ['b16'],
        'image/vnd.tencent.tap': ['tap'],
        'image/vnd.valve.source.texture': ['vtf'],
        'image/vnd.wap.wbmp': ['wbmp'],
        'image/vnd.xiff': ['xif'],
        'image/vnd.zbrush.pcx': ['pcx'],
        'image/x-3ds': ['3ds'],
        'image/x-cmu-raster': ['ras'],
        'image/x-cmx': ['cmx'],
        'image/x-freehand': ['fh', 'fhc', 'fh4', 'fh5', 'fh7'],
        'image/x-icon': ['*ico'],
        'image/x-jng': ['jng'],
        'image/x-mrsid-image': ['sid'],
        'image/x-ms-bmp': ['*bmp'],
        'image/x-pcx': ['*pcx'],
        'image/x-pict': ['pic', 'pct'],
        'image/x-portable-anymap': ['pnm'],
        'image/x-portable-bitmap': ['pbm'],
        'image/x-portable-graymap': ['pgm'],
        'image/x-portable-pixmap': ['ppm'],
        'image/x-rgb': ['rgb'],
        'image/x-tga': ['tga'],
        'image/x-xbitmap': ['xbm'],
        'image/x-xpixmap': ['xpm'],
        'image/x-xwindowdump': ['xwd'],
        'message/vnd.wfa.wsc': ['wsc'],
        'model/vnd.collada+xml': ['dae'],
        'model/vnd.dwf': ['dwf'],
        'model/vnd.gdl': ['gdl'],
        'model/vnd.gtw': ['gtw'],
        'model/vnd.mts': ['mts'],
        'model/vnd.opengex': ['ogex'],
        'model/vnd.parasolid.transmit.binary': ['x_b'],
        'model/vnd.parasolid.transmit.text': ['x_t'],
        'model/vnd.sap.vds': ['vds'],
        'model/vnd.usdz+zip': ['usdz'],
        'model/vnd.valve.source.compiled-map': ['bsp'],
        'model/vnd.vtu': ['vtu'],
        'text/prs.lines.tag': ['dsc'],
        'text/vnd.curl': ['curl'],
        'text/vnd.curl.dcurl': ['dcurl'],
        'text/vnd.curl.mcurl': ['mcurl'],
        'text/vnd.curl.scurl': ['scurl'],
        'text/vnd.dvb.subtitle': ['sub'],
        'text/vnd.fly': ['fly'],
        'text/vnd.fmi.flexstor': ['flx'],
        'text/vnd.graphviz': ['gv'],
        'text/vnd.in3d.3dml': ['3dml'],
        'text/vnd.in3d.spot': ['spot'],
        'text/vnd.sun.j2me.app-descriptor': ['jad'],
        'text/vnd.wap.wml': ['wml'],
        'text/vnd.wap.wmlscript': ['wmls'],
        'text/x-asm': ['s', 'asm'],
        'text/x-c': ['c', 'cc', 'cxx', 'cpp', 'h', 'hh', 'dic'],
        'text/x-component': ['htc'],
        'text/x-fortran': ['f', 'for', 'f77', 'f90'],
        'text/x-handlebars-template': ['hbs'],
        'text/x-java-source': ['java'],
        'text/x-lua': ['lua'],
        'text/x-markdown': ['mkd'],
        'text/x-nfo': ['nfo'],
        'text/x-opml': ['opml'],
        'text/x-org': ['*org'],
        'text/x-pascal': ['p', 'pas'],
        'text/x-processing': ['pde'],
        'text/x-sass': ['sass'],
        'text/x-scss': ['scss'],
        'text/x-setext': ['etx'],
        'text/x-sfv': ['sfv'],
        'text/x-suse-ymp': ['ymp'],
        'text/x-uuencode': ['uu'],
        'text/x-vcalendar': ['vcs'],
        'text/x-vcard': ['vcf'],
        'video/vnd.dece.hd': ['uvh', 'uvvh'],
        'video/vnd.dece.mobile': ['uvm', 'uvvm'],
        'video/vnd.dece.pd': ['uvp', 'uvvp'],
        'video/vnd.dece.sd': ['uvs', 'uvvs'],
        'video/vnd.dece.video': ['uvv', 'uvvv'],
        'video/vnd.dvb.file': ['dvb'],
        'video/vnd.fvt': ['fvt'],
        'video/vnd.mpegurl': ['mxu', 'm4u'],
        'video/vnd.ms-playready.media.pyv': ['pyv'],
        'video/vnd.uvvu.mp4': ['uvu', 'uvvu'],
        'video/vnd.vivo': ['viv'],
        'video/x-f4v': ['f4v'],
        'video/x-fli': ['fli'],
        'video/x-flv': ['flv'],
        'video/x-m4v': ['m4v'],
        'video/x-matroska': ['mkv', 'mk3d', 'mks'],
        'video/x-mng': ['mng'],
        'video/x-ms-asf': ['asf', 'asx'],
        'video/x-ms-vob': ['vob'],
        'video/x-ms-wm': ['wm'],
        'video/x-ms-wmv': ['wmv'],
        'video/x-ms-wmx': ['wmx'],
        'video/x-ms-wvx': ['wvx'],
        'video/x-msvideo': ['avi'],
        'video/x-sgi-movie': ['movie'],
        'video/x-smv': ['smv'],
        'x-conference/x-cooltalk': ['ice'],
      };

      /***/
    },

    /***/ 6521: /***/ (module) => {
      module.exports = {
        'application/andrew-inset': ['ez'],
        'application/applixware': ['aw'],
        'application/atom+xml': ['atom'],
        'application/atomcat+xml': ['atomcat'],
        'application/atomdeleted+xml': ['atomdeleted'],
        'application/atomsvc+xml': ['atomsvc'],
        'application/atsc-dwd+xml': ['dwd'],
        'application/atsc-held+xml': ['held'],
        'application/atsc-rsat+xml': ['rsat'],
        'application/bdoc': ['bdoc'],
        'application/calendar+xml': ['xcs'],
        'application/ccxml+xml': ['ccxml'],
        'application/cdfx+xml': ['cdfx'],
        'application/cdmi-capability': ['cdmia'],
        'application/cdmi-container': ['cdmic'],
        'application/cdmi-domain': ['cdmid'],
        'application/cdmi-object': ['cdmio'],
        'application/cdmi-queue': ['cdmiq'],
        'application/cu-seeme': ['cu'],
        'application/dash+xml': ['mpd'],
        'application/davmount+xml': ['davmount'],
        'application/docbook+xml': ['dbk'],
        'application/dssc+der': ['dssc'],
        'application/dssc+xml': ['xdssc'],
        'application/ecmascript': ['es', 'ecma'],
        'application/emma+xml': ['emma'],
        'application/emotionml+xml': ['emotionml'],
        'application/epub+zip': ['epub'],
        'application/exi': ['exi'],
        'application/express': ['exp'],
        'application/fdt+xml': ['fdt'],
        'application/font-tdpfr': ['pfr'],
        'application/geo+json': ['geojson'],
        'application/gml+xml': ['gml'],
        'application/gpx+xml': ['gpx'],
        'application/gxf': ['gxf'],
        'application/gzip': ['gz'],
        'application/hjson': ['hjson'],
        'application/hyperstudio': ['stk'],
        'application/inkml+xml': ['ink', 'inkml'],
        'application/ipfix': ['ipfix'],
        'application/its+xml': ['its'],
        'application/java-archive': ['jar', 'war', 'ear'],
        'application/java-serialized-object': ['ser'],
        'application/java-vm': ['class'],
        'application/javascript': ['js', 'mjs'],
        'application/json': ['json', 'map'],
        'application/json5': ['json5'],
        'application/jsonml+json': ['jsonml'],
        'application/ld+json': ['jsonld'],
        'application/lgr+xml': ['lgr'],
        'application/lost+xml': ['lostxml'],
        'application/mac-binhex40': ['hqx'],
        'application/mac-compactpro': ['cpt'],
        'application/mads+xml': ['mads'],
        'application/manifest+json': ['webmanifest'],
        'application/marc': ['mrc'],
        'application/marcxml+xml': ['mrcx'],
        'application/mathematica': ['ma', 'nb', 'mb'],
        'application/mathml+xml': ['mathml'],
        'application/mbox': ['mbox'],
        'application/mediaservercontrol+xml': ['mscml'],
        'application/metalink+xml': ['metalink'],
        'application/metalink4+xml': ['meta4'],
        'application/mets+xml': ['mets'],
        'application/mmt-aei+xml': ['maei'],
        'application/mmt-usd+xml': ['musd'],
        'application/mods+xml': ['mods'],
        'application/mp21': ['m21', 'mp21'],
        'application/mp4': ['mp4s', 'm4p'],
        'application/msword': ['doc', 'dot'],
        'application/mxf': ['mxf'],
        'application/n-quads': ['nq'],
        'application/n-triples': ['nt'],
        'application/node': ['cjs'],
        'application/octet-stream': [
          'bin',
          'dms',
          'lrf',
          'mar',
          'so',
          'dist',
          'distz',
          'pkg',
          'bpk',
          'dump',
          'elc',
          'deploy',
          'exe',
          'dll',
          'deb',
          'dmg',
          'iso',
          'img',
          'msi',
          'msp',
          'msm',
          'buffer',
        ],
        'application/oda': ['oda'],
        'application/oebps-package+xml': ['opf'],
        'application/ogg': ['ogx'],
        'application/omdoc+xml': ['omdoc'],
        'application/onenote': ['onetoc', 'onetoc2', 'onetmp', 'onepkg'],
        'application/oxps': ['oxps'],
        'application/p2p-overlay+xml': ['relo'],
        'application/patch-ops-error+xml': ['xer'],
        'application/pdf': ['pdf'],
        'application/pgp-encrypted': ['pgp'],
        'application/pgp-signature': ['asc', 'sig'],
        'application/pics-rules': ['prf'],
        'application/pkcs10': ['p10'],
        'application/pkcs7-mime': ['p7m', 'p7c'],
        'application/pkcs7-signature': ['p7s'],
        'application/pkcs8': ['p8'],
        'application/pkix-attr-cert': ['ac'],
        'application/pkix-cert': ['cer'],
        'application/pkix-crl': ['crl'],
        'application/pkix-pkipath': ['pkipath'],
        'application/pkixcmp': ['pki'],
        'application/pls+xml': ['pls'],
        'application/postscript': ['ai', 'eps', 'ps'],
        'application/provenance+xml': ['provx'],
        'application/pskc+xml': ['pskcxml'],
        'application/raml+yaml': ['raml'],
        'application/rdf+xml': ['rdf', 'owl'],
        'application/reginfo+xml': ['rif'],
        'application/relax-ng-compact-syntax': ['rnc'],
        'application/resource-lists+xml': ['rl'],
        'application/resource-lists-diff+xml': ['rld'],
        'application/rls-services+xml': ['rs'],
        'application/route-apd+xml': ['rapd'],
        'application/route-s-tsid+xml': ['sls'],
        'application/route-usd+xml': ['rusd'],
        'application/rpki-ghostbusters': ['gbr'],
        'application/rpki-manifest': ['mft'],
        'application/rpki-roa': ['roa'],
        'application/rsd+xml': ['rsd'],
        'application/rss+xml': ['rss'],
        'application/rtf': ['rtf'],
        'application/sbml+xml': ['sbml'],
        'application/scvp-cv-request': ['scq'],
        'application/scvp-cv-response': ['scs'],
        'application/scvp-vp-request': ['spq'],
        'application/scvp-vp-response': ['spp'],
        'application/sdp': ['sdp'],
        'application/senml+xml': ['senmlx'],
        'application/sensml+xml': ['sensmlx'],
        'application/set-payment-initiation': ['setpay'],
        'application/set-registration-initiation': ['setreg'],
        'application/shf+xml': ['shf'],
        'application/sieve': ['siv', 'sieve'],
        'application/smil+xml': ['smi', 'smil'],
        'application/sparql-query': ['rq'],
        'application/sparql-results+xml': ['srx'],
        'application/srgs': ['gram'],
        'application/srgs+xml': ['grxml'],
        'application/sru+xml': ['sru'],
        'application/ssdl+xml': ['ssdl'],
        'application/ssml+xml': ['ssml'],
        'application/swid+xml': ['swidtag'],
        'application/tei+xml': ['tei', 'teicorpus'],
        'application/thraud+xml': ['tfi'],
        'application/timestamped-data': ['tsd'],
        'application/toml': ['toml'],
        'application/trig': ['trig'],
        'application/ttml+xml': ['ttml'],
        'application/ubjson': ['ubj'],
        'application/urc-ressheet+xml': ['rsheet'],
        'application/urc-targetdesc+xml': ['td'],
        'application/voicexml+xml': ['vxml'],
        'application/wasm': ['wasm'],
        'application/widget': ['wgt'],
        'application/winhlp': ['hlp'],
        'application/wsdl+xml': ['wsdl'],
        'application/wspolicy+xml': ['wspolicy'],
        'application/xaml+xml': ['xaml'],
        'application/xcap-att+xml': ['xav'],
        'application/xcap-caps+xml': ['xca'],
        'application/xcap-diff+xml': ['xdf'],
        'application/xcap-el+xml': ['xel'],
        'application/xcap-ns+xml': ['xns'],
        'application/xenc+xml': ['xenc'],
        'application/xhtml+xml': ['xhtml', 'xht'],
        'application/xliff+xml': ['xlf'],
        'application/xml': ['xml', 'xsl', 'xsd', 'rng'],
        'application/xml-dtd': ['dtd'],
        'application/xop+xml': ['xop'],
        'application/xproc+xml': ['xpl'],
        'application/xslt+xml': ['*xsl', 'xslt'],
        'application/xspf+xml': ['xspf'],
        'application/xv+xml': ['mxml', 'xhvml', 'xvml', 'xvm'],
        'application/yang': ['yang'],
        'application/yin+xml': ['yin'],
        'application/zip': ['zip'],
        'audio/3gpp': ['*3gpp'],
        'audio/adpcm': ['adp'],
        'audio/amr': ['amr'],
        'audio/basic': ['au', 'snd'],
        'audio/midi': ['mid', 'midi', 'kar', 'rmi'],
        'audio/mobile-xmf': ['mxmf'],
        'audio/mp3': ['*mp3'],
        'audio/mp4': ['m4a', 'mp4a'],
        'audio/mpeg': ['mpga', 'mp2', 'mp2a', 'mp3', 'm2a', 'm3a'],
        'audio/ogg': ['oga', 'ogg', 'spx', 'opus'],
        'audio/s3m': ['s3m'],
        'audio/silk': ['sil'],
        'audio/wav': ['wav'],
        'audio/wave': ['*wav'],
        'audio/webm': ['weba'],
        'audio/xm': ['xm'],
        'font/collection': ['ttc'],
        'font/otf': ['otf'],
        'font/ttf': ['ttf'],
        'font/woff': ['woff'],
        'font/woff2': ['woff2'],
        'image/aces': ['exr'],
        'image/apng': ['apng'],
        'image/avif': ['avif'],
        'image/bmp': ['bmp'],
        'image/cgm': ['cgm'],
        'image/dicom-rle': ['drle'],
        'image/emf': ['emf'],
        'image/fits': ['fits'],
        'image/g3fax': ['g3'],
        'image/gif': ['gif'],
        'image/heic': ['heic'],
        'image/heic-sequence': ['heics'],
        'image/heif': ['heif'],
        'image/heif-sequence': ['heifs'],
        'image/hej2k': ['hej2'],
        'image/hsj2': ['hsj2'],
        'image/ief': ['ief'],
        'image/jls': ['jls'],
        'image/jp2': ['jp2', 'jpg2'],
        'image/jpeg': ['jpeg', 'jpg', 'jpe'],
        'image/jph': ['jph'],
        'image/jphc': ['jhc'],
        'image/jpm': ['jpm'],
        'image/jpx': ['jpx', 'jpf'],
        'image/jxr': ['jxr'],
        'image/jxra': ['jxra'],
        'image/jxrs': ['jxrs'],
        'image/jxs': ['jxs'],
        'image/jxsc': ['jxsc'],
        'image/jxsi': ['jxsi'],
        'image/jxss': ['jxss'],
        'image/ktx': ['ktx'],
        'image/ktx2': ['ktx2'],
        'image/png': ['png'],
        'image/sgi': ['sgi'],
        'image/svg+xml': ['svg', 'svgz'],
        'image/t38': ['t38'],
        'image/tiff': ['tif', 'tiff'],
        'image/tiff-fx': ['tfx'],
        'image/webp': ['webp'],
        'image/wmf': ['wmf'],
        'message/disposition-notification': ['disposition-notification'],
        'message/global': ['u8msg'],
        'message/global-delivery-status': ['u8dsn'],
        'message/global-disposition-notification': ['u8mdn'],
        'message/global-headers': ['u8hdr'],
        'message/rfc822': ['eml', 'mime'],
        'model/3mf': ['3mf'],
        'model/gltf+json': ['gltf'],
        'model/gltf-binary': ['glb'],
        'model/iges': ['igs', 'iges'],
        'model/mesh': ['msh', 'mesh', 'silo'],
        'model/mtl': ['mtl'],
        'model/obj': ['obj'],
        'model/step+xml': ['stpx'],
        'model/step+zip': ['stpz'],
        'model/step-xml+zip': ['stpxz'],
        'model/stl': ['stl'],
        'model/vrml': ['wrl', 'vrml'],
        'model/x3d+binary': ['*x3db', 'x3dbz'],
        'model/x3d+fastinfoset': ['x3db'],
        'model/x3d+vrml': ['*x3dv', 'x3dvz'],
        'model/x3d+xml': ['x3d', 'x3dz'],
        'model/x3d-vrml': ['x3dv'],
        'text/cache-manifest': ['appcache', 'manifest'],
        'text/calendar': ['ics', 'ifb'],
        'text/coffeescript': ['coffee', 'litcoffee'],
        'text/css': ['css'],
        'text/csv': ['csv'],
        'text/html': ['html', 'htm', 'shtml'],
        'text/jade': ['jade'],
        'text/jsx': ['jsx'],
        'text/less': ['less'],
        'text/markdown': ['markdown', 'md'],
        'text/mathml': ['mml'],
        'text/mdx': ['mdx'],
        'text/n3': ['n3'],
        'text/plain': [
          'txt',
          'text',
          'conf',
          'def',
          'list',
          'log',
          'in',
          'ini',
        ],
        'text/richtext': ['rtx'],
        'text/rtf': ['*rtf'],
        'text/sgml': ['sgml', 'sgm'],
        'text/shex': ['shex'],
        'text/slim': ['slim', 'slm'],
        'text/spdx': ['spdx'],
        'text/stylus': ['stylus', 'styl'],
        'text/tab-separated-values': ['tsv'],
        'text/troff': ['t', 'tr', 'roff', 'man', 'me', 'ms'],
        'text/turtle': ['ttl'],
        'text/uri-list': ['uri', 'uris', 'urls'],
        'text/vcard': ['vcard'],
        'text/vtt': ['vtt'],
        'text/xml': ['*xml'],
        'text/yaml': ['yaml', 'yml'],
        'video/3gpp': ['3gp', '3gpp'],
        'video/3gpp2': ['3g2'],
        'video/h261': ['h261'],
        'video/h263': ['h263'],
        'video/h264': ['h264'],
        'video/iso.segment': ['m4s'],
        'video/jpeg': ['jpgv'],
        'video/jpm': ['*jpm', 'jpgm'],
        'video/mj2': ['mj2', 'mjp2'],
        'video/mp2t': ['ts'],
        'video/mp4': ['mp4', 'mp4v', 'mpg4'],
        'video/mpeg': ['mpeg', 'mpg', 'mpe', 'm1v', 'm2v'],
        'video/ogg': ['ogv'],
        'video/quicktime': ['qt', 'mov'],
        'video/webm': ['webm'],
      };

      /***/
    },

    /***/ 9691: /***/ (module) => {
      'use strict';

      function reusify(Constructor) {
        var head = new Constructor();
        var tail = head;

        function get() {
          var current = head;

          if (current.next) {
            head = current.next;
          } else {
            head = new Constructor();
            tail = head;
          }

          current.next = null;

          return current;
        }

        function release(obj) {
          tail.next = obj;
          tail = obj;
        }

        return {
          get: get,
          release: release,
        };
      }

      module.exports = reusify;

      /***/
    },

    /***/ 6671: /***/ (module, exports, __webpack_require__) => {
      /*! safe-buffer. MIT License. Feross Aboukhadijeh <https://feross.org/opensource> */
      /* eslint-disable node/no-deprecated-api */
      var buffer = __webpack_require__(181);
      var Buffer = buffer.Buffer;

      // alternative to using Object.keys for old browsers
      function copyProps(src, dst) {
        for (var key in src) {
          dst[key] = src[key];
        }
      }
      if (
        Buffer.from &&
        Buffer.alloc &&
        Buffer.allocUnsafe &&
        Buffer.allocUnsafeSlow
      ) {
        module.exports = buffer;
      } else {
        // Copy properties from require('buffer')
        copyProps(buffer, exports);
        exports.Buffer = SafeBuffer;
      }

      function SafeBuffer(arg, encodingOrOffset, length) {
        return Buffer(arg, encodingOrOffset, length);
      }

      SafeBuffer.prototype = Object.create(Buffer.prototype);

      // Copy static methods from Buffer
      copyProps(Buffer, SafeBuffer);

      SafeBuffer.from = function (arg, encodingOrOffset, length) {
        if (typeof arg === 'number') {
          throw new TypeError('Argument must not be a number');
        }
        return Buffer(arg, encodingOrOffset, length);
      };

      SafeBuffer.alloc = function (size, fill, encoding) {
        if (typeof size !== 'number') {
          throw new TypeError('Argument must be a number');
        }
        var buf = Buffer(size);
        if (fill !== undefined) {
          if (typeof encoding === 'string') {
            buf.fill(fill, encoding);
          } else {
            buf.fill(fill);
          }
        } else {
          buf.fill(0);
        }
        return buf;
      };

      SafeBuffer.allocUnsafe = function (size) {
        if (typeof size !== 'number') {
          throw new TypeError('Argument must be a number');
        }
        return Buffer(size);
      };

      SafeBuffer.allocUnsafeSlow = function (size) {
        if (typeof size !== 'number') {
          throw new TypeError('Argument must be a number');
        }
        return buffer.SlowBuffer(size);
      };

      /***/
    },

    /***/ 4144: /***/ (module) => {
      'use strict';

      /* eslint no-proto: 0 */
      module.exports =
        Object.setPrototypeOf ||
        ({ __proto__: [] } instanceof Array ? setProtoOf : mixinProperties);

      function setProtoOf(obj, proto) {
        obj.__proto__ = proto;
        return obj;
      }

      function mixinProperties(obj, proto) {
        for (var prop in proto) {
          if (!Object.prototype.hasOwnProperty.call(obj, prop)) {
            obj[prop] = proto[prop];
          }
        }
        return obj;
      }

      /***/
    },

    /***/ 9216: /***/ (
      module,
      __unused_webpack_exports,
      __webpack_require__,
    ) => {
      'use strict';
      /*!
       * statuses
       * Copyright(c) 2014 Jonathan Ong
       * Copyright(c) 2016 Douglas Christopher Wilson
       * MIT Licensed
       */

      /**
       * Module dependencies.
       * @private
       */

      var codes = __webpack_require__(1033);

      /**
       * Module exports.
       * @public
       */

      module.exports = status;

      // status code to message map
      status.message = codes;

      // status message (lower-case) to code map
      status.code = createMessageToStatusCodeMap(codes);

      // array of status codes
      status.codes = createStatusCodeList(codes);

      // status codes for redirects
      status.redirect = {
        300: true,
        301: true,
        302: true,
        303: true,
        305: true,
        307: true,
        308: true,
      };

      // status codes for empty bodies
      status.empty = {
        204: true,
        205: true,
        304: true,
      };

      // status codes for when you should retry the request
      status.retry = {
        502: true,
        503: true,
        504: true,
      };

      /**
       * Create a map of message to status code.
       * @private
       */

      function createMessageToStatusCodeMap(codes) {
        var map = {};

        Object.keys(codes).forEach(function forEachCode(code) {
          var message = codes[code];
          var status = Number(code);

          // populate map
          map[message.toLowerCase()] = status;
        });

        return map;
      }

      /**
       * Create a list of all status codes.
       * @private
       */

      function createStatusCodeList(codes) {
        return Object.keys(codes).map(function mapCode(code) {
          return Number(code);
        });
      }

      /**
       * Get the status code for given message.
       * @private
       */

      function getStatusCode(message) {
        var msg = message.toLowerCase();

        if (!Object.prototype.hasOwnProperty.call(status.code, msg)) {
          throw new Error('invalid status message: "' + message + '"');
        }

        return status.code[msg];
      }

      /**
       * Get the status message for given code.
       * @private
       */

      function getStatusMessage(code) {
        if (!Object.prototype.hasOwnProperty.call(status.message, code)) {
          throw new Error('invalid status code: ' + code);
        }

        return status.message[code];
      }

      /**
       * Get the status code.
       *
       * Given a number, this will throw if it is not a known status
       * code, otherwise the code will be returned. Given a string,
       * the string will be parsed for a number and return the code
       * if valid, otherwise will lookup the code assuming this is
       * the status message.
       *
       * @param {string|number} code
       * @returns {number}
       * @public
       */

      function status(code) {
        if (typeof code === 'number') {
          return getStatusMessage(code);
        }

        if (typeof code !== 'string') {
          throw new TypeError('code must be a number or string');
        }

        // '403'
        var n = parseInt(code, 10);
        if (!isNaN(n)) {
          return getStatusMessage(n);
        }

        return getStatusCode(code);
      }

      /***/
    },

    /***/ 5237: /***/ (module) => {
      'use strict';
      /*!
       * toidentifier
       * Copyright(c) 2016 Douglas Christopher Wilson
       * MIT Licensed
       */

      /**
       * Module exports.
       * @public
       */

      module.exports = toIdentifier;

      /**
       * Trasform the given string into a JavaScript identifier
       *
       * @param {string} str
       * @returns {string}
       * @public
       */

      function toIdentifier(str) {
        return str
          .split(' ')
          .map(function (token) {
            return token.slice(0, 1).toUpperCase() + token.slice(1);
          })
          .join('')
          .replace(/[^ _0-9a-z]/gi, '');
      }

      /***/
    },

    /***/ 5289: /***/ function (
      __unused_webpack_module,
      exports,
      __webpack_require__,
    ) {
      'use strict';

      var __decorate =
        (this && this.__decorate) ||
        function (decorators, target, key, desc) {
          var c = arguments.length,
            r =
              c < 3
                ? target
                : desc === null
                  ? (desc = Object.getOwnPropertyDescriptor(target, key))
                  : desc,
            d;
          if (
            typeof Reflect === 'object' &&
            typeof Reflect.decorate === 'function'
          )
            r = Reflect.decorate(decorators, target, key, desc);
          else
            for (var i = decorators.length - 1; i >= 0; i--)
              if ((d = decorators[i]))
                r =
                  (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) ||
                  r;
          return c > 3 && r && Object.defineProperty(target, key, r), r;
        };
      var __metadata =
        (this && this.__metadata) ||
        function (k, v) {
          if (
            typeof Reflect === 'object' &&
            typeof Reflect.metadata === 'function'
          )
            return Reflect.metadata(k, v);
        };
      var __param =
        (this && this.__param) ||
        function (paramIndex, decorator) {
          return function (target, key) {
            decorator(target, key, paramIndex);
          };
        };
      var _a;
      Object.defineProperty(exports, '__esModule', { value: true });
      exports.DemoController = void 0;
      const common_1 = __webpack_require__(3563);
      const demo_service_1 = __webpack_require__(2266);
      const skip_transform_decorator_1 = __webpack_require__(6536);
      let DemoController = class DemoController {
        constructor(demoService) {
          this.demoService = demoService;
        }
        getHello() {
          return this.demoService.getHello();
        }
        postHello() {
          return this.demoService.postHello();
        }
        getError() {
          return this.demoService.getError();
        }
        postError() {
          return this.demoService.postError();
        }
        getParams(query) {
          return this.demoService.getParams(query);
        }
        postParams(body) {
          return this.demoService.postParams(body);
        }
      };
      exports.DemoController = DemoController;
      __decorate(
        [
          (0, common_1.Get)(),
          __metadata('design:type', Function),
          __metadata('design:paramtypes', []),
          __metadata('design:returntype', void 0),
        ],
        DemoController.prototype,
        'getHello',
        null,
      );
      __decorate(
        [
          (0, common_1.Post)(),
          __metadata('design:type', Function),
          __metadata('design:paramtypes', []),
          __metadata('design:returntype', void 0),
        ],
        DemoController.prototype,
        'postHello',
        null,
      );
      __decorate(
        [
          (0, common_1.Get)('error'),
          __metadata('design:type', Function),
          __metadata('design:paramtypes', []),
          __metadata('design:returntype', void 0),
        ],
        DemoController.prototype,
        'getError',
        null,
      );
      __decorate(
        [
          (0, common_1.Post)('error'),
          (0, skip_transform_decorator_1.SkipTransform)(),
          __metadata('design:type', Function),
          __metadata('design:paramtypes', []),
          __metadata('design:returntype', void 0),
        ],
        DemoController.prototype,
        'postError',
        null,
      );
      __decorate(
        [
          (0, common_1.Get)('params'),
          __param(0, (0, common_1.Query)()),
          __metadata('design:type', Function),
          __metadata('design:paramtypes', [Object]),
          __metadata('design:returntype', void 0),
        ],
        DemoController.prototype,
        'getParams',
        null,
      );
      __decorate(
        [
          (0, common_1.Post)('params'),
          __param(0, (0, common_1.Body)()),
          __metadata('design:type', Function),
          __metadata('design:paramtypes', [Object]),
          __metadata('design:returntype', void 0),
        ],
        DemoController.prototype,
        'postParams',
        null,
      );
      exports.DemoController = DemoController = __decorate(
        [
          (0, common_1.Controller)(),
          __metadata('design:paramtypes', [
            typeof (_a =
              typeof demo_service_1.DemoService !== 'undefined' &&
              demo_service_1.DemoService) === 'function'
              ? _a
              : Object,
          ]),
        ],
        DemoController,
      );

      /***/
    },

    /***/ 9993: /***/ function (
      __unused_webpack_module,
      exports,
      __webpack_require__,
    ) {
      'use strict';

      var __decorate =
        (this && this.__decorate) ||
        function (decorators, target, key, desc) {
          var c = arguments.length,
            r =
              c < 3
                ? target
                : desc === null
                  ? (desc = Object.getOwnPropertyDescriptor(target, key))
                  : desc,
            d;
          if (
            typeof Reflect === 'object' &&
            typeof Reflect.decorate === 'function'
          )
            r = Reflect.decorate(decorators, target, key, desc);
          else
            for (var i = decorators.length - 1; i >= 0; i--)
              if ((d = decorators[i]))
                r =
                  (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) ||
                  r;
          return c > 3 && r && Object.defineProperty(target, key, r), r;
        };
      Object.defineProperty(exports, '__esModule', { value: true });
      exports.DemoModule = void 0;
      const common_1 = __webpack_require__(3563);
      const demo_controller_1 = __webpack_require__(5289);
      const demo_service_1 = __webpack_require__(2266);
      let DemoModule = class DemoModule {};
      exports.DemoModule = DemoModule;
      exports.DemoModule = DemoModule = __decorate(
        [
          (0, common_1.Module)({
            controllers: [demo_controller_1.DemoController],
            providers: [demo_service_1.DemoService],
          }),
        ],
        DemoModule,
      );

      /***/
    },

    /***/ 2266: /***/ function (
      __unused_webpack_module,
      exports,
      __webpack_require__,
    ) {
      'use strict';

      var __decorate =
        (this && this.__decorate) ||
        function (decorators, target, key, desc) {
          var c = arguments.length,
            r =
              c < 3
                ? target
                : desc === null
                  ? (desc = Object.getOwnPropertyDescriptor(target, key))
                  : desc,
            d;
          if (
            typeof Reflect === 'object' &&
            typeof Reflect.decorate === 'function'
          )
            r = Reflect.decorate(decorators, target, key, desc);
          else
            for (var i = decorators.length - 1; i >= 0; i--)
              if ((d = decorators[i]))
                r =
                  (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) ||
                  r;
          return c > 3 && r && Object.defineProperty(target, key, r), r;
        };
      var __metadata =
        (this && this.__metadata) ||
        function (k, v) {
          if (
            typeof Reflect === 'object' &&
            typeof Reflect.metadata === 'function'
          )
            return Reflect.metadata(k, v);
        };
      var _a;
      Object.defineProperty(exports, '__esModule', { value: true });
      exports.DemoService = void 0;
      const common_1 = __webpack_require__(3563);
      const logger_service_1 = __webpack_require__(6417);
      const transform_interceptor_1 = __webpack_require__(6150);
      let DemoService = class DemoService {
        constructor(logger) {
          this.logger = logger;
        }
        getHello() {
          this.logger.log('Getting hello message', 'DemoService');
          return new transform_interceptor_1.CustomResponse(
            'Hello World',
            '请求成功',
            '2000',
          );
        }
        postHello() {
          this.logger.log('post hello message', 'DemoService');
          return 'post hello';
        }
        getError() {
          this.logger.error('get error message', 'DemoService');
          return '错误原因.....';
        }
        postError() {
          this.logger.error('post error message', 'DemoService');
          return '错误原因(跳过序列化).....';
        }
        getParams(query) {
          console.log('======query====', query);
          this.logger.log('get params message', 'DemoService');
          return query;
        }
        postParams(body) {
          console.log('======获取form-urlencoded====', body);
          this.logger.log('post params message', 'DemoService');
          return body;
        }
      };
      exports.DemoService = DemoService;
      exports.DemoService = DemoService = __decorate(
        [
          (0, common_1.Injectable)(),
          __metadata('design:paramtypes', [
            typeof (_a =
              typeof logger_service_1.LoggerService !== 'undefined' &&
              logger_service_1.LoggerService) === 'function'
              ? _a
              : Object,
          ]),
        ],
        DemoService,
      );

      /***/
    },

    /***/ 9000: /***/ function (
      __unused_webpack_module,
      exports,
      __webpack_require__,
    ) {
      'use strict';

      var __decorate =
        (this && this.__decorate) ||
        function (decorators, target, key, desc) {
          var c = arguments.length,
            r =
              c < 3
                ? target
                : desc === null
                  ? (desc = Object.getOwnPropertyDescriptor(target, key))
                  : desc,
            d;
          if (
            typeof Reflect === 'object' &&
            typeof Reflect.decorate === 'function'
          )
            r = Reflect.decorate(decorators, target, key, desc);
          else
            for (var i = decorators.length - 1; i >= 0; i--)
              if ((d = decorators[i]))
                r =
                  (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) ||
                  r;
          return c > 3 && r && Object.defineProperty(target, key, r), r;
        };
      Object.defineProperty(exports, '__esModule', { value: true });
      exports.V1Module = void 0;
      const common_1 = __webpack_require__(3563);
      const core_1 = __webpack_require__(8781);
      const demo_module_1 = __webpack_require__(9993);
      let V1Module = class V1Module {};
      exports.V1Module = V1Module;
      exports.V1Module = V1Module = __decorate(
        [
          (0, common_1.Module)({
            imports: [
              demo_module_1.DemoModule,
              core_1.RouterModule.register([
                {
                  path: 'v1',
                  children: [
                    { path: 'demo', module: demo_module_1.DemoModule },
                  ],
                },
              ]),
            ],
          }),
        ],
        V1Module,
      );

      /***/
    },

    /***/ 3004: /***/ function (
      __unused_webpack_module,
      exports,
      __webpack_require__,
    ) {
      'use strict';

      var __decorate =
        (this && this.__decorate) ||
        function (decorators, target, key, desc) {
          var c = arguments.length,
            r =
              c < 3
                ? target
                : desc === null
                  ? (desc = Object.getOwnPropertyDescriptor(target, key))
                  : desc,
            d;
          if (
            typeof Reflect === 'object' &&
            typeof Reflect.decorate === 'function'
          )
            r = Reflect.decorate(decorators, target, key, desc);
          else
            for (var i = decorators.length - 1; i >= 0; i--)
              if ((d = decorators[i]))
                r =
                  (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) ||
                  r;
          return c > 3 && r && Object.defineProperty(target, key, r), r;
        };
      Object.defineProperty(exports, '__esModule', { value: true });
      exports.AppModule = void 0;
      const common_1 = __webpack_require__(3563);
      const logger_module_1 = __webpack_require__(7984);
      const prisma_module_1 = __webpack_require__(4620);
      const all_exception_filter_1 = __webpack_require__(4521);
      const http_exception_filter_1 = __webpack_require__(5278);
      const index_1 = __webpack_require__(9000);
      const core_1 = __webpack_require__(8781);
      const NODE_ENV = true ? 'production' : 0;
      console.log('=========NODE_ENV==========', NODE_ENV);
      let AppModule = class AppModule {};
      exports.AppModule = AppModule;
      exports.AppModule = AppModule = __decorate(
        [
          (0, common_1.Module)({
            imports: [
              prisma_module_1.PrismaModule,
              logger_module_1.LoggerModule,
              index_1.V1Module,
            ],
            providers: [
              {
                provide: core_1.APP_FILTER,
                useClass: all_exception_filter_1.AllExceptionFilter,
              },
              {
                provide: core_1.APP_FILTER,
                useClass: http_exception_filter_1.HttpExceptionFilter,
              },
            ],
          }),
        ],
        AppModule,
      );

      /***/
    },

    /***/ 7984: /***/ function (
      __unused_webpack_module,
      exports,
      __webpack_require__,
    ) {
      'use strict';

      var __decorate =
        (this && this.__decorate) ||
        function (decorators, target, key, desc) {
          var c = arguments.length,
            r =
              c < 3
                ? target
                : desc === null
                  ? (desc = Object.getOwnPropertyDescriptor(target, key))
                  : desc,
            d;
          if (
            typeof Reflect === 'object' &&
            typeof Reflect.decorate === 'function'
          )
            r = Reflect.decorate(decorators, target, key, desc);
          else
            for (var i = decorators.length - 1; i >= 0; i--)
              if ((d = decorators[i]))
                r =
                  (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) ||
                  r;
          return c > 3 && r && Object.defineProperty(target, key, r), r;
        };
      Object.defineProperty(exports, '__esModule', { value: true });
      exports.LoggerModule = void 0;
      const common_1 = __webpack_require__(3563);
      const logger_service_1 = __webpack_require__(6417);
      let LoggerModule = class LoggerModule {};
      exports.LoggerModule = LoggerModule;
      exports.LoggerModule = LoggerModule = __decorate(
        [
          (0, common_1.Global)(),
          (0, common_1.Module)({
            providers: [logger_service_1.LoggerService],
            exports: [logger_service_1.LoggerService],
          }),
        ],
        LoggerModule,
      );

      /***/
    },

    /***/ 6417: /***/ function (
      __unused_webpack_module,
      exports,
      __webpack_require__,
    ) {
      'use strict';

      var __decorate =
        (this && this.__decorate) ||
        function (decorators, target, key, desc) {
          var c = arguments.length,
            r =
              c < 3
                ? target
                : desc === null
                  ? (desc = Object.getOwnPropertyDescriptor(target, key))
                  : desc,
            d;
          if (
            typeof Reflect === 'object' &&
            typeof Reflect.decorate === 'function'
          )
            r = Reflect.decorate(decorators, target, key, desc);
          else
            for (var i = decorators.length - 1; i >= 0; i--)
              if ((d = decorators[i]))
                r =
                  (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) ||
                  r;
          return c > 3 && r && Object.defineProperty(target, key, r), r;
        };
      var __metadata =
        (this && this.__metadata) ||
        function (k, v) {
          if (
            typeof Reflect === 'object' &&
            typeof Reflect.metadata === 'function'
          )
            return Reflect.metadata(k, v);
        };
      Object.defineProperty(exports, '__esModule', { value: true });
      exports.LoggerService = void 0;
      const common_1 = __webpack_require__(3563);
      const winston = __webpack_require__(5124);
      const path = __webpack_require__(6928);
      const DailyRotateFile = __webpack_require__(9233);
      const LOG_DIR = 'logs';
      let LoggerService = class LoggerService {
        constructor() {
          this.logger = winston.createLogger({
            level: 'info',
            format: winston.format.combine(
              winston.format.timestamp(),
              winston.format.json(),
            ),
            transports: [
              new DailyRotateFile({
                dirname: path.join(LOG_DIR, 'error'),
                filename: 'error-%DATE%.log',
                datePattern: 'YYYY-MM-DD',
                level: 'error',
                maxSize: '20m',
                maxFiles: '14d',
              }),
              new DailyRotateFile({
                dirname: path.join(LOG_DIR, 'combined'),
                filename: 'combined-%DATE%.log',
                datePattern: 'YYYY-MM-DD',
                maxSize: '20m',
                maxFiles: '14d',
              }),
            ],
          });
          if (false) {
          }
        }
        log(message, context) {
          this.logger.info(message, { context });
        }
        error(message, trace, context) {
          this.logger.error(message, { trace, context });
        }
        warn(message, context) {
          this.logger.warn(message, { context });
        }
        debug(message, context) {
          this.logger.debug(message, { context });
        }
        verbose(message, context) {
          this.logger.verbose(message, { context });
        }
      };
      exports.LoggerService = LoggerService;
      exports.LoggerService = LoggerService = __decorate(
        [(0, common_1.Injectable)(), __metadata('design:paramtypes', [])],
        LoggerService,
      );

      /***/
    },

    /***/ 4620: /***/ function (
      __unused_webpack_module,
      exports,
      __webpack_require__,
    ) {
      'use strict';

      var __decorate =
        (this && this.__decorate) ||
        function (decorators, target, key, desc) {
          var c = arguments.length,
            r =
              c < 3
                ? target
                : desc === null
                  ? (desc = Object.getOwnPropertyDescriptor(target, key))
                  : desc,
            d;
          if (
            typeof Reflect === 'object' &&
            typeof Reflect.decorate === 'function'
          )
            r = Reflect.decorate(decorators, target, key, desc);
          else
            for (var i = decorators.length - 1; i >= 0; i--)
              if ((d = decorators[i]))
                r =
                  (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) ||
                  r;
          return c > 3 && r && Object.defineProperty(target, key, r), r;
        };
      Object.defineProperty(exports, '__esModule', { value: true });
      exports.PrismaModule = void 0;
      const common_1 = __webpack_require__(3563);
      const prisma_service_1 = __webpack_require__(2733);
      const logger_service_1 = __webpack_require__(6417);
      let PrismaModule = class PrismaModule {};
      exports.PrismaModule = PrismaModule;
      exports.PrismaModule = PrismaModule = __decorate(
        [
          (0, common_1.Global)(),
          (0, common_1.Module)({
            providers: [
              prisma_service_1.PrismaService,
              logger_service_1.LoggerService,
            ],
            exports: [prisma_service_1.PrismaService],
          }),
        ],
        PrismaModule,
      );

      /***/
    },

    /***/ 2733: /***/ function (
      __unused_webpack_module,
      exports,
      __webpack_require__,
    ) {
      'use strict';

      var __decorate =
        (this && this.__decorate) ||
        function (decorators, target, key, desc) {
          var c = arguments.length,
            r =
              c < 3
                ? target
                : desc === null
                  ? (desc = Object.getOwnPropertyDescriptor(target, key))
                  : desc,
            d;
          if (
            typeof Reflect === 'object' &&
            typeof Reflect.decorate === 'function'
          )
            r = Reflect.decorate(decorators, target, key, desc);
          else
            for (var i = decorators.length - 1; i >= 0; i--)
              if ((d = decorators[i]))
                r =
                  (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) ||
                  r;
          return c > 3 && r && Object.defineProperty(target, key, r), r;
        };
      var __metadata =
        (this && this.__metadata) ||
        function (k, v) {
          if (
            typeof Reflect === 'object' &&
            typeof Reflect.metadata === 'function'
          )
            return Reflect.metadata(k, v);
        };
      var _a;
      Object.defineProperty(exports, '__esModule', { value: true });
      exports.PrismaService = void 0;
      const common_1 = __webpack_require__(3563);
      const client_1 = __webpack_require__(6330);
      const logger_service_1 = __webpack_require__(6417);
      let PrismaService = class PrismaService extends client_1.PrismaClient {
        constructor(logger) {
          super({
            log: [
              { emit: 'event', level: 'query' },
              { emit: 'event', level: 'info' },
              { emit: 'event', level: 'warn' },
              { emit: 'event', level: 'error' },
            ],
          });
          this.logger = logger;
          this.$on('query', (e) => {
            this.logger.debug(`Query: ${e.query}`, 'PrismaService');
          });
          this.$on('info', (e) => {
            this.logger.log(`${e.message}`, 'PrismaService');
          });
          this.$on('warn', (e) => {
            this.logger.warn(`${e.message}`, 'PrismaService');
          });
          this.$on('error', (e) => {
            this.logger.error(`${e.message}`, null, 'PrismaService');
          });
        }
        async onModuleInit() {
          console.group('this must be cancelled');
          this.logger.log('Database connected successfully', 'PrismaService');
        }
        async onModuleDestroy() {
          await this.$disconnect();
          this.logger.log(
            'Database disconnected successfully',
            'PrismaService',
          );
        }
      };
      exports.PrismaService = PrismaService;
      exports.PrismaService = PrismaService = __decorate(
        [
          (0, common_1.Injectable)(),
          __metadata('design:paramtypes', [
            typeof (_a =
              typeof logger_service_1.LoggerService !== 'undefined' &&
              logger_service_1.LoggerService) === 'function'
              ? _a
              : Object,
          ]),
        ],
        PrismaService,
      );

      /***/
    },

    /***/ 6536: /***/ (
      __unused_webpack_module,
      exports,
      __webpack_require__,
    ) => {
      'use strict';

      Object.defineProperty(exports, '__esModule', { value: true });
      exports.SkipTransform = exports.SKIP_TRANSFORM_KEY = void 0;
      const common_1 = __webpack_require__(3563);
      exports.SKIP_TRANSFORM_KEY = 'skipTransform';
      const SkipTransform = () =>
        (0, common_1.SetMetadata)(exports.SKIP_TRANSFORM_KEY, true);
      exports.SkipTransform = SkipTransform;

      /***/
    },

    /***/ 4521: /***/ function (
      __unused_webpack_module,
      exports,
      __webpack_require__,
    ) {
      'use strict';

      var __decorate =
        (this && this.__decorate) ||
        function (decorators, target, key, desc) {
          var c = arguments.length,
            r =
              c < 3
                ? target
                : desc === null
                  ? (desc = Object.getOwnPropertyDescriptor(target, key))
                  : desc,
            d;
          if (
            typeof Reflect === 'object' &&
            typeof Reflect.decorate === 'function'
          )
            r = Reflect.decorate(decorators, target, key, desc);
          else
            for (var i = decorators.length - 1; i >= 0; i--)
              if ((d = decorators[i]))
                r =
                  (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) ||
                  r;
          return c > 3 && r && Object.defineProperty(target, key, r), r;
        };
      var __metadata =
        (this && this.__metadata) ||
        function (k, v) {
          if (
            typeof Reflect === 'object' &&
            typeof Reflect.metadata === 'function'
          )
            return Reflect.metadata(k, v);
        };
      var _a, _b;
      Object.defineProperty(exports, '__esModule', { value: true });
      exports.AllExceptionFilter = void 0;
      const common_1 = __webpack_require__(3563);
      const core_1 = __webpack_require__(8781);
      const library_1 = __webpack_require__(6541);
      const logger_service_1 = __webpack_require__(6417);
      let AllExceptionFilter = class AllExceptionFilter {
        constructor(httpAdapterHost, logger) {
          this.httpAdapterHost = httpAdapterHost;
          this.logger = logger;
        }
        catch(exception, host) {
          const { httpAdapter } = this.httpAdapterHost;
          const ctx = host.switchToHttp();
          let statusCode = common_1.HttpStatus.INTERNAL_SERVER_ERROR;
          let message;
          let code;
          if (exception instanceof common_1.BadRequestException) {
            statusCode = common_1.HttpStatus.BAD_REQUEST;
            const response = exception.getResponse();
            message = Array.isArray(response.message)
              ? response.message.join(', ')
              : response.message || '请求参数验证失败';
            code = 'VALIDATION_ERROR';
          } else if (
            exception instanceof library_1.PrismaClientKnownRequestError
          ) {
            const prismaError = exception;
            switch (prismaError.code) {
              case 'P2002':
                statusCode = common_1.HttpStatus.CONFLICT;
                message = '数据已存在';
                code = 'PRISMA_P2002';
                break;
              case 'P2025':
                statusCode = common_1.HttpStatus.NOT_FOUND;
                message = '记录不存在';
                code = 'PRISMA_P2025';
                break;
              default:
                message = '数据库操作错误';
                code = `PRISMA_${prismaError.code}`;
            }
          } else {
            message =
              exception instanceof Error ? exception.message : '服务器内部错误';
            code = 'INTERNAL_SERVER_ERROR';
          }
          this.logger.error(
            message,
            exception instanceof Error ? exception.stack : undefined,
            'AllExceptionFilter',
          );
          const responseBody = {
            code,
            message,
            timestamp: new Date().toISOString(),
            path: httpAdapter.getRequestUrl(ctx.getRequest()),
          };
          httpAdapter.reply(ctx.getResponse(), responseBody, statusCode);
        }
      };
      exports.AllExceptionFilter = AllExceptionFilter;
      exports.AllExceptionFilter = AllExceptionFilter = __decorate(
        [
          (0, common_1.Catch)(),
          __metadata('design:paramtypes', [
            typeof (_a =
              typeof core_1.HttpAdapterHost !== 'undefined' &&
              core_1.HttpAdapterHost) === 'function'
              ? _a
              : Object,
            typeof (_b =
              typeof logger_service_1.LoggerService !== 'undefined' &&
              logger_service_1.LoggerService) === 'function'
              ? _b
              : Object,
          ]),
        ],
        AllExceptionFilter,
      );

      /***/
    },

    /***/ 5278: /***/ function (
      __unused_webpack_module,
      exports,
      __webpack_require__,
    ) {
      'use strict';

      var __decorate =
        (this && this.__decorate) ||
        function (decorators, target, key, desc) {
          var c = arguments.length,
            r =
              c < 3
                ? target
                : desc === null
                  ? (desc = Object.getOwnPropertyDescriptor(target, key))
                  : desc,
            d;
          if (
            typeof Reflect === 'object' &&
            typeof Reflect.decorate === 'function'
          )
            r = Reflect.decorate(decorators, target, key, desc);
          else
            for (var i = decorators.length - 1; i >= 0; i--)
              if ((d = decorators[i]))
                r =
                  (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) ||
                  r;
          return c > 3 && r && Object.defineProperty(target, key, r), r;
        };
      var __metadata =
        (this && this.__metadata) ||
        function (k, v) {
          if (
            typeof Reflect === 'object' &&
            typeof Reflect.metadata === 'function'
          )
            return Reflect.metadata(k, v);
        };
      var _a;
      Object.defineProperty(exports, '__esModule', { value: true });
      exports.HttpExceptionFilter = void 0;
      const common_1 = __webpack_require__(3563);
      const logger_service_1 = __webpack_require__(6417);
      let HttpExceptionFilter = class HttpExceptionFilter {
        constructor(logger) {
          this.logger = logger;
        }
        catch(exception, host) {
          const ctx = host.switchToHttp();
          const response = ctx.getResponse();
          const request = ctx.getRequest();
          const status = exception.getStatus();
          const exceptionResponse = exception.getResponse();
          let errorMessage;
          let errorCode;
          if (request.url === '/favicon.ico' && status === 404) {
            return response.status(204).send();
          }
          if (typeof exceptionResponse === 'string') {
            errorMessage = exceptionResponse;
            errorCode = `HTTP_${status}`;
          } else {
            const response = exceptionResponse;
            errorMessage = response.message || '请求失败';
            errorCode = response.code || `HTTP_${status}`;
          }
          this.logger.error(
            errorMessage,
            exception.stack,
            'HttpExceptionFilter',
          );
          response.status(status).send({
            code: errorCode,
            message: errorMessage,
            timestamp: new Date().toISOString(),
            path: request.url,
          });
        }
      };
      exports.HttpExceptionFilter = HttpExceptionFilter;
      exports.HttpExceptionFilter = HttpExceptionFilter = __decorate(
        [
          (0, common_1.Catch)(common_1.HttpException),
          __metadata('design:paramtypes', [
            typeof (_a =
              typeof logger_service_1.LoggerService !== 'undefined' &&
              logger_service_1.LoggerService) === 'function'
              ? _a
              : Object,
          ]),
        ],
        HttpExceptionFilter,
      );

      /***/
    },

    /***/ 17: /***/ function (
      __unused_webpack_module,
      exports,
      __webpack_require__,
    ) {
      'use strict';

      var __decorate =
        (this && this.__decorate) ||
        function (decorators, target, key, desc) {
          var c = arguments.length,
            r =
              c < 3
                ? target
                : desc === null
                  ? (desc = Object.getOwnPropertyDescriptor(target, key))
                  : desc,
            d;
          if (
            typeof Reflect === 'object' &&
            typeof Reflect.decorate === 'function'
          )
            r = Reflect.decorate(decorators, target, key, desc);
          else
            for (var i = decorators.length - 1; i >= 0; i--)
              if ((d = decorators[i]))
                r =
                  (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) ||
                  r;
          return c > 3 && r && Object.defineProperty(target, key, r), r;
        };
      var __metadata =
        (this && this.__metadata) ||
        function (k, v) {
          if (
            typeof Reflect === 'object' &&
            typeof Reflect.metadata === 'function'
          )
            return Reflect.metadata(k, v);
        };
      Object.defineProperty(exports, '__esModule', { value: true });
      exports.TimeoutInterceptor = void 0;
      const common_1 = __webpack_require__(3563);
      const rxjs_1 = __webpack_require__(573);
      const operators_1 = __webpack_require__(603);
      let TimeoutInterceptor = class TimeoutInterceptor {
        constructor(timeoutMs = 5000) {
          this.timeoutMs = timeoutMs;
        }
        intercept(context, next) {
          return next.handle().pipe(
            (0, operators_1.timeout)(this.timeoutMs),
            (0, operators_1.catchError)((err) => {
              if (err instanceof rxjs_1.TimeoutError) {
                return (0, rxjs_1.throwError)(
                  () =>
                    new common_1.RequestTimeoutException({
                      message: 'Request timeout',
                      code: '408',
                      data: '',
                      timestamp: new Date().toISOString(),
                    }),
                );
              }
              return (0, rxjs_1.throwError)(() => err);
            }),
          );
        }
      };
      exports.TimeoutInterceptor = TimeoutInterceptor;
      exports.TimeoutInterceptor = TimeoutInterceptor = __decorate(
        [(0, common_1.Injectable)(), __metadata('design:paramtypes', [Number])],
        TimeoutInterceptor,
      );

      /***/
    },

    /***/ 6150: /***/ function (
      __unused_webpack_module,
      exports,
      __webpack_require__,
    ) {
      'use strict';

      var __decorate =
        (this && this.__decorate) ||
        function (decorators, target, key, desc) {
          var c = arguments.length,
            r =
              c < 3
                ? target
                : desc === null
                  ? (desc = Object.getOwnPropertyDescriptor(target, key))
                  : desc,
            d;
          if (
            typeof Reflect === 'object' &&
            typeof Reflect.decorate === 'function'
          )
            r = Reflect.decorate(decorators, target, key, desc);
          else
            for (var i = decorators.length - 1; i >= 0; i--)
              if ((d = decorators[i]))
                r =
                  (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) ||
                  r;
          return c > 3 && r && Object.defineProperty(target, key, r), r;
        };
      var __metadata =
        (this && this.__metadata) ||
        function (k, v) {
          if (
            typeof Reflect === 'object' &&
            typeof Reflect.metadata === 'function'
          )
            return Reflect.metadata(k, v);
        };
      var _a;
      Object.defineProperty(exports, '__esModule', { value: true });
      exports.TransformInterceptor = exports.CustomResponse = void 0;
      const common_1 = __webpack_require__(3563);
      const operators_1 = __webpack_require__(603);
      const core_1 = __webpack_require__(8781);
      const skip_transform_decorator_1 = __webpack_require__(6536);
      class CustomResponse {
        constructor(data, message = '请求成功', code = 'SUCCESS') {
          this.data = data;
          this.message = message;
          this.code = code;
        }
      }
      exports.CustomResponse = CustomResponse;
      let TransformInterceptor = class TransformInterceptor {
        constructor(reflector) {
          this.reflector = reflector;
        }
        intercept(context, next) {
          const skipTransform = this.reflector.get(
            skip_transform_decorator_1.SKIP_TRANSFORM_KEY,
            context.getHandler(),
          );
          if (skipTransform) {
            return next.handle();
          }
          return next.handle().pipe(
            (0, operators_1.map)((data) => {
              if (data instanceof CustomResponse) {
                return {
                  code: data.code,
                  data: data.data,
                  message: data.message,
                  timestamp: new Date().toISOString(),
                };
              }
              return {
                code: 'SUCCESS',
                data,
                message: '请求成功',
                timestamp: new Date().toISOString(),
              };
            }),
          );
        }
      };
      exports.TransformInterceptor = TransformInterceptor;
      exports.TransformInterceptor = TransformInterceptor = __decorate(
        [
          (0, common_1.Injectable)(),
          __metadata('design:paramtypes', [
            typeof (_a =
              typeof core_1.Reflector !== 'undefined' && core_1.Reflector) ===
            'function'
              ? _a
              : Object,
          ]),
        ],
        TransformInterceptor,
      );

      /***/
    },

    /***/ 3563: /***/ (module) => {
      'use strict';
      module.exports = require('@nestjs/common');

      /***/
    },

    /***/ 8781: /***/ (module) => {
      'use strict';
      module.exports = require('@nestjs/core');

      /***/
    },

    /***/ 5560: /***/ (module) => {
      'use strict';
      module.exports = require('@nestjs/platform-fastify');

      /***/
    },

    /***/ 9742: /***/ (module) => {
      'use strict';
      module.exports = require('@nestjs/swagger');

      /***/
    },

    /***/ 6330: /***/ (module) => {
      'use strict';
      module.exports = require('@prisma/client');

      /***/
    },

    /***/ 6541: /***/ (module) => {
      'use strict';
      module.exports = require('@prisma/client/runtime/library');

      /***/
    },

    /***/ 573: /***/ (module) => {
      'use strict';
      module.exports = require('rxjs');

      /***/
    },

    /***/ 603: /***/ (module) => {
      'use strict';
      module.exports = require('rxjs/operators');

      /***/
    },

    /***/ 5124: /***/ (module) => {
      'use strict';
      module.exports = require('winston');

      /***/
    },

    /***/ 9233: /***/ (module) => {
      'use strict';
      module.exports = require('winston-daily-rotate-file');

      /***/
    },

    /***/ 181: /***/ (module) => {
      'use strict';
      module.exports = require('buffer');

      /***/
    },

    /***/ 9896: /***/ (module) => {
      'use strict';
      module.exports = require('fs');

      /***/
    },

    /***/ 8474: /***/ (module) => {
      'use strict';
      module.exports = require('node:events');

      /***/
    },

    /***/ 3024: /***/ (module) => {
      'use strict';
      module.exports = require('node:fs');

      /***/
    },

    /***/ 1455: /***/ (module) => {
      'use strict';
      module.exports = require('node:fs/promises');

      /***/
    },

    /***/ 8161: /***/ (module) => {
      'use strict';
      module.exports = require('node:os');

      /***/
    },

    /***/ 6760: /***/ (module) => {
      'use strict';
      module.exports = require('node:path');

      /***/
    },

    /***/ 7075: /***/ (module) => {
      'use strict';
      module.exports = require('node:stream');

      /***/
    },

    /***/ 6193: /***/ (module) => {
      'use strict';
      module.exports = require('node:string_decoder');

      /***/
    },

    /***/ 3136: /***/ (module) => {
      'use strict';
      module.exports = require('node:url');

      /***/
    },

    /***/ 7975: /***/ (module) => {
      'use strict';
      module.exports = require('node:util');

      /***/
    },

    /***/ 6928: /***/ (module) => {
      'use strict';
      module.exports = require('path');

      /***/
    },

    /***/ 9023: /***/ (module) => {
      'use strict';
      module.exports = require('util');

      /***/
    },

    /***/ 4102: /***/ (module) => {
      'use strict';

      function Negotiator(options) {
        if (!new.target) {
          return new Negotiator(options);
        }

        const { supportedValues = [], cache } =
          (options && typeof options === 'object' && options) || {};

        this.supportedValues = supportedValues;

        this.cache = cache;
      }

      Negotiator.prototype.negotiate = function (header) {
        if (typeof header !== 'string') {
          return null;
        }
        if (!this.cache) {
          return negotiate(header, this.supportedValues);
        }
        if (!this.cache.has(header)) {
          this.cache.set(header, negotiate(header, this.supportedValues));
        }
        return this.cache.get(header);
      };

      function negotiate(header, supportedValues) {
        if (
          !header ||
          !Array.isArray(supportedValues) ||
          supportedValues.length === 0
        ) {
          return null;
        }

        if (header === '*') {
          return supportedValues[0];
        }

        let preferredEncoding = null;
        let preferredEncodingPriority = Infinity;
        let preferredEncodingQuality = 0;

        function processMatch(enc, quality) {
          if (quality === 0 || preferredEncodingQuality > quality) {
            return false;
          }

          const encoding = (enc === '*' && supportedValues[0]) || enc;
          const priority = supportedValues.indexOf(encoding);
          if (priority === -1) {
            return false;
          }

          if (priority === 0 && quality === 1) {
            preferredEncoding = encoding;
            return true;
          } else if (preferredEncodingQuality < quality) {
            preferredEncoding = encoding;
            preferredEncodingPriority = priority;
            preferredEncodingQuality = quality;
          } else if (preferredEncodingPriority > priority) {
            preferredEncoding = encoding;
            preferredEncodingPriority = priority;
            preferredEncodingQuality = quality;
          }
          return false;
        }

        parse(header, processMatch);

        return preferredEncoding;
      }

      const BEGIN = 0;
      const TOKEN = 1;
      const QUALITY = 2;
      const END = 3;

      function parse(header, processMatch) {
        let str = '';
        let quality;
        let state = BEGIN;
        for (let i = 0, il = header.length; i < il; ++i) {
          const char = header[i];

          if (char === ' ' || char === '\t') {
            continue;
          } else if (char === ';') {
            if (state === TOKEN) {
              state = QUALITY;
              quality = '';
            }
            continue;
          } else if (char === ',') {
            if (state === TOKEN) {
              if (processMatch(str, 1)) {
                state = END;
                break;
              }
              state = BEGIN;
              str = '';
            } else if (state === QUALITY) {
              if (processMatch(str, parseFloat(quality) || 0)) {
                state = END;
                break;
              }
              state = BEGIN;
              str = '';
              quality = '';
            }
            continue;
          } else if (state === QUALITY) {
            if (char === 'q' || char === '=') {
              continue;
            } else if (
              char === '.' ||
              char === '1' ||
              char === '0' ||
              char === '2' ||
              char === '3' ||
              char === '4' ||
              char === '5' ||
              char === '6' ||
              char === '7' ||
              char === '8' ||
              char === '9'
            ) {
              quality += char;
              continue;
            }
          } else if (state === BEGIN) {
            state = TOKEN;
            str += char;
            continue;
          }
          if (state === TOKEN) {
            const prevChar = header[i - 1];
            if (prevChar === ' ' || prevChar === '\t') {
              str = '';
            }
            str += char;
            continue;
          }
          if (processMatch(str, parseFloat(quality) || 0)) {
            state = END;
            break;
          }
          state = BEGIN;
          str = char;
          quality = '';
        }

        if (state === TOKEN) {
          processMatch(str, 1);
        } else if (state === QUALITY) {
          processMatch(str, parseFloat(quality) || 0);
        }
      }

      module.exports = negotiate;
      module.exports['default'] = negotiate;
      module.exports.negotiate = negotiate;
      module.exports.Negotiator = Negotiator;

      /***/
    },

    /***/ 3351: /***/ (
      module,
      __unused_webpack_exports,
      __webpack_require__,
    ) => {
      'use strict';

      const { PassThrough } = __webpack_require__(7075);
      const path = __webpack_require__(6760);
      const { fileURLToPath } = __webpack_require__(3136);
      const { statSync } = __webpack_require__(3024);
      const { glob } = __webpack_require__(3220);
      const fp = __webpack_require__(3462);
      const send = __webpack_require__(1924);
      const encodingNegotiator = __webpack_require__(4102);
      const contentDisposition = __webpack_require__(3570);

      const dirList = __webpack_require__(496);

      const endForwardSlashRegex = /\/$/u;
      const asteriskRegex = /\*/gu;

      const supportedEncodings = ['br', 'gzip', 'deflate'];
      send.mime.default_type = 'application/octet-stream';

      async function fastifyStatic(fastify, opts) {
        opts.root = normalizeRoot(opts.root);
        checkRootPathForErrors(fastify, opts.root);

        const setHeaders = opts.setHeaders;
        if (setHeaders !== undefined && typeof setHeaders !== 'function') {
          throw new TypeError('The `setHeaders` option must be a function');
        }

        const invalidDirListOpts = dirList.validateOptions(opts);
        if (invalidDirListOpts) {
          throw invalidDirListOpts;
        }

        if (opts.dotfiles === undefined) {
          opts.dotfiles = 'allow';
        }

        const sendOptions = {
          root: opts.root,
          acceptRanges: opts.acceptRanges,
          cacheControl: opts.cacheControl,
          dotfiles: opts.dotfiles,
          etag: opts.etag,
          extensions: opts.extensions,
          immutable: opts.immutable,
          index: opts.index,
          lastModified: opts.lastModified,
          maxAge: opts.maxAge,
        };

        let prefix = opts.prefix ?? (opts.prefix = '/');

        if (!opts.prefixAvoidTrailingSlash) {
          prefix = prefix[prefix.length - 1] === '/' ? prefix : prefix + '/';
        }

        // Set the schema hide property if defined in opts or true by default
        const routeOpts = {
          constraints: opts.constraints,
          schema: {
            hide: opts.schemaHide !== undefined ? opts.schemaHide : true,
          },
          errorHandler(error, request, reply) {
            if (error?.code === 'ERR_STREAM_PREMATURE_CLOSE') {
              reply.request.raw.destroy();
              return;
            }

            fastify.errorHandler(error, request, reply);
          },
        };

        if (opts.decorateReply !== false) {
          fastify.decorateReply(
            'sendFile',
            function (filePath, rootPath, options) {
              const opts = typeof rootPath === 'object' ? rootPath : options;
              const root =
                typeof rootPath === 'string' ? rootPath : opts && opts.root;
              pumpSendToReply(
                this.request,
                this,
                filePath,
                root || sendOptions.root,
                0,
                opts,
              );
              return this;
            },
          );

          fastify.decorateReply(
            'download',
            function (filePath, fileName, options = {}) {
              const { root, ...opts } =
                typeof fileName === 'object' ? fileName : options;
              fileName = typeof fileName === 'string' ? fileName : filePath;

              // Set content disposition header
              this.header('content-disposition', contentDisposition(fileName));

              pumpSendToReply(this.request, this, filePath, root, 0, opts);

              return this;
            },
          );
        }

        if (opts.serve !== false) {
          if (opts.wildcard && typeof opts.wildcard !== 'boolean') {
            throw new Error('"wildcard" option must be a boolean');
          }
          if (opts.wildcard === undefined || opts.wildcard === true) {
            fastify.route({
              ...routeOpts,
              method: ['HEAD', 'GET'],
              path: prefix + '*',
              handler(req, reply) {
                pumpSendToReply(
                  req,
                  reply,
                  '/' + req.params['*'],
                  sendOptions.root,
                );
              },
            });
            if (opts.redirect === true && prefix !== opts.prefix) {
              fastify.get(opts.prefix, routeOpts, (req, reply) => {
                reply.redirect(301, getRedirectUrl(req.raw.url));
              });
            }
          } else {
            const indexes =
              opts.index === undefined ? ['index.html'] : [].concat(opts.index);
            const indexDirs = new Map();
            const routes = new Set();

            const roots = Array.isArray(sendOptions.root)
              ? sendOptions.root
              : [sendOptions.root];
            for (let rootPath of roots) {
              rootPath = rootPath.split(path.win32.sep).join(path.posix.sep);
              !rootPath.endsWith('/') && (rootPath += '/');
              const files = await glob('**/**', {
                cwd: rootPath,
                absolute: false,
                follow: true,
                nodir: true,
                dot: opts.serveDotFiles,
              });

              for (let file of files) {
                file = file.split(path.win32.sep).join(path.posix.sep);
                const route = prefix + file;

                if (routes.has(route)) {
                  continue;
                }

                routes.add(route);

                setUpHeadAndGet(routeOpts, route, `/${file}`, rootPath);

                const key = path.posix.basename(route);
                if (indexes.includes(key) && !indexDirs.has(key)) {
                  indexDirs.set(path.posix.dirname(route), rootPath);
                }
              }
            }

            for (const [dirname, rootPath] of indexDirs.entries()) {
              const pathname = dirname + (dirname.endsWith('/') ? '' : '/');
              const file = '/' + pathname.replace(prefix, '');
              setUpHeadAndGet(routeOpts, pathname, file, rootPath);

              if (opts.redirect === true) {
                setUpHeadAndGet(
                  routeOpts,
                  pathname.replace(endForwardSlashRegex, ''),
                  file.replace(endForwardSlashRegex, ''),
                  rootPath,
                );
              }
            }
          }
        }

        const allowedPath = opts.allowedPath;

        function pumpSendToReply(
          request,
          reply,
          pathname,
          rootPath,
          rootPathOffset = 0,
          pumpOptions,
          checkedEncodings,
        ) {
          const pathnameOrig = pathname;
          const options = Object.assign({}, sendOptions, pumpOptions);

          if (rootPath) {
            if (Array.isArray(rootPath)) {
              options.root = rootPath[rootPathOffset];
            } else {
              options.root = rootPath;
            }
          }

          if (allowedPath && !allowedPath(pathname, options.root, request)) {
            return reply.callNotFound();
          }

          let encoding;
          let pathnameForSend = pathname;

          if (opts.preCompressed) {
            /**
             * We conditionally create this structure to track our attempts
             * at sending pre-compressed assets
             */
            if (!checkedEncodings) {
              checkedEncodings = new Set();
            }

            encoding = getEncodingHeader(request.headers, checkedEncodings);

            if (encoding) {
              if (pathname.endsWith('/')) {
                pathname = findIndexFile(pathname, options.root, options.index);
                if (!pathname) {
                  return reply.callNotFound();
                }
                pathnameForSend =
                  pathnameForSend +
                  pathname +
                  '.' +
                  getEncodingExtension(encoding);
              } else {
                pathnameForSend =
                  pathname + '.' + getEncodingExtension(encoding);
              }
            }
          }

          // `send(..., path, ...)` will URI-decode path so we pass an encoded path here
          const stream = send(request.raw, encodeURI(pathnameForSend), options);
          let resolvedFilename;
          stream.on('file', function (file) {
            resolvedFilename = file;
          });

          const wrap = new PassThrough({
            flush(cb) {
              this.finished = true;
              if (reply.raw.statusCode === 304) {
                reply.send('');
              }
              cb();
            },
          });

          wrap.getHeader = reply.getHeader.bind(reply);
          wrap.setHeader = reply.header.bind(reply);
          wrap.removeHeader = () => {};
          wrap.finished = false;

          Object.defineProperty(wrap, 'filename', {
            get() {
              return resolvedFilename;
            },
          });
          Object.defineProperty(wrap, 'statusCode', {
            get() {
              return reply.raw.statusCode;
            },
            set(code) {
              reply.code(code);
            },
          });

          if (request.method === 'HEAD') {
            wrap.on('finish', reply.send.bind(reply));
          } else {
            wrap.on('pipe', function () {
              if (encoding) {
                reply.header('content-type', getContentType(pathname));
                reply.header('content-encoding', encoding);
              }
              reply.send(wrap);
            });
          }

          if (setHeaders !== undefined) {
            stream.on('headers', setHeaders);
          }

          stream.on('directory', function (_, path) {
            if (opts.list) {
              dirList
                .send({
                  reply,
                  dir: path,
                  options: opts.list,
                  route: pathname,
                  prefix,
                  dotfiles: opts.dotfiles,
                })
                .catch((err) => reply.send(err));
              return;
            }

            if (opts.redirect === true) {
              try {
                reply.redirect(301, getRedirectUrl(request.raw.url));
              } catch (error) {
                // the try-catch here is actually unreachable, but we keep it for safety and prevent DoS attack
                /* istanbul ignore next */
                reply.send(error);
              }
            } else {
              // if is a directory path without a trailing slash, and has an index file, reply as if it has a trailing slash
              if (
                !pathname.endsWith('/') &&
                findIndexFile(pathname, options.root, options.index)
              ) {
                return pumpSendToReply(
                  request,
                  reply,
                  pathname + '/',
                  rootPath,
                  undefined,
                  undefined,
                  checkedEncodings,
                );
              }

              reply.callNotFound();
            }
          });

          stream.on('error', function (err) {
            if (err.code === 'ENOENT') {
              // when preCompress is enabled and the path is a directory without a trailing slash
              if (opts.preCompressed && encoding) {
                const indexPathname = findIndexFile(
                  pathname,
                  options.root,
                  options.index,
                );
                if (indexPathname) {
                  return pumpSendToReply(
                    request,
                    reply,
                    pathname + '/',
                    rootPath,
                    undefined,
                    undefined,
                    checkedEncodings,
                  );
                }
              }

              // if file exists, send real file, otherwise send dir list if name match
              if (opts.list && dirList.handle(pathname, opts.list)) {
                dirList
                  .send({
                    reply,
                    dir: dirList.path(opts.root, pathname),
                    options: opts.list,
                    route: pathname,
                    prefix,
                    dotfiles: opts.dotfiles,
                  })
                  .catch((err) => reply.send(err));
                return;
              }

              // root paths left to try?
              if (
                Array.isArray(rootPath) &&
                rootPathOffset < rootPath.length - 1
              ) {
                return pumpSendToReply(
                  request,
                  reply,
                  pathname,
                  rootPath,
                  rootPathOffset + 1,
                );
              }

              if (opts.preCompressed && !checkedEncodings.has(encoding)) {
                checkedEncodings.add(encoding);
                return pumpSendToReply(
                  request,
                  reply,
                  pathnameOrig,
                  rootPath,
                  rootPathOffset,
                  undefined,
                  checkedEncodings,
                );
              }

              return reply.callNotFound();
            }

            // The `send` library terminates the request with a 404 if the requested
            // path contains a dotfile and `send` is initialized with `{dotfiles:
            // 'ignore'}`. `send` aborts the request before getting far enough to
            // check if the file exists (hence, a 404 `NotFoundError` instead of
            // `ENOENT`).
            // https://github.com/pillarjs/send/blob/de073ed3237ade9ff71c61673a34474b30e5d45b/index.js#L582
            if (err.status === 404) {
              return reply.callNotFound();
            }

            reply.send(err);
          });

          // we cannot use pump, because send error
          // handling is not compatible
          stream.pipe(wrap);
        }

        function setUpHeadAndGet(routeOpts, route, file, rootPath) {
          const toSetUp = Object.assign({}, routeOpts, {
            method: ['HEAD', 'GET'],
            url: route,
            handler: serveFileHandler,
          });
          toSetUp.config = toSetUp.config || {};
          toSetUp.config.file = file;
          toSetUp.config.rootPath = rootPath;
          fastify.route(toSetUp);
        }

        function serveFileHandler(req, reply) {
          // TODO: remove the fallback branch when bump major
          /* istanbul ignore next */
          const routeConfig = req.routeOptions?.config || req.routeConfig;
          pumpSendToReply(req, reply, routeConfig.file, routeConfig.rootPath);
        }
      }

      function normalizeRoot(root) {
        if (root === undefined) {
          return root;
        }
        if (root instanceof URL && root.protocol === 'file:') {
          return fileURLToPath(root);
        }
        if (Array.isArray(root)) {
          const result = [];
          for (let i = 0, il = root.length; i < il; ++i) {
            if (root[i] instanceof URL && root[i].protocol === 'file:') {
              result.push(fileURLToPath(root[i]));
            } else {
              result.push(root[i]);
            }
          }

          return result;
        }

        return root;
      }

      function checkRootPathForErrors(fastify, rootPath) {
        if (rootPath === undefined) {
          throw new Error('"root" option is required');
        }

        if (Array.isArray(rootPath)) {
          if (!rootPath.length) {
            throw new Error('"root" option array requires one or more paths');
          }

          if (new Set(rootPath).size !== rootPath.length) {
            throw new Error(
              '"root" option array contains one or more duplicate paths',
            );
          }

          // check each path and fail at first invalid
          rootPath.map((path) => checkPath(fastify, path));
          return;
        }

        if (typeof rootPath === 'string') {
          return checkPath(fastify, rootPath);
        }

        throw new Error('"root" option must be a string or array of strings');
      }

      function checkPath(fastify, rootPath) {
        if (typeof rootPath !== 'string') {
          throw new Error('"root" option must be a string');
        }
        if (path.isAbsolute(rootPath) === false) {
          throw new Error('"root" option must be an absolute path');
        }

        let pathStat;

        try {
          pathStat = statSync(rootPath);
        } catch (e) {
          if (e.code === 'ENOENT') {
            fastify.log.warn(`"root" path "${rootPath}" must exist`);
            return;
          }

          throw e;
        }

        if (pathStat.isDirectory() === false) {
          throw new Error('"root" option must point to a directory');
        }
      }

      function getContentType(path) {
        const type = send.mime.getType(path) || send.mime.default_type;

        if (!send.isUtf8MimeType(type)) {
          return type;
        }
        return `${type}; charset=UTF-8`;
      }

      function findIndexFile(pathname, root, indexFiles = ['index.html']) {
        // TODO remove istanbul ignore
        /* istanbul ignore else */
        if (Array.isArray(indexFiles)) {
          return indexFiles.find((filename) => {
            const p = path.join(root, pathname, filename);
            try {
              const stats = statSync(p);
              return !stats.isDirectory();
            } catch {
              return false;
            }
          });
        }
        /* istanbul ignore next */
        return false;
      }

      // Adapted from https://github.com/fastify/fastify-compress/blob/665e132fa63d3bf05ad37df3c20346660b71a857/index.js#L451
      function getEncodingHeader(headers, checked) {
        if (!('accept-encoding' in headers)) return;

        // consider the no-preference token as gzip for downstream compat
        const header = headers['accept-encoding']
          .toLowerCase()
          .replace(asteriskRegex, 'gzip');

        return encodingNegotiator.negotiate(
          header,
          supportedEncodings.filter((enc) => !checked.has(enc)),
        );
      }

      function getEncodingExtension(encoding) {
        switch (encoding) {
          case 'br':
            return 'br';

          case 'gzip':
            return 'gz';
        }
      }

      function getRedirectUrl(url) {
        let i = 0;
        // we detect how many slash before a valid path
        for (; i < url.length; ++i) {
          if (url[i] !== '/' && url[i] !== '\\') break;
        }
        // turns all leading / or \ into a single /
        url = '/' + url.substr(i);
        try {
          const parsed = new URL(url, 'http://localhost.com/');
          const parsedPathname = parsed.pathname;
          return (
            parsedPathname +
            (parsedPathname[parsedPathname.length - 1] !== '/' ? '/' : '') +
            (parsed.search || '')
          );
        } catch {
          // the try-catch here is actually unreachable, but we keep it for safety and prevent DoS attack
          /* istanbul ignore next */
          const err = new Error(`Invalid redirect URL: ${url}`);
          /* istanbul ignore next */
          err.statusCode = 400;
          /* istanbul ignore next */
          throw err;
        }
      }

      module.exports = fp(fastifyStatic, {
        fastify: '4.x',
        name: '@fastify/static',
      });
      module.exports['default'] = fastifyStatic;
      module.exports.fastifyStatic = fastifyStatic;

      /***/
    },

    /***/ 496: /***/ (
      module,
      __unused_webpack_exports,
      __webpack_require__,
    ) => {
      'use strict';

      const os = __webpack_require__(8161);
      const path = __webpack_require__(6760);
      const fs = __webpack_require__(1455);
      const fastq = __webpack_require__(1086);
      const fastqConcurrency = Math.max(1, os.cpus().length - 1);

      const dirList = {
        _getExtendedInfo: async function (dir, info) {
          const depth = dir.split(path.sep).length;
          const files = await fs.readdir(dir);

          const worker = async (filename) => {
            const filePath = path.join(dir, filename);
            let stats;
            try {
              stats = await fs.stat(filePath);
            } catch {
              return;
            }

            if (stats.isDirectory()) {
              info.totalFolderCount++;
              filePath.split(path.sep).length === depth + 1 &&
                info.folderCount++;
              await dirList._getExtendedInfo(filePath, info);
            } else {
              info.totalSize += stats.size;
              info.totalFileCount++;
              filePath.split(path.sep).length === depth + 1 && info.fileCount++;
              info.lastModified = Math.max(info.lastModified, stats.mtimeMs);
            }
          };
          const queue = fastq.promise(worker, fastqConcurrency);
          await Promise.all(files.map((filename) => queue.push(filename)));
        },

        /**
         * get extended info about a folder
         * @param {string} folderPath full path fs dir
         * @return {Promise<ExtendedInfo>}
         */
        getExtendedInfo: async function (folderPath) {
          const info = {
            totalSize: 0,
            fileCount: 0,
            totalFileCount: 0,
            folderCount: 0,
            totalFolderCount: 0,
            lastModified: 0,
          };

          await dirList._getExtendedInfo(folderPath, info);

          return info;
        },

        /**
         * get files and dirs from dir, or error
         * @param {string} dir full path fs dir
         * @param {(boolean | ListOptionsJsonFormat | ListOptionsHtmlFormat)} options
         * @param {string} dotfiles
         * note: can't use glob because don't get error on non existing dir
         */
        list: async function (dir, options, dotfiles) {
          const entries = { dirs: [], files: [] };
          let files = await fs.readdir(dir);
          if (dotfiles === 'deny' || dotfiles === 'ignore') {
            files = files.filter((file) => file.charAt(0) !== '.');
          }
          if (files.length < 1) {
            return entries;
          }

          const worker = async (filename) => {
            let stats;
            try {
              stats = await fs.stat(path.join(dir, filename));
            } catch {
              return;
            }
            const entry = { name: filename, stats };
            if (stats.isDirectory()) {
              if (options.extendedFolderInfo) {
                entry.extendedInfo = await dirList.getExtendedInfo(
                  path.join(dir, filename),
                );
              }
              entries.dirs.push(entry);
            } else {
              entries.files.push(entry);
            }
          };
          const queue = fastq.promise(worker, fastqConcurrency);
          await Promise.all(files.map((filename) => queue.push(filename)));

          entries.dirs.sort((a, b) => a.name.localeCompare(b.name));
          entries.files.sort((a, b) => a.name.localeCompare(b.name));

          return entries;
        },

        /**
         * send dir list content, or 404 on error
         * @param {Fastify.Reply} reply
         * @param {string} dir full path fs dir
         * @param {(boolean | ListOptionsJsonFormat | ListOptionsHtmlFormat)} options
         * @param {string} route request route
         * @param {string} dotfiles
         */
        send: async function ({
          reply,
          dir,
          options,
          route,
          prefix,
          dotfiles,
        }) {
          if (
            reply.request.query.format === 'html' &&
            typeof options.render !== 'function'
          ) {
            throw new Error(
              'The `list.render` option must be a function and is required with the URL parameter `format=html`',
            );
          }

          let entries;
          try {
            entries = await dirList.list(dir, options, dotfiles);
          } catch {
            return reply.callNotFound();
          }

          const format = reply.request.query.format || options.format;
          if (format !== 'html') {
            if (options.jsonFormat !== 'extended') {
              const nameEntries = { dirs: [], files: [] };
              entries.dirs.forEach((entry) =>
                nameEntries.dirs.push(entry.name),
              );
              entries.files.forEach((entry) =>
                nameEntries.files.push(entry.name),
              );

              reply.send(nameEntries);
            } else {
              reply.send(entries);
            }
            return;
          }

          const html = options.render(
            entries.dirs.map((entry) =>
              dirList.htmlInfo(entry, route, prefix, options),
            ),
            entries.files.map((entry) =>
              dirList.htmlInfo(entry, route, prefix, options),
            ),
          );
          reply.type('text/html').send(html);
        },

        /**
         * provide the html information about entry and route, to get name and full route
         * @param entry file or dir name and stats
         * @param {string} route request route
         * @return {ListFile}
         */
        htmlInfo: function (entry, route, prefix, options) {
          if (options.names?.includes(path.basename(route))) {
            route = path.normalize(path.join(route, '..'));
          }
          return {
            href: encodeURI(
              path.join(prefix, route, entry.name).replace(/\\/gu, '/'),
            ),
            name: entry.name,
            stats: entry.stats,
            extendedInfo: entry.extendedInfo,
          };
        },

        /**
         * say if the route can be handled by dir list or not
         * @param {string} route request route
         * @param {(boolean | ListOptionsJsonFormat | ListOptionsHtmlFormat)} options
         * @return {boolean}
         */
        handle: function (route, options) {
          return (
            options.names?.includes(path.basename(route)) ||
            // match trailing slash
            ((options.names?.includes('/') &&
              route[route.length - 1] === '/') ??
              false)
          );
        },

        /**
         * get path from route and fs root paths, considering trailing slash
         * @param {string} root fs root path
         * @param {string} route request route
         */
        path: function (root, route) {
          const _route =
            route[route.length - 1] === '/' ? route + 'none' : route;
          return path.dirname(path.join(root, _route));
        },

        /**
         * validate options
         * @return {Error}
         */
        validateOptions: function (options) {
          if (!options.list) {
            return;
          }

          if (Array.isArray(options.root)) {
            return new TypeError(
              'multi-root with list option is not supported',
            );
          }

          if (
            options.list.format &&
            options.list.format !== 'json' &&
            options.list.format !== 'html'
          ) {
            return new TypeError(
              'The `list.format` option must be json or html',
            );
          }
          if (options.list.names && !Array.isArray(options.list.names)) {
            return new TypeError('The `list.names` option must be an array');
          }
          if (
            options.list.jsonFormat != null &&
            options.list.jsonFormat !== 'names' &&
            options.list.jsonFormat !== 'extended'
          ) {
            return new TypeError(
              'The `list.jsonFormat` option must be name or extended',
            );
          }
          if (
            options.list.format === 'html' &&
            typeof options.list.render !== 'function'
          ) {
            return new TypeError(
              'The `list.render` option must be a function and is required with html format',
            );
          }
        },
      };

      module.exports = dirList;

      /***/
    },

    /***/ 6652: /***/ (
      __unused_webpack_module,
      exports,
      __webpack_require__,
    ) => {
      'use strict';

      Object.defineProperty(exports, '__esModule', { value: true });
      exports.Glob = void 0;
      const minimatch_1 = __webpack_require__(854);
      const node_url_1 = __webpack_require__(3136);
      const path_scurry_1 = __webpack_require__(642);
      const pattern_js_1 = __webpack_require__(5558);
      const walker_js_1 = __webpack_require__(24);
      // if no process global, just call it linux.
      // so we default to case-sensitive, / separators
      const defaultPlatform =
        typeof process === 'object' &&
        process &&
        typeof process.platform === 'string'
          ? process.platform
          : 'linux';
      /**
       * An object that can perform glob pattern traversals.
       */
      class Glob {
        absolute;
        cwd;
        root;
        dot;
        dotRelative;
        follow;
        ignore;
        magicalBraces;
        mark;
        matchBase;
        maxDepth;
        nobrace;
        nocase;
        nodir;
        noext;
        noglobstar;
        pattern;
        platform;
        realpath;
        scurry;
        stat;
        signal;
        windowsPathsNoEscape;
        withFileTypes;
        includeChildMatches;
        /**
         * The options provided to the constructor.
         */
        opts;
        /**
         * An array of parsed immutable {@link Pattern} objects.
         */
        patterns;
        /**
         * All options are stored as properties on the `Glob` object.
         *
         * See {@link GlobOptions} for full options descriptions.
         *
         * Note that a previous `Glob` object can be passed as the
         * `GlobOptions` to another `Glob` instantiation to re-use settings
         * and caches with a new pattern.
         *
         * Traversal functions can be called multiple times to run the walk
         * again.
         */
        constructor(pattern, opts) {
          /* c8 ignore start */
          if (!opts) throw new TypeError('glob options required');
          /* c8 ignore stop */
          this.withFileTypes = !!opts.withFileTypes;
          this.signal = opts.signal;
          this.follow = !!opts.follow;
          this.dot = !!opts.dot;
          this.dotRelative = !!opts.dotRelative;
          this.nodir = !!opts.nodir;
          this.mark = !!opts.mark;
          if (!opts.cwd) {
            this.cwd = '';
          } else if (
            opts.cwd instanceof URL ||
            opts.cwd.startsWith('file://')
          ) {
            opts.cwd = (0, node_url_1.fileURLToPath)(opts.cwd);
          }
          this.cwd = opts.cwd || '';
          this.root = opts.root;
          this.magicalBraces = !!opts.magicalBraces;
          this.nobrace = !!opts.nobrace;
          this.noext = !!opts.noext;
          this.realpath = !!opts.realpath;
          this.absolute = opts.absolute;
          this.includeChildMatches = opts.includeChildMatches !== false;
          this.noglobstar = !!opts.noglobstar;
          this.matchBase = !!opts.matchBase;
          this.maxDepth =
            typeof opts.maxDepth === 'number' ? opts.maxDepth : Infinity;
          this.stat = !!opts.stat;
          this.ignore = opts.ignore;
          if (this.withFileTypes && this.absolute !== undefined) {
            throw new Error('cannot set absolute and withFileTypes:true');
          }
          if (typeof pattern === 'string') {
            pattern = [pattern];
          }
          this.windowsPathsNoEscape =
            !!opts.windowsPathsNoEscape || opts.allowWindowsEscape === false;
          if (this.windowsPathsNoEscape) {
            pattern = pattern.map((p) => p.replace(/\\/g, '/'));
          }
          if (this.matchBase) {
            if (opts.noglobstar) {
              throw new TypeError('base matching requires globstar');
            }
            pattern = pattern.map((p) => (p.includes('/') ? p : `./**/${p}`));
          }
          this.pattern = pattern;
          this.platform = opts.platform || defaultPlatform;
          this.opts = { ...opts, platform: this.platform };
          if (opts.scurry) {
            this.scurry = opts.scurry;
            if (
              opts.nocase !== undefined &&
              opts.nocase !== opts.scurry.nocase
            ) {
              throw new Error(
                'nocase option contradicts provided scurry option',
              );
            }
          } else {
            const Scurry =
              opts.platform === 'win32'
                ? path_scurry_1.PathScurryWin32
                : opts.platform === 'darwin'
                  ? path_scurry_1.PathScurryDarwin
                  : opts.platform
                    ? path_scurry_1.PathScurryPosix
                    : path_scurry_1.PathScurry;
            this.scurry = new Scurry(this.cwd, {
              nocase: opts.nocase,
              fs: opts.fs,
            });
          }
          this.nocase = this.scurry.nocase;
          // If you do nocase:true on a case-sensitive file system, then
          // we need to use regexps instead of strings for non-magic
          // path portions, because statting `aBc` won't return results
          // for the file `AbC` for example.
          const nocaseMagicOnly =
            this.platform === 'darwin' || this.platform === 'win32';
          const mmo = {
            // default nocase based on platform
            ...opts,
            dot: this.dot,
            matchBase: this.matchBase,
            nobrace: this.nobrace,
            nocase: this.nocase,
            nocaseMagicOnly,
            nocomment: true,
            noext: this.noext,
            nonegate: true,
            optimizationLevel: 2,
            platform: this.platform,
            windowsPathsNoEscape: this.windowsPathsNoEscape,
            debug: !!this.opts.debug,
          };
          const mms = this.pattern.map(
            (p) => new minimatch_1.Minimatch(p, mmo),
          );
          const [matchSet, globParts] = mms.reduce(
            (set, m) => {
              set[0].push(...m.set);
              set[1].push(...m.globParts);
              return set;
            },
            [[], []],
          );
          this.patterns = matchSet.map((set, i) => {
            const g = globParts[i];
            /* c8 ignore start */
            if (!g) throw new Error('invalid pattern object');
            /* c8 ignore stop */
            return new pattern_js_1.Pattern(set, g, 0, this.platform);
          });
        }
        async walk() {
          // Walkers always return array of Path objects, so we just have to
          // coerce them into the right shape.  It will have already called
          // realpath() if the option was set to do so, so we know that's cached.
          // start out knowing the cwd, at least
          return [
            ...(await new walker_js_1.GlobWalker(
              this.patterns,
              this.scurry.cwd,
              {
                ...this.opts,
                maxDepth:
                  this.maxDepth !== Infinity
                    ? this.maxDepth + this.scurry.cwd.depth()
                    : Infinity,
                platform: this.platform,
                nocase: this.nocase,
                includeChildMatches: this.includeChildMatches,
              },
            ).walk()),
          ];
        }
        walkSync() {
          return [
            ...new walker_js_1.GlobWalker(this.patterns, this.scurry.cwd, {
              ...this.opts,
              maxDepth:
                this.maxDepth !== Infinity
                  ? this.maxDepth + this.scurry.cwd.depth()
                  : Infinity,
              platform: this.platform,
              nocase: this.nocase,
              includeChildMatches: this.includeChildMatches,
            }).walkSync(),
          ];
        }
        stream() {
          return new walker_js_1.GlobStream(this.patterns, this.scurry.cwd, {
            ...this.opts,
            maxDepth:
              this.maxDepth !== Infinity
                ? this.maxDepth + this.scurry.cwd.depth()
                : Infinity,
            platform: this.platform,
            nocase: this.nocase,
            includeChildMatches: this.includeChildMatches,
          }).stream();
        }
        streamSync() {
          return new walker_js_1.GlobStream(this.patterns, this.scurry.cwd, {
            ...this.opts,
            maxDepth:
              this.maxDepth !== Infinity
                ? this.maxDepth + this.scurry.cwd.depth()
                : Infinity,
            platform: this.platform,
            nocase: this.nocase,
            includeChildMatches: this.includeChildMatches,
          }).streamSync();
        }
        /**
         * Default sync iteration function. Returns a Generator that
         * iterates over the results.
         */
        iterateSync() {
          return this.streamSync()[Symbol.iterator]();
        }
        [Symbol.iterator]() {
          return this.iterateSync();
        }
        /**
         * Default async iteration function. Returns an AsyncGenerator that
         * iterates over the results.
         */
        iterate() {
          return this.stream()[Symbol.asyncIterator]();
        }
        [Symbol.asyncIterator]() {
          return this.iterate();
        }
      }
      exports.Glob = Glob;
      //# sourceMappingURL=glob.js.map

      /***/
    },

    /***/ 5294: /***/ (
      __unused_webpack_module,
      exports,
      __webpack_require__,
    ) => {
      'use strict';

      Object.defineProperty(exports, '__esModule', { value: true });
      exports.hasMagic = void 0;
      const minimatch_1 = __webpack_require__(854);
      /**
       * Return true if the patterns provided contain any magic glob characters,
       * given the options provided.
       *
       * Brace expansion is not considered "magic" unless the `magicalBraces` option
       * is set, as brace expansion just turns one string into an array of strings.
       * So a pattern like `'x{a,b}y'` would return `false`, because `'xay'` and
       * `'xby'` both do not contain any magic glob characters, and it's treated the
       * same as if you had called it on `['xay', 'xby']`. When `magicalBraces:true`
       * is in the options, brace expansion _is_ treated as a pattern having magic.
       */
      const hasMagic = (pattern, options = {}) => {
        if (!Array.isArray(pattern)) {
          pattern = [pattern];
        }
        for (const p of pattern) {
          if (new minimatch_1.Minimatch(p, options).hasMagic()) return true;
        }
        return false;
      };
      exports.hasMagic = hasMagic;
      //# sourceMappingURL=has-magic.js.map

      /***/
    },

    /***/ 4924: /***/ (
      __unused_webpack_module,
      exports,
      __webpack_require__,
    ) => {
      'use strict';

      // give it a pattern, and it'll be able to tell you if
      // a given path should be ignored.
      // Ignoring a path ignores its children if the pattern ends in /**
      // Ignores are always parsed in dot:true mode
      Object.defineProperty(exports, '__esModule', { value: true });
      exports.Ignore = void 0;
      const minimatch_1 = __webpack_require__(854);
      const pattern_js_1 = __webpack_require__(5558);
      const defaultPlatform =
        typeof process === 'object' &&
        process &&
        typeof process.platform === 'string'
          ? process.platform
          : 'linux';
      /**
       * Class used to process ignored patterns
       */
      class Ignore {
        relative;
        relativeChildren;
        absolute;
        absoluteChildren;
        platform;
        mmopts;
        constructor(
          ignored,
          { nobrace, nocase, noext, noglobstar, platform = defaultPlatform },
        ) {
          this.relative = [];
          this.absolute = [];
          this.relativeChildren = [];
          this.absoluteChildren = [];
          this.platform = platform;
          this.mmopts = {
            dot: true,
            nobrace,
            nocase,
            noext,
            noglobstar,
            optimizationLevel: 2,
            platform,
            nocomment: true,
            nonegate: true,
          };
          for (const ign of ignored) this.add(ign);
        }
        add(ign) {
          // this is a little weird, but it gives us a clean set of optimized
          // minimatch matchers, without getting tripped up if one of them
          // ends in /** inside a brace section, and it's only inefficient at
          // the start of the walk, not along it.
          // It'd be nice if the Pattern class just had a .test() method, but
          // handling globstars is a bit of a pita, and that code already lives
          // in minimatch anyway.
          // Another way would be if maybe Minimatch could take its set/globParts
          // as an option, and then we could at least just use Pattern to test
          // for absolute-ness.
          // Yet another way, Minimatch could take an array of glob strings, and
          // a cwd option, and do the right thing.
          const mm = new minimatch_1.Minimatch(ign, this.mmopts);
          for (let i = 0; i < mm.set.length; i++) {
            const parsed = mm.set[i];
            const globParts = mm.globParts[i];
            /* c8 ignore start */
            if (!parsed || !globParts) {
              throw new Error('invalid pattern object');
            }
            // strip off leading ./ portions
            // https://github.com/isaacs/node-glob/issues/570
            while (parsed[0] === '.' && globParts[0] === '.') {
              parsed.shift();
              globParts.shift();
            }
            /* c8 ignore stop */
            const p = new pattern_js_1.Pattern(
              parsed,
              globParts,
              0,
              this.platform,
            );
            const m = new minimatch_1.Minimatch(p.globString(), this.mmopts);
            const children = globParts[globParts.length - 1] === '**';
            const absolute = p.isAbsolute();
            if (absolute) this.absolute.push(m);
            else this.relative.push(m);
            if (children) {
              if (absolute) this.absoluteChildren.push(m);
              else this.relativeChildren.push(m);
            }
          }
        }
        ignored(p) {
          const fullpath = p.fullpath();
          const fullpaths = `${fullpath}/`;
          const relative = p.relative() || '.';
          const relatives = `${relative}/`;
          for (const m of this.relative) {
            if (m.match(relative) || m.match(relatives)) return true;
          }
          for (const m of this.absolute) {
            if (m.match(fullpath) || m.match(fullpaths)) return true;
          }
          return false;
        }
        childrenIgnored(p) {
          const fullpath = p.fullpath() + '/';
          const relative = (p.relative() || '.') + '/';
          for (const m of this.relativeChildren) {
            if (m.match(relative)) return true;
          }
          for (const m of this.absoluteChildren) {
            if (m.match(fullpath)) return true;
          }
          return false;
        }
      }
      exports.Ignore = Ignore;
      //# sourceMappingURL=ignore.js.map

      /***/
    },

    /***/ 3220: /***/ (
      __unused_webpack_module,
      exports,
      __webpack_require__,
    ) => {
      'use strict';

      Object.defineProperty(exports, '__esModule', { value: true });
      exports.glob =
        exports.sync =
        exports.iterate =
        exports.iterateSync =
        exports.stream =
        exports.streamSync =
        exports.Ignore =
        exports.hasMagic =
        exports.Glob =
        exports.unescape =
        exports.escape =
          void 0;
      exports.globStreamSync = globStreamSync;
      exports.globStream = globStream;
      exports.globSync = globSync;
      exports.globIterateSync = globIterateSync;
      exports.globIterate = globIterate;
      const minimatch_1 = __webpack_require__(854);
      const glob_js_1 = __webpack_require__(6652);
      const has_magic_js_1 = __webpack_require__(5294);
      var minimatch_2 = __webpack_require__(854);
      Object.defineProperty(exports, 'escape', {
        enumerable: true,
        get: function () {
          return minimatch_2.escape;
        },
      });
      Object.defineProperty(exports, 'unescape', {
        enumerable: true,
        get: function () {
          return minimatch_2.unescape;
        },
      });
      var glob_js_2 = __webpack_require__(6652);
      Object.defineProperty(exports, 'Glob', {
        enumerable: true,
        get: function () {
          return glob_js_2.Glob;
        },
      });
      var has_magic_js_2 = __webpack_require__(5294);
      Object.defineProperty(exports, 'hasMagic', {
        enumerable: true,
        get: function () {
          return has_magic_js_2.hasMagic;
        },
      });
      var ignore_js_1 = __webpack_require__(4924);
      Object.defineProperty(exports, 'Ignore', {
        enumerable: true,
        get: function () {
          return ignore_js_1.Ignore;
        },
      });
      function globStreamSync(pattern, options = {}) {
        return new glob_js_1.Glob(pattern, options).streamSync();
      }
      function globStream(pattern, options = {}) {
        return new glob_js_1.Glob(pattern, options).stream();
      }
      function globSync(pattern, options = {}) {
        return new glob_js_1.Glob(pattern, options).walkSync();
      }
      async function glob_(pattern, options = {}) {
        return new glob_js_1.Glob(pattern, options).walk();
      }
      function globIterateSync(pattern, options = {}) {
        return new glob_js_1.Glob(pattern, options).iterateSync();
      }
      function globIterate(pattern, options = {}) {
        return new glob_js_1.Glob(pattern, options).iterate();
      }
      // aliases: glob.sync.stream() glob.stream.sync() glob.sync() etc
      exports.streamSync = globStreamSync;
      exports.stream = Object.assign(globStream, { sync: globStreamSync });
      exports.iterateSync = globIterateSync;
      exports.iterate = Object.assign(globIterate, {
        sync: globIterateSync,
      });
      exports.sync = Object.assign(globSync, {
        stream: globStreamSync,
        iterate: globIterateSync,
      });
      exports.glob = Object.assign(glob_, {
        glob: glob_,
        globSync,
        sync: exports.sync,
        globStream,
        stream: exports.stream,
        globStreamSync,
        streamSync: exports.streamSync,
        globIterate,
        iterate: exports.iterate,
        globIterateSync,
        iterateSync: exports.iterateSync,
        Glob: glob_js_1.Glob,
        hasMagic: has_magic_js_1.hasMagic,
        escape: minimatch_1.escape,
        unescape: minimatch_1.unescape,
      });
      exports.glob.glob = exports.glob;
      //# sourceMappingURL=index.js.map

      /***/
    },

    /***/ 5558: /***/ (
      __unused_webpack_module,
      exports,
      __webpack_require__,
    ) => {
      'use strict';

      // this is just a very light wrapper around 2 arrays with an offset index
      Object.defineProperty(exports, '__esModule', { value: true });
      exports.Pattern = void 0;
      const minimatch_1 = __webpack_require__(854);
      const isPatternList = (pl) => pl.length >= 1;
      const isGlobList = (gl) => gl.length >= 1;
      /**
       * An immutable-ish view on an array of glob parts and their parsed
       * results
       */
      class Pattern {
        #patternList;
        #globList;
        #index;
        length;
        #platform;
        #rest;
        #globString;
        #isDrive;
        #isUNC;
        #isAbsolute;
        #followGlobstar = true;
        constructor(patternList, globList, index, platform) {
          if (!isPatternList(patternList)) {
            throw new TypeError('empty pattern list');
          }
          if (!isGlobList(globList)) {
            throw new TypeError('empty glob list');
          }
          if (globList.length !== patternList.length) {
            throw new TypeError(
              'mismatched pattern list and glob list lengths',
            );
          }
          this.length = patternList.length;
          if (index < 0 || index >= this.length) {
            throw new TypeError('index out of range');
          }
          this.#patternList = patternList;
          this.#globList = globList;
          this.#index = index;
          this.#platform = platform;
          // normalize root entries of absolute patterns on initial creation.
          if (this.#index === 0) {
            // c: => ['c:/']
            // C:/ => ['C:/']
            // C:/x => ['C:/', 'x']
            // //host/share => ['//host/share/']
            // //host/share/ => ['//host/share/']
            // //host/share/x => ['//host/share/', 'x']
            // /etc => ['/', 'etc']
            // / => ['/']
            if (this.isUNC()) {
              // '' / '' / 'host' / 'share'
              const [p0, p1, p2, p3, ...prest] = this.#patternList;
              const [g0, g1, g2, g3, ...grest] = this.#globList;
              if (prest[0] === '') {
                // ends in /
                prest.shift();
                grest.shift();
              }
              const p = [p0, p1, p2, p3, ''].join('/');
              const g = [g0, g1, g2, g3, ''].join('/');
              this.#patternList = [p, ...prest];
              this.#globList = [g, ...grest];
              this.length = this.#patternList.length;
            } else if (this.isDrive() || this.isAbsolute()) {
              const [p1, ...prest] = this.#patternList;
              const [g1, ...grest] = this.#globList;
              if (prest[0] === '') {
                // ends in /
                prest.shift();
                grest.shift();
              }
              const p = p1 + '/';
              const g = g1 + '/';
              this.#patternList = [p, ...prest];
              this.#globList = [g, ...grest];
              this.length = this.#patternList.length;
            }
          }
        }
        /**
         * The first entry in the parsed list of patterns
         */
        pattern() {
          return this.#patternList[this.#index];
        }
        /**
         * true of if pattern() returns a string
         */
        isString() {
          return typeof this.#patternList[this.#index] === 'string';
        }
        /**
         * true of if pattern() returns GLOBSTAR
         */
        isGlobstar() {
          return this.#patternList[this.#index] === minimatch_1.GLOBSTAR;
        }
        /**
         * true if pattern() returns a regexp
         */
        isRegExp() {
          return this.#patternList[this.#index] instanceof RegExp;
        }
        /**
         * The /-joined set of glob parts that make up this pattern
         */
        globString() {
          return (this.#globString =
            this.#globString ||
            (this.#index === 0
              ? this.isAbsolute()
                ? this.#globList[0] + this.#globList.slice(1).join('/')
                : this.#globList.join('/')
              : this.#globList.slice(this.#index).join('/')));
        }
        /**
         * true if there are more pattern parts after this one
         */
        hasMore() {
          return this.length > this.#index + 1;
        }
        /**
         * The rest of the pattern after this part, or null if this is the end
         */
        rest() {
          if (this.#rest !== undefined) return this.#rest;
          if (!this.hasMore()) return (this.#rest = null);
          this.#rest = new Pattern(
            this.#patternList,
            this.#globList,
            this.#index + 1,
            this.#platform,
          );
          this.#rest.#isAbsolute = this.#isAbsolute;
          this.#rest.#isUNC = this.#isUNC;
          this.#rest.#isDrive = this.#isDrive;
          return this.#rest;
        }
        /**
         * true if the pattern represents a //unc/path/ on windows
         */
        isUNC() {
          const pl = this.#patternList;
          return this.#isUNC !== undefined
            ? this.#isUNC
            : (this.#isUNC =
                this.#platform === 'win32' &&
                this.#index === 0 &&
                pl[0] === '' &&
                pl[1] === '' &&
                typeof pl[2] === 'string' &&
                !!pl[2] &&
                typeof pl[3] === 'string' &&
                !!pl[3]);
        }
        // pattern like C:/...
        // split = ['C:', ...]
        // XXX: would be nice to handle patterns like `c:*` to test the cwd
        // in c: for *, but I don't know of a way to even figure out what that
        // cwd is without actually chdir'ing into it?
        /**
         * True if the pattern starts with a drive letter on Windows
         */
        isDrive() {
          const pl = this.#patternList;
          return this.#isDrive !== undefined
            ? this.#isDrive
            : (this.#isDrive =
                this.#platform === 'win32' &&
                this.#index === 0 &&
                this.length > 1 &&
                typeof pl[0] === 'string' &&
                /^[a-z]:$/i.test(pl[0]));
        }
        // pattern = '/' or '/...' or '/x/...'
        // split = ['', ''] or ['', ...] or ['', 'x', ...]
        // Drive and UNC both considered absolute on windows
        /**
         * True if the pattern is rooted on an absolute path
         */
        isAbsolute() {
          const pl = this.#patternList;
          return this.#isAbsolute !== undefined
            ? this.#isAbsolute
            : (this.#isAbsolute =
                (pl[0] === '' && pl.length > 1) ||
                this.isDrive() ||
                this.isUNC());
        }
        /**
         * consume the root of the pattern, and return it
         */
        root() {
          const p = this.#patternList[0];
          return typeof p === 'string' && this.isAbsolute() && this.#index === 0
            ? p
            : '';
        }
        /**
         * Check to see if the current globstar pattern is allowed to follow
         * a symbolic link.
         */
        checkFollowGlobstar() {
          return !(
            this.#index === 0 ||
            !this.isGlobstar() ||
            !this.#followGlobstar
          );
        }
        /**
         * Mark that the current globstar pattern is following a symbolic link
         */
        markFollowGlobstar() {
          if (this.#index === 0 || !this.isGlobstar() || !this.#followGlobstar)
            return false;
          this.#followGlobstar = false;
          return true;
        }
      }
      exports.Pattern = Pattern;
      //# sourceMappingURL=pattern.js.map

      /***/
    },

    /***/ 520: /***/ (
      __unused_webpack_module,
      exports,
      __webpack_require__,
    ) => {
      'use strict';

      // synchronous utility for filtering entries and calculating subwalks
      Object.defineProperty(exports, '__esModule', { value: true });
      exports.Processor =
        exports.SubWalks =
        exports.MatchRecord =
        exports.HasWalkedCache =
          void 0;
      const minimatch_1 = __webpack_require__(854);
      /**
       * A cache of which patterns have been processed for a given Path
       */
      class HasWalkedCache {
        store;
        constructor(store = new Map()) {
          this.store = store;
        }
        copy() {
          return new HasWalkedCache(new Map(this.store));
        }
        hasWalked(target, pattern) {
          return this.store.get(target.fullpath())?.has(pattern.globString());
        }
        storeWalked(target, pattern) {
          const fullpath = target.fullpath();
          const cached = this.store.get(fullpath);
          if (cached) cached.add(pattern.globString());
          else this.store.set(fullpath, new Set([pattern.globString()]));
        }
      }
      exports.HasWalkedCache = HasWalkedCache;
      /**
       * A record of which paths have been matched in a given walk step,
       * and whether they only are considered a match if they are a directory,
       * and whether their absolute or relative path should be returned.
       */
      class MatchRecord {
        store = new Map();
        add(target, absolute, ifDir) {
          const n = (absolute ? 2 : 0) | (ifDir ? 1 : 0);
          const current = this.store.get(target);
          this.store.set(target, current === undefined ? n : n & current);
        }
        // match, absolute, ifdir
        entries() {
          return [...this.store.entries()].map(([path, n]) => [
            path,
            !!(n & 2),
            !!(n & 1),
          ]);
        }
      }
      exports.MatchRecord = MatchRecord;
      /**
       * A collection of patterns that must be processed in a subsequent step
       * for a given path.
       */
      class SubWalks {
        store = new Map();
        add(target, pattern) {
          if (!target.canReaddir()) {
            return;
          }
          const subs = this.store.get(target);
          if (subs) {
            if (!subs.find((p) => p.globString() === pattern.globString())) {
              subs.push(pattern);
            }
          } else this.store.set(target, [pattern]);
        }
        get(target) {
          const subs = this.store.get(target);
          /* c8 ignore start */
          if (!subs) {
            throw new Error('attempting to walk unknown path');
          }
          /* c8 ignore stop */
          return subs;
        }
        entries() {
          return this.keys().map((k) => [k, this.store.get(k)]);
        }
        keys() {
          return [...this.store.keys()].filter((t) => t.canReaddir());
        }
      }
      exports.SubWalks = SubWalks;
      /**
       * The class that processes patterns for a given path.
       *
       * Handles child entry filtering, and determining whether a path's
       * directory contents must be read.
       */
      class Processor {
        hasWalkedCache;
        matches = new MatchRecord();
        subwalks = new SubWalks();
        patterns;
        follow;
        dot;
        opts;
        constructor(opts, hasWalkedCache) {
          this.opts = opts;
          this.follow = !!opts.follow;
          this.dot = !!opts.dot;
          this.hasWalkedCache = hasWalkedCache
            ? hasWalkedCache.copy()
            : new HasWalkedCache();
        }
        processPatterns(target, patterns) {
          this.patterns = patterns;
          const processingSet = patterns.map((p) => [target, p]);
          // map of paths to the magic-starting subwalks they need to walk
          // first item in patterns is the filter
          for (let [t, pattern] of processingSet) {
            this.hasWalkedCache.storeWalked(t, pattern);
            const root = pattern.root();
            const absolute =
              pattern.isAbsolute() && this.opts.absolute !== false;
            // start absolute patterns at root
            if (root) {
              t = t.resolve(
                root === '/' && this.opts.root !== undefined
                  ? this.opts.root
                  : root,
              );
              const rest = pattern.rest();
              if (!rest) {
                this.matches.add(t, true, false);
                continue;
              } else {
                pattern = rest;
              }
            }
            if (t.isENOENT()) continue;
            let p;
            let rest;
            let changed = false;
            while (
              typeof (p = pattern.pattern()) === 'string' &&
              (rest = pattern.rest())
            ) {
              const c = t.resolve(p);
              t = c;
              pattern = rest;
              changed = true;
            }
            p = pattern.pattern();
            rest = pattern.rest();
            if (changed) {
              if (this.hasWalkedCache.hasWalked(t, pattern)) continue;
              this.hasWalkedCache.storeWalked(t, pattern);
            }
            // now we have either a final string for a known entry,
            // more strings for an unknown entry,
            // or a pattern starting with magic, mounted on t.
            if (typeof p === 'string') {
              // must not be final entry, otherwise we would have
              // concatenated it earlier.
              const ifDir = p === '..' || p === '' || p === '.';
              this.matches.add(t.resolve(p), absolute, ifDir);
              continue;
            } else if (p === minimatch_1.GLOBSTAR) {
              // if no rest, match and subwalk pattern
              // if rest, process rest and subwalk pattern
              // if it's a symlink, but we didn't get here by way of a
              // globstar match (meaning it's the first time THIS globstar
              // has traversed a symlink), then we follow it. Otherwise, stop.
              if (
                !t.isSymbolicLink() ||
                this.follow ||
                pattern.checkFollowGlobstar()
              ) {
                this.subwalks.add(t, pattern);
              }
              const rp = rest?.pattern();
              const rrest = rest?.rest();
              if (!rest || ((rp === '' || rp === '.') && !rrest)) {
                // only HAS to be a dir if it ends in **/ or **/.
                // but ending in ** will match files as well.
                this.matches.add(t, absolute, rp === '' || rp === '.');
              } else {
                if (rp === '..') {
                  // this would mean you're matching **/.. at the fs root,
                  // and no thanks, I'm not gonna test that specific case.
                  /* c8 ignore start */
                  const tp = t.parent || t;
                  /* c8 ignore stop */
                  if (!rrest) this.matches.add(tp, absolute, true);
                  else if (!this.hasWalkedCache.hasWalked(tp, rrest)) {
                    this.subwalks.add(tp, rrest);
                  }
                }
              }
            } else if (p instanceof RegExp) {
              this.subwalks.add(t, pattern);
            }
          }
          return this;
        }
        subwalkTargets() {
          return this.subwalks.keys();
        }
        child() {
          return new Processor(this.opts, this.hasWalkedCache);
        }
        // return a new Processor containing the subwalks for each
        // child entry, and a set of matches, and
        // a hasWalkedCache that's a copy of this one
        // then we're going to call
        filterEntries(parent, entries) {
          const patterns = this.subwalks.get(parent);
          // put matches and entry walks into the results processor
          const results = this.child();
          for (const e of entries) {
            for (const pattern of patterns) {
              const absolute = pattern.isAbsolute();
              const p = pattern.pattern();
              const rest = pattern.rest();
              if (p === minimatch_1.GLOBSTAR) {
                results.testGlobstar(e, pattern, rest, absolute);
              } else if (p instanceof RegExp) {
                results.testRegExp(e, p, rest, absolute);
              } else {
                results.testString(e, p, rest, absolute);
              }
            }
          }
          return results;
        }
        testGlobstar(e, pattern, rest, absolute) {
          if (this.dot || !e.name.startsWith('.')) {
            if (!pattern.hasMore()) {
              this.matches.add(e, absolute, false);
            }
            if (e.canReaddir()) {
              // if we're in follow mode or it's not a symlink, just keep
              // testing the same pattern. If there's more after the globstar,
              // then this symlink consumes the globstar. If not, then we can
              // follow at most ONE symlink along the way, so we mark it, which
              // also checks to ensure that it wasn't already marked.
              if (this.follow || !e.isSymbolicLink()) {
                this.subwalks.add(e, pattern);
              } else if (e.isSymbolicLink()) {
                if (rest && pattern.checkFollowGlobstar()) {
                  this.subwalks.add(e, rest);
                } else if (pattern.markFollowGlobstar()) {
                  this.subwalks.add(e, pattern);
                }
              }
            }
          }
          // if the NEXT thing matches this entry, then also add
          // the rest.
          if (rest) {
            const rp = rest.pattern();
            if (
              typeof rp === 'string' &&
              // dots and empty were handled already
              rp !== '..' &&
              rp !== '' &&
              rp !== '.'
            ) {
              this.testString(e, rp, rest.rest(), absolute);
            } else if (rp === '..') {
              /* c8 ignore start */
              const ep = e.parent || e;
              /* c8 ignore stop */
              this.subwalks.add(ep, rest);
            } else if (rp instanceof RegExp) {
              this.testRegExp(e, rp, rest.rest(), absolute);
            }
          }
        }
        testRegExp(e, p, rest, absolute) {
          if (!p.test(e.name)) return;
          if (!rest) {
            this.matches.add(e, absolute, false);
          } else {
            this.subwalks.add(e, rest);
          }
        }
        testString(e, p, rest, absolute) {
          // should never happen?
          if (!e.isNamed(p)) return;
          if (!rest) {
            this.matches.add(e, absolute, false);
          } else {
            this.subwalks.add(e, rest);
          }
        }
      }
      exports.Processor = Processor;
      //# sourceMappingURL=processor.js.map

      /***/
    },

    /***/ 24: /***/ (__unused_webpack_module, exports, __webpack_require__) => {
      'use strict';

      Object.defineProperty(exports, '__esModule', { value: true });
      exports.GlobStream = exports.GlobWalker = exports.GlobUtil = void 0;
      /**
       * Single-use utility classes to provide functionality to the {@link Glob}
       * methods.
       *
       * @module
       */
      const minipass_1 = __webpack_require__(2225);
      const ignore_js_1 = __webpack_require__(4924);
      const processor_js_1 = __webpack_require__(520);
      const makeIgnore = (ignore, opts) =>
        typeof ignore === 'string'
          ? new ignore_js_1.Ignore([ignore], opts)
          : Array.isArray(ignore)
            ? new ignore_js_1.Ignore(ignore, opts)
            : ignore;
      /**
       * basic walking utilities that all the glob walker types use
       */
      class GlobUtil {
        path;
        patterns;
        opts;
        seen = new Set();
        paused = false;
        aborted = false;
        #onResume = [];
        #ignore;
        #sep;
        signal;
        maxDepth;
        includeChildMatches;
        constructor(patterns, path, opts) {
          this.patterns = patterns;
          this.path = path;
          this.opts = opts;
          this.#sep = !opts.posix && opts.platform === 'win32' ? '\\' : '/';
          this.includeChildMatches = opts.includeChildMatches !== false;
          if (opts.ignore || !this.includeChildMatches) {
            this.#ignore = makeIgnore(opts.ignore ?? [], opts);
            if (
              !this.includeChildMatches &&
              typeof this.#ignore.add !== 'function'
            ) {
              const m =
                'cannot ignore child matches, ignore lacks add() method.';
              throw new Error(m);
            }
          }
          // ignore, always set with maxDepth, but it's optional on the
          // GlobOptions type
          /* c8 ignore start */
          this.maxDepth = opts.maxDepth || Infinity;
          /* c8 ignore stop */
          if (opts.signal) {
            this.signal = opts.signal;
            this.signal.addEventListener('abort', () => {
              this.#onResume.length = 0;
            });
          }
        }
        #ignored(path) {
          return this.seen.has(path) || !!this.#ignore?.ignored?.(path);
        }
        #childrenIgnored(path) {
          return !!this.#ignore?.childrenIgnored?.(path);
        }
        // backpressure mechanism
        pause() {
          this.paused = true;
        }
        resume() {
          /* c8 ignore start */
          if (this.signal?.aborted) return;
          /* c8 ignore stop */
          this.paused = false;
          let fn = undefined;
          while (!this.paused && (fn = this.#onResume.shift())) {
            fn();
          }
        }
        onResume(fn) {
          if (this.signal?.aborted) return;
          /* c8 ignore start */
          if (!this.paused) {
            fn();
          } else {
            /* c8 ignore stop */
            this.#onResume.push(fn);
          }
        }
        // do the requisite realpath/stat checking, and return the path
        // to add or undefined to filter it out.
        async matchCheck(e, ifDir) {
          if (ifDir && this.opts.nodir) return undefined;
          let rpc;
          if (this.opts.realpath) {
            rpc = e.realpathCached() || (await e.realpath());
            if (!rpc) return undefined;
            e = rpc;
          }
          const needStat = e.isUnknown() || this.opts.stat;
          const s = needStat ? await e.lstat() : e;
          if (this.opts.follow && this.opts.nodir && s?.isSymbolicLink()) {
            const target = await s.realpath();
            /* c8 ignore start */
            if (target && (target.isUnknown() || this.opts.stat)) {
              await target.lstat();
            }
            /* c8 ignore stop */
          }
          return this.matchCheckTest(s, ifDir);
        }
        matchCheckTest(e, ifDir) {
          return e &&
            (this.maxDepth === Infinity || e.depth() <= this.maxDepth) &&
            (!ifDir || e.canReaddir()) &&
            (!this.opts.nodir || !e.isDirectory()) &&
            (!this.opts.nodir ||
              !this.opts.follow ||
              !e.isSymbolicLink() ||
              !e.realpathCached()?.isDirectory()) &&
            !this.#ignored(e)
            ? e
            : undefined;
        }
        matchCheckSync(e, ifDir) {
          if (ifDir && this.opts.nodir) return undefined;
          let rpc;
          if (this.opts.realpath) {
            rpc = e.realpathCached() || e.realpathSync();
            if (!rpc) return undefined;
            e = rpc;
          }
          const needStat = e.isUnknown() || this.opts.stat;
          const s = needStat ? e.lstatSync() : e;
          if (this.opts.follow && this.opts.nodir && s?.isSymbolicLink()) {
            const target = s.realpathSync();
            if (target && (target?.isUnknown() || this.opts.stat)) {
              target.lstatSync();
            }
          }
          return this.matchCheckTest(s, ifDir);
        }
        matchFinish(e, absolute) {
          if (this.#ignored(e)) return;
          // we know we have an ignore if this is false, but TS doesn't
          if (!this.includeChildMatches && this.#ignore?.add) {
            const ign = `${e.relativePosix()}/**`;
            this.#ignore.add(ign);
          }
          const abs =
            this.opts.absolute === undefined ? absolute : this.opts.absolute;
          this.seen.add(e);
          const mark = this.opts.mark && e.isDirectory() ? this.#sep : '';
          // ok, we have what we need!
          if (this.opts.withFileTypes) {
            this.matchEmit(e);
          } else if (abs) {
            const abs = this.opts.posix ? e.fullpathPosix() : e.fullpath();
            this.matchEmit(abs + mark);
          } else {
            const rel = this.opts.posix ? e.relativePosix() : e.relative();
            const pre =
              this.opts.dotRelative && !rel.startsWith('..' + this.#sep)
                ? '.' + this.#sep
                : '';
            this.matchEmit(!rel ? '.' + mark : pre + rel + mark);
          }
        }
        async match(e, absolute, ifDir) {
          const p = await this.matchCheck(e, ifDir);
          if (p) this.matchFinish(p, absolute);
        }
        matchSync(e, absolute, ifDir) {
          const p = this.matchCheckSync(e, ifDir);
          if (p) this.matchFinish(p, absolute);
        }
        walkCB(target, patterns, cb) {
          /* c8 ignore start */
          if (this.signal?.aborted) cb();
          /* c8 ignore stop */
          this.walkCB2(
            target,
            patterns,
            new processor_js_1.Processor(this.opts),
            cb,
          );
        }
        walkCB2(target, patterns, processor, cb) {
          if (this.#childrenIgnored(target)) return cb();
          if (this.signal?.aborted) cb();
          if (this.paused) {
            this.onResume(() => this.walkCB2(target, patterns, processor, cb));
            return;
          }
          processor.processPatterns(target, patterns);
          // done processing.  all of the above is sync, can be abstracted out.
          // subwalks is a map of paths to the entry filters they need
          // matches is a map of paths to [absolute, ifDir] tuples.
          let tasks = 1;
          const next = () => {
            if (--tasks === 0) cb();
          };
          for (const [m, absolute, ifDir] of processor.matches.entries()) {
            if (this.#ignored(m)) continue;
            tasks++;
            this.match(m, absolute, ifDir).then(() => next());
          }
          for (const t of processor.subwalkTargets()) {
            if (this.maxDepth !== Infinity && t.depth() >= this.maxDepth) {
              continue;
            }
            tasks++;
            const childrenCached = t.readdirCached();
            if (t.calledReaddir())
              this.walkCB3(t, childrenCached, processor, next);
            else {
              t.readdirCB(
                (_, entries) => this.walkCB3(t, entries, processor, next),
                true,
              );
            }
          }
          next();
        }
        walkCB3(target, entries, processor, cb) {
          processor = processor.filterEntries(target, entries);
          let tasks = 1;
          const next = () => {
            if (--tasks === 0) cb();
          };
          for (const [m, absolute, ifDir] of processor.matches.entries()) {
            if (this.#ignored(m)) continue;
            tasks++;
            this.match(m, absolute, ifDir).then(() => next());
          }
          for (const [target, patterns] of processor.subwalks.entries()) {
            tasks++;
            this.walkCB2(target, patterns, processor.child(), next);
          }
          next();
        }
        walkCBSync(target, patterns, cb) {
          /* c8 ignore start */
          if (this.signal?.aborted) cb();
          /* c8 ignore stop */
          this.walkCB2Sync(
            target,
            patterns,
            new processor_js_1.Processor(this.opts),
            cb,
          );
        }
        walkCB2Sync(target, patterns, processor, cb) {
          if (this.#childrenIgnored(target)) return cb();
          if (this.signal?.aborted) cb();
          if (this.paused) {
            this.onResume(() =>
              this.walkCB2Sync(target, patterns, processor, cb),
            );
            return;
          }
          processor.processPatterns(target, patterns);
          // done processing.  all of the above is sync, can be abstracted out.
          // subwalks is a map of paths to the entry filters they need
          // matches is a map of paths to [absolute, ifDir] tuples.
          let tasks = 1;
          const next = () => {
            if (--tasks === 0) cb();
          };
          for (const [m, absolute, ifDir] of processor.matches.entries()) {
            if (this.#ignored(m)) continue;
            this.matchSync(m, absolute, ifDir);
          }
          for (const t of processor.subwalkTargets()) {
            if (this.maxDepth !== Infinity && t.depth() >= this.maxDepth) {
              continue;
            }
            tasks++;
            const children = t.readdirSync();
            this.walkCB3Sync(t, children, processor, next);
          }
          next();
        }
        walkCB3Sync(target, entries, processor, cb) {
          processor = processor.filterEntries(target, entries);
          let tasks = 1;
          const next = () => {
            if (--tasks === 0) cb();
          };
          for (const [m, absolute, ifDir] of processor.matches.entries()) {
            if (this.#ignored(m)) continue;
            this.matchSync(m, absolute, ifDir);
          }
          for (const [target, patterns] of processor.subwalks.entries()) {
            tasks++;
            this.walkCB2Sync(target, patterns, processor.child(), next);
          }
          next();
        }
      }
      exports.GlobUtil = GlobUtil;
      class GlobWalker extends GlobUtil {
        matches = new Set();
        constructor(patterns, path, opts) {
          super(patterns, path, opts);
        }
        matchEmit(e) {
          this.matches.add(e);
        }
        async walk() {
          if (this.signal?.aborted) throw this.signal.reason;
          if (this.path.isUnknown()) {
            await this.path.lstat();
          }
          await new Promise((res, rej) => {
            this.walkCB(this.path, this.patterns, () => {
              if (this.signal?.aborted) {
                rej(this.signal.reason);
              } else {
                res(this.matches);
              }
            });
          });
          return this.matches;
        }
        walkSync() {
          if (this.signal?.aborted) throw this.signal.reason;
          if (this.path.isUnknown()) {
            this.path.lstatSync();
          }
          // nothing for the callback to do, because this never pauses
          this.walkCBSync(this.path, this.patterns, () => {
            if (this.signal?.aborted) throw this.signal.reason;
          });
          return this.matches;
        }
      }
      exports.GlobWalker = GlobWalker;
      class GlobStream extends GlobUtil {
        results;
        constructor(patterns, path, opts) {
          super(patterns, path, opts);
          this.results = new minipass_1.Minipass({
            signal: this.signal,
            objectMode: true,
          });
          this.results.on('drain', () => this.resume());
          this.results.on('resume', () => this.resume());
        }
        matchEmit(e) {
          this.results.write(e);
          if (!this.results.flowing) this.pause();
        }
        stream() {
          const target = this.path;
          if (target.isUnknown()) {
            target.lstat().then(() => {
              this.walkCB(target, this.patterns, () => this.results.end());
            });
          } else {
            this.walkCB(target, this.patterns, () => this.results.end());
          }
          return this.results;
        }
        streamSync() {
          if (this.path.isUnknown()) {
            this.path.lstatSync();
          }
          this.walkCBSync(this.path, this.patterns, () => this.results.end());
          return this.results;
        }
      }
      exports.GlobStream = GlobStream;
      //# sourceMappingURL=walker.js.map

      /***/
    },

    /***/ 4606: /***/ (__unused_webpack_module, exports) => {
      'use strict';

      /**
       * @module LRUCache
       */
      Object.defineProperty(exports, '__esModule', { value: true });
      exports.LRUCache = void 0;
      const perf =
        typeof performance === 'object' &&
        performance &&
        typeof performance.now === 'function'
          ? performance
          : Date;
      const warned = new Set();
      /* c8 ignore start */
      const PROCESS = typeof process === 'object' && !!process ? process : {};
      /* c8 ignore start */
      const emitWarning = (msg, type, code, fn) => {
        typeof PROCESS.emitWarning === 'function'
          ? PROCESS.emitWarning(msg, type, code, fn)
          : console.error(`[${code}] ${type}: ${msg}`);
      };
      let AC = globalThis.AbortController;
      let AS = globalThis.AbortSignal;
      /* c8 ignore start */
      if (typeof AC === 'undefined') {
        //@ts-ignore
        AS = class AbortSignal {
          onabort;
          _onabort = [];
          reason;
          aborted = false;
          addEventListener(_, fn) {
            this._onabort.push(fn);
          }
        };
        //@ts-ignore
        AC = class AbortController {
          constructor() {
            warnACPolyfill();
          }
          signal = new AS();
          abort(reason) {
            if (this.signal.aborted) return;
            //@ts-ignore
            this.signal.reason = reason;
            //@ts-ignore
            this.signal.aborted = true;
            //@ts-ignore
            for (const fn of this.signal._onabort) {
              fn(reason);
            }
            this.signal.onabort?.(reason);
          }
        };
        let printACPolyfillWarning =
          PROCESS.env?.LRU_CACHE_IGNORE_AC_WARNING !== '1';
        const warnACPolyfill = () => {
          if (!printACPolyfillWarning) return;
          printACPolyfillWarning = false;
          emitWarning(
            'AbortController is not defined. If using lru-cache in ' +
              'node 14, load an AbortController polyfill from the ' +
              '`node-abort-controller` package. A minimal polyfill is ' +
              'provided for use by LRUCache.fetch(), but it should not be ' +
              'relied upon in other contexts (eg, passing it to other APIs that ' +
              'use AbortController/AbortSignal might have undesirable effects). ' +
              'You may disable this with LRU_CACHE_IGNORE_AC_WARNING=1 in the env.',
            'NO_ABORT_CONTROLLER',
            'ENOTSUP',
            warnACPolyfill,
          );
        };
      }
      /* c8 ignore stop */
      const shouldWarn = (code) => !warned.has(code);
      const TYPE = Symbol('type');
      const isPosInt = (n) => n && n === Math.floor(n) && n > 0 && isFinite(n);
      /* c8 ignore start */
      // This is a little bit ridiculous, tbh.
      // The maximum array length is 2^32-1 or thereabouts on most JS impls.
      // And well before that point, you're caching the entire world, I mean,
      // that's ~32GB of just integers for the next/prev links, plus whatever
      // else to hold that many keys and values.  Just filling the memory with
      // zeroes at init time is brutal when you get that big.
      // But why not be complete?
      // Maybe in the future, these limits will have expanded.
      const getUintArray = (max) =>
        !isPosInt(max)
          ? null
          : max <= Math.pow(2, 8)
            ? Uint8Array
            : max <= Math.pow(2, 16)
              ? Uint16Array
              : max <= Math.pow(2, 32)
                ? Uint32Array
                : max <= Number.MAX_SAFE_INTEGER
                  ? ZeroArray
                  : null;
      /* c8 ignore stop */
      class ZeroArray extends Array {
        constructor(size) {
          super(size);
          this.fill(0);
        }
      }
      class Stack {
        heap;
        length;
        // private constructor
        static #constructing = false;
        static create(max) {
          const HeapCls = getUintArray(max);
          if (!HeapCls) return [];
          Stack.#constructing = true;
          const s = new Stack(max, HeapCls);
          Stack.#constructing = false;
          return s;
        }
        constructor(max, HeapCls) {
          /* c8 ignore start */
          if (!Stack.#constructing) {
            throw new TypeError('instantiate Stack using Stack.create(n)');
          }
          /* c8 ignore stop */
          this.heap = new HeapCls(max);
          this.length = 0;
        }
        push(n) {
          this.heap[this.length++] = n;
        }
        pop() {
          return this.heap[--this.length];
        }
      }
      /**
       * Default export, the thing you're using this module to get.
       *
       * The `K` and `V` types define the key and value types, respectively. The
       * optional `FC` type defines the type of the `context` object passed to
       * `cache.fetch()` and `cache.memo()`.
       *
       * Keys and values **must not** be `null` or `undefined`.
       *
       * All properties from the options object (with the exception of `max`,
       * `maxSize`, `fetchMethod`, `memoMethod`, `dispose` and `disposeAfter`) are
       * added as normal public members. (The listed options are read-only getters.)
       *
       * Changing any of these will alter the defaults for subsequent method calls.
       */
      class LRUCache {
        // options that cannot be changed without disaster
        #max;
        #maxSize;
        #dispose;
        #disposeAfter;
        #fetchMethod;
        #memoMethod;
        /**
         * {@link LRUCache.OptionsBase.ttl}
         */
        ttl;
        /**
         * {@link LRUCache.OptionsBase.ttlResolution}
         */
        ttlResolution;
        /**
         * {@link LRUCache.OptionsBase.ttlAutopurge}
         */
        ttlAutopurge;
        /**
         * {@link LRUCache.OptionsBase.updateAgeOnGet}
         */
        updateAgeOnGet;
        /**
         * {@link LRUCache.OptionsBase.updateAgeOnHas}
         */
        updateAgeOnHas;
        /**
         * {@link LRUCache.OptionsBase.allowStale}
         */
        allowStale;
        /**
         * {@link LRUCache.OptionsBase.noDisposeOnSet}
         */
        noDisposeOnSet;
        /**
         * {@link LRUCache.OptionsBase.noUpdateTTL}
         */
        noUpdateTTL;
        /**
         * {@link LRUCache.OptionsBase.maxEntrySize}
         */
        maxEntrySize;
        /**
         * {@link LRUCache.OptionsBase.sizeCalculation}
         */
        sizeCalculation;
        /**
         * {@link LRUCache.OptionsBase.noDeleteOnFetchRejection}
         */
        noDeleteOnFetchRejection;
        /**
         * {@link LRUCache.OptionsBase.noDeleteOnStaleGet}
         */
        noDeleteOnStaleGet;
        /**
         * {@link LRUCache.OptionsBase.allowStaleOnFetchAbort}
         */
        allowStaleOnFetchAbort;
        /**
         * {@link LRUCache.OptionsBase.allowStaleOnFetchRejection}
         */
        allowStaleOnFetchRejection;
        /**
         * {@link LRUCache.OptionsBase.ignoreFetchAbort}
         */
        ignoreFetchAbort;
        // computed properties
        #size;
        #calculatedSize;
        #keyMap;
        #keyList;
        #valList;
        #next;
        #prev;
        #head;
        #tail;
        #free;
        #disposed;
        #sizes;
        #starts;
        #ttls;
        #hasDispose;
        #hasFetchMethod;
        #hasDisposeAfter;
        /**
         * Do not call this method unless you need to inspect the
         * inner workings of the cache.  If anything returned by this
         * object is modified in any way, strange breakage may occur.
         *
         * These fields are private for a reason!
         *
         * @internal
         */
        static unsafeExposeInternals(c) {
          return {
            // properties
            starts: c.#starts,
            ttls: c.#ttls,
            sizes: c.#sizes,
            keyMap: c.#keyMap,
            keyList: c.#keyList,
            valList: c.#valList,
            next: c.#next,
            prev: c.#prev,
            get head() {
              return c.#head;
            },
            get tail() {
              return c.#tail;
            },
            free: c.#free,
            // methods
            isBackgroundFetch: (p) => c.#isBackgroundFetch(p),
            backgroundFetch: (k, index, options, context) =>
              c.#backgroundFetch(k, index, options, context),
            moveToTail: (index) => c.#moveToTail(index),
            indexes: (options) => c.#indexes(options),
            rindexes: (options) => c.#rindexes(options),
            isStale: (index) => c.#isStale(index),
          };
        }
        // Protected read-only members
        /**
         * {@link LRUCache.OptionsBase.max} (read-only)
         */
        get max() {
          return this.#max;
        }
        /**
         * {@link LRUCache.OptionsBase.maxSize} (read-only)
         */
        get maxSize() {
          return this.#maxSize;
        }
        /**
         * The total computed size of items in the cache (read-only)
         */
        get calculatedSize() {
          return this.#calculatedSize;
        }
        /**
         * The number of items stored in the cache (read-only)
         */
        get size() {
          return this.#size;
        }
        /**
         * {@link LRUCache.OptionsBase.fetchMethod} (read-only)
         */
        get fetchMethod() {
          return this.#fetchMethod;
        }
        get memoMethod() {
          return this.#memoMethod;
        }
        /**
         * {@link LRUCache.OptionsBase.dispose} (read-only)
         */
        get dispose() {
          return this.#dispose;
        }
        /**
         * {@link LRUCache.OptionsBase.disposeAfter} (read-only)
         */
        get disposeAfter() {
          return this.#disposeAfter;
        }
        constructor(options) {
          const {
            max = 0,
            ttl,
            ttlResolution = 1,
            ttlAutopurge,
            updateAgeOnGet,
            updateAgeOnHas,
            allowStale,
            dispose,
            disposeAfter,
            noDisposeOnSet,
            noUpdateTTL,
            maxSize = 0,
            maxEntrySize = 0,
            sizeCalculation,
            fetchMethod,
            memoMethod,
            noDeleteOnFetchRejection,
            noDeleteOnStaleGet,
            allowStaleOnFetchRejection,
            allowStaleOnFetchAbort,
            ignoreFetchAbort,
          } = options;
          if (max !== 0 && !isPosInt(max)) {
            throw new TypeError('max option must be a nonnegative integer');
          }
          const UintArray = max ? getUintArray(max) : Array;
          if (!UintArray) {
            throw new Error('invalid max value: ' + max);
          }
          this.#max = max;
          this.#maxSize = maxSize;
          this.maxEntrySize = maxEntrySize || this.#maxSize;
          this.sizeCalculation = sizeCalculation;
          if (this.sizeCalculation) {
            if (!this.#maxSize && !this.maxEntrySize) {
              throw new TypeError(
                'cannot set sizeCalculation without setting maxSize or maxEntrySize',
              );
            }
            if (typeof this.sizeCalculation !== 'function') {
              throw new TypeError('sizeCalculation set to non-function');
            }
          }
          if (memoMethod !== undefined && typeof memoMethod !== 'function') {
            throw new TypeError('memoMethod must be a function if defined');
          }
          this.#memoMethod = memoMethod;
          if (fetchMethod !== undefined && typeof fetchMethod !== 'function') {
            throw new TypeError('fetchMethod must be a function if specified');
          }
          this.#fetchMethod = fetchMethod;
          this.#hasFetchMethod = !!fetchMethod;
          this.#keyMap = new Map();
          this.#keyList = new Array(max).fill(undefined);
          this.#valList = new Array(max).fill(undefined);
          this.#next = new UintArray(max);
          this.#prev = new UintArray(max);
          this.#head = 0;
          this.#tail = 0;
          this.#free = Stack.create(max);
          this.#size = 0;
          this.#calculatedSize = 0;
          if (typeof dispose === 'function') {
            this.#dispose = dispose;
          }
          if (typeof disposeAfter === 'function') {
            this.#disposeAfter = disposeAfter;
            this.#disposed = [];
          } else {
            this.#disposeAfter = undefined;
            this.#disposed = undefined;
          }
          this.#hasDispose = !!this.#dispose;
          this.#hasDisposeAfter = !!this.#disposeAfter;
          this.noDisposeOnSet = !!noDisposeOnSet;
          this.noUpdateTTL = !!noUpdateTTL;
          this.noDeleteOnFetchRejection = !!noDeleteOnFetchRejection;
          this.allowStaleOnFetchRejection = !!allowStaleOnFetchRejection;
          this.allowStaleOnFetchAbort = !!allowStaleOnFetchAbort;
          this.ignoreFetchAbort = !!ignoreFetchAbort;
          // NB: maxEntrySize is set to maxSize if it's set
          if (this.maxEntrySize !== 0) {
            if (this.#maxSize !== 0) {
              if (!isPosInt(this.#maxSize)) {
                throw new TypeError(
                  'maxSize must be a positive integer if specified',
                );
              }
            }
            if (!isPosInt(this.maxEntrySize)) {
              throw new TypeError(
                'maxEntrySize must be a positive integer if specified',
              );
            }
            this.#initializeSizeTracking();
          }
          this.allowStale = !!allowStale;
          this.noDeleteOnStaleGet = !!noDeleteOnStaleGet;
          this.updateAgeOnGet = !!updateAgeOnGet;
          this.updateAgeOnHas = !!updateAgeOnHas;
          this.ttlResolution =
            isPosInt(ttlResolution) || ttlResolution === 0 ? ttlResolution : 1;
          this.ttlAutopurge = !!ttlAutopurge;
          this.ttl = ttl || 0;
          if (this.ttl) {
            if (!isPosInt(this.ttl)) {
              throw new TypeError(
                'ttl must be a positive integer if specified',
              );
            }
            this.#initializeTTLTracking();
          }
          // do not allow completely unbounded caches
          if (this.#max === 0 && this.ttl === 0 && this.#maxSize === 0) {
            throw new TypeError(
              'At least one of max, maxSize, or ttl is required',
            );
          }
          if (!this.ttlAutopurge && !this.#max && !this.#maxSize) {
            const code = 'LRU_CACHE_UNBOUNDED';
            if (shouldWarn(code)) {
              warned.add(code);
              const msg =
                'TTL caching without ttlAutopurge, max, or maxSize can ' +
                'result in unbounded memory consumption.';
              emitWarning(msg, 'UnboundedCacheWarning', code, LRUCache);
            }
          }
        }
        /**
         * Return the number of ms left in the item's TTL. If item is not in cache,
         * returns `0`. Returns `Infinity` if item is in cache without a defined TTL.
         */
        getRemainingTTL(key) {
          return this.#keyMap.has(key) ? Infinity : 0;
        }
        #initializeTTLTracking() {
          const ttls = new ZeroArray(this.#max);
          const starts = new ZeroArray(this.#max);
          this.#ttls = ttls;
          this.#starts = starts;
          this.#setItemTTL = (index, ttl, start = perf.now()) => {
            starts[index] = ttl !== 0 ? start : 0;
            ttls[index] = ttl;
            if (ttl !== 0 && this.ttlAutopurge) {
              const t = setTimeout(() => {
                if (this.#isStale(index)) {
                  this.#delete(this.#keyList[index], 'expire');
                }
              }, ttl + 1);
              // unref() not supported on all platforms
              /* c8 ignore start */
              if (t.unref) {
                t.unref();
              }
              /* c8 ignore stop */
            }
          };
          this.#updateItemAge = (index) => {
            starts[index] = ttls[index] !== 0 ? perf.now() : 0;
          };
          this.#statusTTL = (status, index) => {
            if (ttls[index]) {
              const ttl = ttls[index];
              const start = starts[index];
              /* c8 ignore next */
              if (!ttl || !start) return;
              status.ttl = ttl;
              status.start = start;
              status.now = cachedNow || getNow();
              const age = status.now - start;
              status.remainingTTL = ttl - age;
            }
          };
          // debounce calls to perf.now() to 1s so we're not hitting
          // that costly call repeatedly.
          let cachedNow = 0;
          const getNow = () => {
            const n = perf.now();
            if (this.ttlResolution > 0) {
              cachedNow = n;
              const t = setTimeout(() => (cachedNow = 0), this.ttlResolution);
              // not available on all platforms
              /* c8 ignore start */
              if (t.unref) {
                t.unref();
              }
              /* c8 ignore stop */
            }
            return n;
          };
          this.getRemainingTTL = (key) => {
            const index = this.#keyMap.get(key);
            if (index === undefined) {
              return 0;
            }
            const ttl = ttls[index];
            const start = starts[index];
            if (!ttl || !start) {
              return Infinity;
            }
            const age = (cachedNow || getNow()) - start;
            return ttl - age;
          };
          this.#isStale = (index) => {
            const s = starts[index];
            const t = ttls[index];
            return !!t && !!s && (cachedNow || getNow()) - s > t;
          };
        }
        // conditionally set private methods related to TTL
        #updateItemAge = () => {};
        #statusTTL = () => {};
        #setItemTTL = () => {};
        /* c8 ignore stop */
        #isStale = () => false;
        #initializeSizeTracking() {
          const sizes = new ZeroArray(this.#max);
          this.#calculatedSize = 0;
          this.#sizes = sizes;
          this.#removeItemSize = (index) => {
            this.#calculatedSize -= sizes[index];
            sizes[index] = 0;
          };
          this.#requireSize = (k, v, size, sizeCalculation) => {
            // provisionally accept background fetches.
            // actual value size will be checked when they return.
            if (this.#isBackgroundFetch(v)) {
              return 0;
            }
            if (!isPosInt(size)) {
              if (sizeCalculation) {
                if (typeof sizeCalculation !== 'function') {
                  throw new TypeError('sizeCalculation must be a function');
                }
                size = sizeCalculation(v, k);
                if (!isPosInt(size)) {
                  throw new TypeError(
                    'sizeCalculation return invalid (expect positive integer)',
                  );
                }
              } else {
                throw new TypeError(
                  'invalid size value (must be positive integer). ' +
                    'When maxSize or maxEntrySize is used, sizeCalculation ' +
                    'or size must be set.',
                );
              }
            }
            return size;
          };
          this.#addItemSize = (index, size, status) => {
            sizes[index] = size;
            if (this.#maxSize) {
              const maxSize = this.#maxSize - sizes[index];
              while (this.#calculatedSize > maxSize) {
                this.#evict(true);
              }
            }
            this.#calculatedSize += sizes[index];
            if (status) {
              status.entrySize = size;
              status.totalCalculatedSize = this.#calculatedSize;
            }
          };
        }
        #removeItemSize = (_i) => {};
        #addItemSize = (_i, _s, _st) => {};
        #requireSize = (_k, _v, size, sizeCalculation) => {
          if (size || sizeCalculation) {
            throw new TypeError(
              'cannot set size without setting maxSize or maxEntrySize on cache',
            );
          }
          return 0;
        };
        *#indexes({ allowStale = this.allowStale } = {}) {
          if (this.#size) {
            for (let i = this.#tail; true; ) {
              if (!this.#isValidIndex(i)) {
                break;
              }
              if (allowStale || !this.#isStale(i)) {
                yield i;
              }
              if (i === this.#head) {
                break;
              } else {
                i = this.#prev[i];
              }
            }
          }
        }
        *#rindexes({ allowStale = this.allowStale } = {}) {
          if (this.#size) {
            for (let i = this.#head; true; ) {
              if (!this.#isValidIndex(i)) {
                break;
              }
              if (allowStale || !this.#isStale(i)) {
                yield i;
              }
              if (i === this.#tail) {
                break;
              } else {
                i = this.#next[i];
              }
            }
          }
        }
        #isValidIndex(index) {
          return (
            index !== undefined &&
            this.#keyMap.get(this.#keyList[index]) === index
          );
        }
        /**
         * Return a generator yielding `[key, value]` pairs,
         * in order from most recently used to least recently used.
         */
        *entries() {
          for (const i of this.#indexes()) {
            if (
              this.#valList[i] !== undefined &&
              this.#keyList[i] !== undefined &&
              !this.#isBackgroundFetch(this.#valList[i])
            ) {
              yield [this.#keyList[i], this.#valList[i]];
            }
          }
        }
        /**
         * Inverse order version of {@link LRUCache.entries}
         *
         * Return a generator yielding `[key, value]` pairs,
         * in order from least recently used to most recently used.
         */
        *rentries() {
          for (const i of this.#rindexes()) {
            if (
              this.#valList[i] !== undefined &&
              this.#keyList[i] !== undefined &&
              !this.#isBackgroundFetch(this.#valList[i])
            ) {
              yield [this.#keyList[i], this.#valList[i]];
            }
          }
        }
        /**
         * Return a generator yielding the keys in the cache,
         * in order from most recently used to least recently used.
         */
        *keys() {
          for (const i of this.#indexes()) {
            const k = this.#keyList[i];
            if (k !== undefined && !this.#isBackgroundFetch(this.#valList[i])) {
              yield k;
            }
          }
        }
        /**
         * Inverse order version of {@link LRUCache.keys}
         *
         * Return a generator yielding the keys in the cache,
         * in order from least recently used to most recently used.
         */
        *rkeys() {
          for (const i of this.#rindexes()) {
            const k = this.#keyList[i];
            if (k !== undefined && !this.#isBackgroundFetch(this.#valList[i])) {
              yield k;
            }
          }
        }
        /**
         * Return a generator yielding the values in the cache,
         * in order from most recently used to least recently used.
         */
        *values() {
          for (const i of this.#indexes()) {
            const v = this.#valList[i];
            if (v !== undefined && !this.#isBackgroundFetch(this.#valList[i])) {
              yield this.#valList[i];
            }
          }
        }
        /**
         * Inverse order version of {@link LRUCache.values}
         *
         * Return a generator yielding the values in the cache,
         * in order from least recently used to most recently used.
         */
        *rvalues() {
          for (const i of this.#rindexes()) {
            const v = this.#valList[i];
            if (v !== undefined && !this.#isBackgroundFetch(this.#valList[i])) {
              yield this.#valList[i];
            }
          }
        }
        /**
         * Iterating over the cache itself yields the same results as
         * {@link LRUCache.entries}
         */
        [Symbol.iterator]() {
          return this.entries();
        }
        /**
         * A String value that is used in the creation of the default string
         * description of an object. Called by the built-in method
         * `Object.prototype.toString`.
         */
        [Symbol.toStringTag] = 'LRUCache';
        /**
         * Find a value for which the supplied fn method returns a truthy value,
         * similar to `Array.find()`. fn is called as `fn(value, key, cache)`.
         */
        find(fn, getOptions = {}) {
          for (const i of this.#indexes()) {
            const v = this.#valList[i];
            const value = this.#isBackgroundFetch(v)
              ? v.__staleWhileFetching
              : v;
            if (value === undefined) continue;
            if (fn(value, this.#keyList[i], this)) {
              return this.get(this.#keyList[i], getOptions);
            }
          }
        }
        /**
         * Call the supplied function on each item in the cache, in order from most
         * recently used to least recently used.
         *
         * `fn` is called as `fn(value, key, cache)`.
         *
         * If `thisp` is provided, function will be called in the `this`-context of
         * the provided object, or the cache if no `thisp` object is provided.
         *
         * Does not update age or recenty of use, or iterate over stale values.
         */
        forEach(fn, thisp = this) {
          for (const i of this.#indexes()) {
            const v = this.#valList[i];
            const value = this.#isBackgroundFetch(v)
              ? v.__staleWhileFetching
              : v;
            if (value === undefined) continue;
            fn.call(thisp, value, this.#keyList[i], this);
          }
        }
        /**
         * The same as {@link LRUCache.forEach} but items are iterated over in
         * reverse order.  (ie, less recently used items are iterated over first.)
         */
        rforEach(fn, thisp = this) {
          for (const i of this.#rindexes()) {
            const v = this.#valList[i];
            const value = this.#isBackgroundFetch(v)
              ? v.__staleWhileFetching
              : v;
            if (value === undefined) continue;
            fn.call(thisp, value, this.#keyList[i], this);
          }
        }
        /**
         * Delete any stale entries. Returns true if anything was removed,
         * false otherwise.
         */
        purgeStale() {
          let deleted = false;
          for (const i of this.#rindexes({ allowStale: true })) {
            if (this.#isStale(i)) {
              this.#delete(this.#keyList[i], 'expire');
              deleted = true;
            }
          }
          return deleted;
        }
        /**
         * Get the extended info about a given entry, to get its value, size, and
         * TTL info simultaneously. Returns `undefined` if the key is not present.
         *
         * Unlike {@link LRUCache#dump}, which is designed to be portable and survive
         * serialization, the `start` value is always the current timestamp, and the
         * `ttl` is a calculated remaining time to live (negative if expired).
         *
         * Always returns stale values, if their info is found in the cache, so be
         * sure to check for expirations (ie, a negative {@link LRUCache.Entry#ttl})
         * if relevant.
         */
        info(key) {
          const i = this.#keyMap.get(key);
          if (i === undefined) return undefined;
          const v = this.#valList[i];
          const value = this.#isBackgroundFetch(v) ? v.__staleWhileFetching : v;
          if (value === undefined) return undefined;
          const entry = { value };
          if (this.#ttls && this.#starts) {
            const ttl = this.#ttls[i];
            const start = this.#starts[i];
            if (ttl && start) {
              const remain = ttl - (perf.now() - start);
              entry.ttl = remain;
              entry.start = Date.now();
            }
          }
          if (this.#sizes) {
            entry.size = this.#sizes[i];
          }
          return entry;
        }
        /**
         * Return an array of [key, {@link LRUCache.Entry}] tuples which can be
         * passed to {@link LRLUCache#load}.
         *
         * The `start` fields are calculated relative to a portable `Date.now()`
         * timestamp, even if `performance.now()` is available.
         *
         * Stale entries are always included in the `dump`, even if
         * {@link LRUCache.OptionsBase.allowStale} is false.
         *
         * Note: this returns an actual array, not a generator, so it can be more
         * easily passed around.
         */
        dump() {
          const arr = [];
          for (const i of this.#indexes({ allowStale: true })) {
            const key = this.#keyList[i];
            const v = this.#valList[i];
            const value = this.#isBackgroundFetch(v)
              ? v.__staleWhileFetching
              : v;
            if (value === undefined || key === undefined) continue;
            const entry = { value };
            if (this.#ttls && this.#starts) {
              entry.ttl = this.#ttls[i];
              // always dump the start relative to a portable timestamp
              // it's ok for this to be a bit slow, it's a rare operation.
              const age = perf.now() - this.#starts[i];
              entry.start = Math.floor(Date.now() - age);
            }
            if (this.#sizes) {
              entry.size = this.#sizes[i];
            }
            arr.unshift([key, entry]);
          }
          return arr;
        }
        /**
         * Reset the cache and load in the items in entries in the order listed.
         *
         * The shape of the resulting cache may be different if the same options are
         * not used in both caches.
         *
         * The `start` fields are assumed to be calculated relative to a portable
         * `Date.now()` timestamp, even if `performance.now()` is available.
         */
        load(arr) {
          this.clear();
          for (const [key, entry] of arr) {
            if (entry.start) {
              // entry.start is a portable timestamp, but we may be using
              // node's performance.now(), so calculate the offset, so that
              // we get the intended remaining TTL, no matter how long it's
              // been on ice.
              //
              // it's ok for this to be a bit slow, it's a rare operation.
              const age = Date.now() - entry.start;
              entry.start = perf.now() - age;
            }
            this.set(key, entry.value, entry);
          }
        }
        /**
         * Add a value to the cache.
         *
         * Note: if `undefined` is specified as a value, this is an alias for
         * {@link LRUCache#delete}
         *
         * Fields on the {@link LRUCache.SetOptions} options param will override
         * their corresponding values in the constructor options for the scope
         * of this single `set()` operation.
         *
         * If `start` is provided, then that will set the effective start
         * time for the TTL calculation. Note that this must be a previous
         * value of `performance.now()` if supported, or a previous value of
         * `Date.now()` if not.
         *
         * Options object may also include `size`, which will prevent
         * calling the `sizeCalculation` function and just use the specified
         * number if it is a positive integer, and `noDisposeOnSet` which
         * will prevent calling a `dispose` function in the case of
         * overwrites.
         *
         * If the `size` (or return value of `sizeCalculation`) for a given
         * entry is greater than `maxEntrySize`, then the item will not be
         * added to the cache.
         *
         * Will update the recency of the entry.
         *
         * If the value is `undefined`, then this is an alias for
         * `cache.delete(key)`. `undefined` is never stored in the cache.
         */
        set(k, v, setOptions = {}) {
          if (v === undefined) {
            this.delete(k);
            return this;
          }
          const {
            ttl = this.ttl,
            start,
            noDisposeOnSet = this.noDisposeOnSet,
            sizeCalculation = this.sizeCalculation,
            status,
          } = setOptions;
          let { noUpdateTTL = this.noUpdateTTL } = setOptions;
          const size = this.#requireSize(
            k,
            v,
            setOptions.size || 0,
            sizeCalculation,
          );
          // if the item doesn't fit, don't do anything
          // NB: maxEntrySize set to maxSize by default
          if (this.maxEntrySize && size > this.maxEntrySize) {
            if (status) {
              status.set = 'miss';
              status.maxEntrySizeExceeded = true;
            }
            // have to delete, in case something is there already.
            this.#delete(k, 'set');
            return this;
          }
          let index = this.#size === 0 ? undefined : this.#keyMap.get(k);
          if (index === undefined) {
            // addition
            index =
              this.#size === 0
                ? this.#tail
                : this.#free.length !== 0
                  ? this.#free.pop()
                  : this.#size === this.#max
                    ? this.#evict(false)
                    : this.#size;
            this.#keyList[index] = k;
            this.#valList[index] = v;
            this.#keyMap.set(k, index);
            this.#next[this.#tail] = index;
            this.#prev[index] = this.#tail;
            this.#tail = index;
            this.#size++;
            this.#addItemSize(index, size, status);
            if (status) status.set = 'add';
            noUpdateTTL = false;
          } else {
            // update
            this.#moveToTail(index);
            const oldVal = this.#valList[index];
            if (v !== oldVal) {
              if (this.#hasFetchMethod && this.#isBackgroundFetch(oldVal)) {
                oldVal.__abortController.abort(new Error('replaced'));
                const { __staleWhileFetching: s } = oldVal;
                if (s !== undefined && !noDisposeOnSet) {
                  if (this.#hasDispose) {
                    this.#dispose?.(s, k, 'set');
                  }
                  if (this.#hasDisposeAfter) {
                    this.#disposed?.push([s, k, 'set']);
                  }
                }
              } else if (!noDisposeOnSet) {
                if (this.#hasDispose) {
                  this.#dispose?.(oldVal, k, 'set');
                }
                if (this.#hasDisposeAfter) {
                  this.#disposed?.push([oldVal, k, 'set']);
                }
              }
              this.#removeItemSize(index);
              this.#addItemSize(index, size, status);
              this.#valList[index] = v;
              if (status) {
                status.set = 'replace';
                const oldValue =
                  oldVal && this.#isBackgroundFetch(oldVal)
                    ? oldVal.__staleWhileFetching
                    : oldVal;
                if (oldValue !== undefined) status.oldValue = oldValue;
              }
            } else if (status) {
              status.set = 'update';
            }
          }
          if (ttl !== 0 && !this.#ttls) {
            this.#initializeTTLTracking();
          }
          if (this.#ttls) {
            if (!noUpdateTTL) {
              this.#setItemTTL(index, ttl, start);
            }
            if (status) this.#statusTTL(status, index);
          }
          if (!noDisposeOnSet && this.#hasDisposeAfter && this.#disposed) {
            const dt = this.#disposed;
            let task;
            while ((task = dt?.shift())) {
              this.#disposeAfter?.(...task);
            }
          }
          return this;
        }
        /**
         * Evict the least recently used item, returning its value or
         * `undefined` if cache is empty.
         */
        pop() {
          try {
            while (this.#size) {
              const val = this.#valList[this.#head];
              this.#evict(true);
              if (this.#isBackgroundFetch(val)) {
                if (val.__staleWhileFetching) {
                  return val.__staleWhileFetching;
                }
              } else if (val !== undefined) {
                return val;
              }
            }
          } finally {
            if (this.#hasDisposeAfter && this.#disposed) {
              const dt = this.#disposed;
              let task;
              while ((task = dt?.shift())) {
                this.#disposeAfter?.(...task);
              }
            }
          }
        }
        #evict(free) {
          const head = this.#head;
          const k = this.#keyList[head];
          const v = this.#valList[head];
          if (this.#hasFetchMethod && this.#isBackgroundFetch(v)) {
            v.__abortController.abort(new Error('evicted'));
          } else if (this.#hasDispose || this.#hasDisposeAfter) {
            if (this.#hasDispose) {
              this.#dispose?.(v, k, 'evict');
            }
            if (this.#hasDisposeAfter) {
              this.#disposed?.push([v, k, 'evict']);
            }
          }
          this.#removeItemSize(head);
          // if we aren't about to use the index, then null these out
          if (free) {
            this.#keyList[head] = undefined;
            this.#valList[head] = undefined;
            this.#free.push(head);
          }
          if (this.#size === 1) {
            this.#head = this.#tail = 0;
            this.#free.length = 0;
          } else {
            this.#head = this.#next[head];
          }
          this.#keyMap.delete(k);
          this.#size--;
          return head;
        }
        /**
         * Check if a key is in the cache, without updating the recency of use.
         * Will return false if the item is stale, even though it is technically
         * in the cache.
         *
         * Check if a key is in the cache, without updating the recency of
         * use. Age is updated if {@link LRUCache.OptionsBase.updateAgeOnHas} is set
         * to `true` in either the options or the constructor.
         *
         * Will return `false` if the item is stale, even though it is technically in
         * the cache. The difference can be determined (if it matters) by using a
         * `status` argument, and inspecting the `has` field.
         *
         * Will not update item age unless
         * {@link LRUCache.OptionsBase.updateAgeOnHas} is set.
         */
        has(k, hasOptions = {}) {
          const { updateAgeOnHas = this.updateAgeOnHas, status } = hasOptions;
          const index = this.#keyMap.get(k);
          if (index !== undefined) {
            const v = this.#valList[index];
            if (
              this.#isBackgroundFetch(v) &&
              v.__staleWhileFetching === undefined
            ) {
              return false;
            }
            if (!this.#isStale(index)) {
              if (updateAgeOnHas) {
                this.#updateItemAge(index);
              }
              if (status) {
                status.has = 'hit';
                this.#statusTTL(status, index);
              }
              return true;
            } else if (status) {
              status.has = 'stale';
              this.#statusTTL(status, index);
            }
          } else if (status) {
            status.has = 'miss';
          }
          return false;
        }
        /**
         * Like {@link LRUCache#get} but doesn't update recency or delete stale
         * items.
         *
         * Returns `undefined` if the item is stale, unless
         * {@link LRUCache.OptionsBase.allowStale} is set.
         */
        peek(k, peekOptions = {}) {
          const { allowStale = this.allowStale } = peekOptions;
          const index = this.#keyMap.get(k);
          if (index === undefined || (!allowStale && this.#isStale(index))) {
            return;
          }
          const v = this.#valList[index];
          // either stale and allowed, or forcing a refresh of non-stale value
          return this.#isBackgroundFetch(v) ? v.__staleWhileFetching : v;
        }
        #backgroundFetch(k, index, options, context) {
          const v = index === undefined ? undefined : this.#valList[index];
          if (this.#isBackgroundFetch(v)) {
            return v;
          }
          const ac = new AC();
          const { signal } = options;
          // when/if our AC signals, then stop listening to theirs.
          signal?.addEventListener('abort', () => ac.abort(signal.reason), {
            signal: ac.signal,
          });
          const fetchOpts = {
            signal: ac.signal,
            options,
            context,
          };
          const cb = (v, updateCache = false) => {
            const { aborted } = ac.signal;
            const ignoreAbort = options.ignoreFetchAbort && v !== undefined;
            if (options.status) {
              if (aborted && !updateCache) {
                options.status.fetchAborted = true;
                options.status.fetchError = ac.signal.reason;
                if (ignoreAbort) options.status.fetchAbortIgnored = true;
              } else {
                options.status.fetchResolved = true;
              }
            }
            if (aborted && !ignoreAbort && !updateCache) {
              return fetchFail(ac.signal.reason);
            }
            // either we didn't abort, and are still here, or we did, and ignored
            const bf = p;
            if (this.#valList[index] === p) {
              if (v === undefined) {
                if (bf.__staleWhileFetching) {
                  this.#valList[index] = bf.__staleWhileFetching;
                } else {
                  this.#delete(k, 'fetch');
                }
              } else {
                if (options.status) options.status.fetchUpdated = true;
                this.set(k, v, fetchOpts.options);
              }
            }
            return v;
          };
          const eb = (er) => {
            if (options.status) {
              options.status.fetchRejected = true;
              options.status.fetchError = er;
            }
            return fetchFail(er);
          };
          const fetchFail = (er) => {
            const { aborted } = ac.signal;
            const allowStaleAborted = aborted && options.allowStaleOnFetchAbort;
            const allowStale =
              allowStaleAborted || options.allowStaleOnFetchRejection;
            const noDelete = allowStale || options.noDeleteOnFetchRejection;
            const bf = p;
            if (this.#valList[index] === p) {
              // if we allow stale on fetch rejections, then we need to ensure that
              // the stale value is not removed from the cache when the fetch fails.
              const del = !noDelete || bf.__staleWhileFetching === undefined;
              if (del) {
                this.#delete(k, 'fetch');
              } else if (!allowStaleAborted) {
                // still replace the *promise* with the stale value,
                // since we are done with the promise at this point.
                // leave it untouched if we're still waiting for an
                // aborted background fetch that hasn't yet returned.
                this.#valList[index] = bf.__staleWhileFetching;
              }
            }
            if (allowStale) {
              if (options.status && bf.__staleWhileFetching !== undefined) {
                options.status.returnedStale = true;
              }
              return bf.__staleWhileFetching;
            } else if (bf.__returned === bf) {
              throw er;
            }
          };
          const pcall = (res, rej) => {
            const fmp = this.#fetchMethod?.(k, v, fetchOpts);
            if (fmp && fmp instanceof Promise) {
              fmp.then((v) => res(v === undefined ? undefined : v), rej);
            }
            // ignored, we go until we finish, regardless.
            // defer check until we are actually aborting,
            // so fetchMethod can override.
            ac.signal.addEventListener('abort', () => {
              if (!options.ignoreFetchAbort || options.allowStaleOnFetchAbort) {
                res(undefined);
                // when it eventually resolves, update the cache.
                if (options.allowStaleOnFetchAbort) {
                  res = (v) => cb(v, true);
                }
              }
            });
          };
          if (options.status) options.status.fetchDispatched = true;
          const p = new Promise(pcall).then(cb, eb);
          const bf = Object.assign(p, {
            __abortController: ac,
            __staleWhileFetching: v,
            __returned: undefined,
          });
          if (index === undefined) {
            // internal, don't expose status.
            this.set(k, bf, { ...fetchOpts.options, status: undefined });
            index = this.#keyMap.get(k);
          } else {
            this.#valList[index] = bf;
          }
          return bf;
        }
        #isBackgroundFetch(p) {
          if (!this.#hasFetchMethod) return false;
          const b = p;
          return (
            !!b &&
            b instanceof Promise &&
            b.hasOwnProperty('__staleWhileFetching') &&
            b.__abortController instanceof AC
          );
        }
        async fetch(k, fetchOptions = {}) {
          const {
            // get options
            allowStale = this.allowStale,
            updateAgeOnGet = this.updateAgeOnGet,
            noDeleteOnStaleGet = this.noDeleteOnStaleGet,
            // set options
            ttl = this.ttl,
            noDisposeOnSet = this.noDisposeOnSet,
            size = 0,
            sizeCalculation = this.sizeCalculation,
            noUpdateTTL = this.noUpdateTTL,
            // fetch exclusive options
            noDeleteOnFetchRejection = this.noDeleteOnFetchRejection,
            allowStaleOnFetchRejection = this.allowStaleOnFetchRejection,
            ignoreFetchAbort = this.ignoreFetchAbort,
            allowStaleOnFetchAbort = this.allowStaleOnFetchAbort,
            context,
            forceRefresh = false,
            status,
            signal,
          } = fetchOptions;
          if (!this.#hasFetchMethod) {
            if (status) status.fetch = 'get';
            return this.get(k, {
              allowStale,
              updateAgeOnGet,
              noDeleteOnStaleGet,
              status,
            });
          }
          const options = {
            allowStale,
            updateAgeOnGet,
            noDeleteOnStaleGet,
            ttl,
            noDisposeOnSet,
            size,
            sizeCalculation,
            noUpdateTTL,
            noDeleteOnFetchRejection,
            allowStaleOnFetchRejection,
            allowStaleOnFetchAbort,
            ignoreFetchAbort,
            status,
            signal,
          };
          let index = this.#keyMap.get(k);
          if (index === undefined) {
            if (status) status.fetch = 'miss';
            const p = this.#backgroundFetch(k, index, options, context);
            return (p.__returned = p);
          } else {
            // in cache, maybe already fetching
            const v = this.#valList[index];
            if (this.#isBackgroundFetch(v)) {
              const stale = allowStale && v.__staleWhileFetching !== undefined;
              if (status) {
                status.fetch = 'inflight';
                if (stale) status.returnedStale = true;
              }
              return stale ? v.__staleWhileFetching : (v.__returned = v);
            }
            // if we force a refresh, that means do NOT serve the cached value,
            // unless we are already in the process of refreshing the cache.
            const isStale = this.#isStale(index);
            if (!forceRefresh && !isStale) {
              if (status) status.fetch = 'hit';
              this.#moveToTail(index);
              if (updateAgeOnGet) {
                this.#updateItemAge(index);
              }
              if (status) this.#statusTTL(status, index);
              return v;
            }
            // ok, it is stale or a forced refresh, and not already fetching.
            // refresh the cache.
            const p = this.#backgroundFetch(k, index, options, context);
            const hasStale = p.__staleWhileFetching !== undefined;
            const staleVal = hasStale && allowStale;
            if (status) {
              status.fetch = isStale ? 'stale' : 'refresh';
              if (staleVal && isStale) status.returnedStale = true;
            }
            return staleVal ? p.__staleWhileFetching : (p.__returned = p);
          }
        }
        async forceFetch(k, fetchOptions = {}) {
          const v = await this.fetch(k, fetchOptions);
          if (v === undefined) throw new Error('fetch() returned undefined');
          return v;
        }
        memo(k, memoOptions = {}) {
          const memoMethod = this.#memoMethod;
          if (!memoMethod) {
            throw new Error('no memoMethod provided to constructor');
          }
          const { context, forceRefresh, ...options } = memoOptions;
          const v = this.get(k, options);
          if (!forceRefresh && v !== undefined) return v;
          const vv = memoMethod(k, v, {
            options,
            context,
          });
          this.set(k, vv, options);
          return vv;
        }
        /**
         * Return a value from the cache. Will update the recency of the cache
         * entry found.
         *
         * If the key is not found, get() will return `undefined`.
         */
        get(k, getOptions = {}) {
          const {
            allowStale = this.allowStale,
            updateAgeOnGet = this.updateAgeOnGet,
            noDeleteOnStaleGet = this.noDeleteOnStaleGet,
            status,
          } = getOptions;
          const index = this.#keyMap.get(k);
          if (index !== undefined) {
            const value = this.#valList[index];
            const fetching = this.#isBackgroundFetch(value);
            if (status) this.#statusTTL(status, index);
            if (this.#isStale(index)) {
              if (status) status.get = 'stale';
              // delete only if not an in-flight background fetch
              if (!fetching) {
                if (!noDeleteOnStaleGet) {
                  this.#delete(k, 'expire');
                }
                if (status && allowStale) status.returnedStale = true;
                return allowStale ? value : undefined;
              } else {
                if (
                  status &&
                  allowStale &&
                  value.__staleWhileFetching !== undefined
                ) {
                  status.returnedStale = true;
                }
                return allowStale ? value.__staleWhileFetching : undefined;
              }
            } else {
              if (status) status.get = 'hit';
              // if we're currently fetching it, we don't actually have it yet
              // it's not stale, which means this isn't a staleWhileRefetching.
              // If it's not stale, and fetching, AND has a __staleWhileFetching
              // value, then that means the user fetched with {forceRefresh:true},
              // so it's safe to return that value.
              if (fetching) {
                return value.__staleWhileFetching;
              }
              this.#moveToTail(index);
              if (updateAgeOnGet) {
                this.#updateItemAge(index);
              }
              return value;
            }
          } else if (status) {
            status.get = 'miss';
          }
        }
        #connect(p, n) {
          this.#prev[n] = p;
          this.#next[p] = n;
        }
        #moveToTail(index) {
          // if tail already, nothing to do
          // if head, move head to next[index]
          // else
          //   move next[prev[index]] to next[index] (head has no prev)
          //   move prev[next[index]] to prev[index]
          // prev[index] = tail
          // next[tail] = index
          // tail = index
          if (index !== this.#tail) {
            if (index === this.#head) {
              this.#head = this.#next[index];
            } else {
              this.#connect(this.#prev[index], this.#next[index]);
            }
            this.#connect(this.#tail, index);
            this.#tail = index;
          }
        }
        /**
         * Deletes a key out of the cache.
         *
         * Returns true if the key was deleted, false otherwise.
         */
        delete(k) {
          return this.#delete(k, 'delete');
        }
        #delete(k, reason) {
          let deleted = false;
          if (this.#size !== 0) {
            const index = this.#keyMap.get(k);
            if (index !== undefined) {
              deleted = true;
              if (this.#size === 1) {
                this.#clear(reason);
              } else {
                this.#removeItemSize(index);
                const v = this.#valList[index];
                if (this.#isBackgroundFetch(v)) {
                  v.__abortController.abort(new Error('deleted'));
                } else if (this.#hasDispose || this.#hasDisposeAfter) {
                  if (this.#hasDispose) {
                    this.#dispose?.(v, k, reason);
                  }
                  if (this.#hasDisposeAfter) {
                    this.#disposed?.push([v, k, reason]);
                  }
                }
                this.#keyMap.delete(k);
                this.#keyList[index] = undefined;
                this.#valList[index] = undefined;
                if (index === this.#tail) {
                  this.#tail = this.#prev[index];
                } else if (index === this.#head) {
                  this.#head = this.#next[index];
                } else {
                  const pi = this.#prev[index];
                  this.#next[pi] = this.#next[index];
                  const ni = this.#next[index];
                  this.#prev[ni] = this.#prev[index];
                }
                this.#size--;
                this.#free.push(index);
              }
            }
          }
          if (this.#hasDisposeAfter && this.#disposed?.length) {
            const dt = this.#disposed;
            let task;
            while ((task = dt?.shift())) {
              this.#disposeAfter?.(...task);
            }
          }
          return deleted;
        }
        /**
         * Clear the cache entirely, throwing away all values.
         */
        clear() {
          return this.#clear('delete');
        }
        #clear(reason) {
          for (const index of this.#rindexes({ allowStale: true })) {
            const v = this.#valList[index];
            if (this.#isBackgroundFetch(v)) {
              v.__abortController.abort(new Error('deleted'));
            } else {
              const k = this.#keyList[index];
              if (this.#hasDispose) {
                this.#dispose?.(v, k, reason);
              }
              if (this.#hasDisposeAfter) {
                this.#disposed?.push([v, k, reason]);
              }
            }
          }
          this.#keyMap.clear();
          this.#valList.fill(undefined);
          this.#keyList.fill(undefined);
          if (this.#ttls && this.#starts) {
            this.#ttls.fill(0);
            this.#starts.fill(0);
          }
          if (this.#sizes) {
            this.#sizes.fill(0);
          }
          this.#head = 0;
          this.#tail = 0;
          this.#free.length = 0;
          this.#calculatedSize = 0;
          this.#size = 0;
          if (this.#hasDisposeAfter && this.#disposed) {
            const dt = this.#disposed;
            let task;
            while ((task = dt?.shift())) {
              this.#disposeAfter?.(...task);
            }
          }
        }
      }
      exports.LRUCache = LRUCache;
      //# sourceMappingURL=index.js.map

      /***/
    },

    /***/ 4486: /***/ (__unused_webpack_module, exports) => {
      'use strict';

      Object.defineProperty(exports, '__esModule', { value: true });
      exports.assertValidPattern = void 0;
      const MAX_PATTERN_LENGTH = 1024 * 64;
      const assertValidPattern = (pattern) => {
        if (typeof pattern !== 'string') {
          throw new TypeError('invalid pattern');
        }
        if (pattern.length > MAX_PATTERN_LENGTH) {
          throw new TypeError('pattern is too long');
        }
      };
      exports.assertValidPattern = assertValidPattern;
      //# sourceMappingURL=assert-valid-pattern.js.map

      /***/
    },

    /***/ 6078: /***/ (
      __unused_webpack_module,
      exports,
      __webpack_require__,
    ) => {
      'use strict';

      // parse a single path portion
      Object.defineProperty(exports, '__esModule', { value: true });
      exports.AST = void 0;
      const brace_expressions_js_1 = __webpack_require__(607);
      const unescape_js_1 = __webpack_require__(888);
      const types = new Set(['!', '?', '+', '*', '@']);
      const isExtglobType = (c) => types.has(c);
      // Patterns that get prepended to bind to the start of either the
      // entire string, or just a single path portion, to prevent dots
      // and/or traversal patterns, when needed.
      // Exts don't need the ^ or / bit, because the root binds that already.
      const startNoTraversal = '(?!(?:^|/)\\.\\.?(?:$|/))';
      const startNoDot = '(?!\\.)';
      // characters that indicate a start of pattern needs the "no dots" bit,
      // because a dot *might* be matched. ( is not in the list, because in
      // the case of a child extglob, it will handle the prevention itself.
      const addPatternStart = new Set(['[', '.']);
      // cases where traversal is A-OK, no dot prevention needed
      const justDots = new Set(['..', '.']);
      const reSpecials = new Set('().*{}+?[]^$\\!');
      const regExpEscape = (s) => s.replace(/[-[\]{}()*+?.,\\^$|#\s]/g, '\\$&');
      // any single thing other than /
      const qmark = '[^/]';
      // * => any number of characters
      const star = qmark + '*?';
      // use + when we need to ensure that *something* matches, because the * is
      // the only thing in the path portion.
      const starNoEmpty = qmark + '+?';
      // remove the \ chars that we added if we end up doing a nonmagic compare
      // const deslash = (s: string) => s.replace(/\\(.)/g, '$1')
      class AST {
        type;
        #root;
        #hasMagic;
        #uflag = false;
        #parts = [];
        #parent;
        #parentIndex;
        #negs;
        #filledNegs = false;
        #options;
        #toString;
        // set to true if it's an extglob with no children
        // (which really means one child of '')
        #emptyExt = false;
        constructor(type, parent, options = {}) {
          this.type = type;
          // extglobs are inherently magical
          if (type) this.#hasMagic = true;
          this.#parent = parent;
          this.#root = this.#parent ? this.#parent.#root : this;
          this.#options = this.#root === this ? options : this.#root.#options;
          this.#negs = this.#root === this ? [] : this.#root.#negs;
          if (type === '!' && !this.#root.#filledNegs) this.#negs.push(this);
          this.#parentIndex = this.#parent ? this.#parent.#parts.length : 0;
        }
        get hasMagic() {
          /* c8 ignore start */
          if (this.#hasMagic !== undefined) return this.#hasMagic;
          /* c8 ignore stop */
          for (const p of this.#parts) {
            if (typeof p === 'string') continue;
            if (p.type || p.hasMagic) return (this.#hasMagic = true);
          }
          // note: will be undefined until we generate the regexp src and find out
          return this.#hasMagic;
        }
        // reconstructs the pattern
        toString() {
          if (this.#toString !== undefined) return this.#toString;
          if (!this.type) {
            return (this.#toString = this.#parts
              .map((p) => String(p))
              .join(''));
          } else {
            return (this.#toString =
              this.type +
              '(' +
              this.#parts.map((p) => String(p)).join('|') +
              ')');
          }
        }
        #fillNegs() {
          /* c8 ignore start */
          if (this !== this.#root) throw new Error('should only call on root');
          if (this.#filledNegs) return this;
          /* c8 ignore stop */
          // call toString() once to fill this out
          this.toString();
          this.#filledNegs = true;
          let n;
          while ((n = this.#negs.pop())) {
            if (n.type !== '!') continue;
            // walk up the tree, appending everthing that comes AFTER parentIndex
            let p = n;
            let pp = p.#parent;
            while (pp) {
              for (
                let i = p.#parentIndex + 1;
                !pp.type && i < pp.#parts.length;
                i++
              ) {
                for (const part of n.#parts) {
                  /* c8 ignore start */
                  if (typeof part === 'string') {
                    throw new Error('string part in extglob AST??');
                  }
                  /* c8 ignore stop */
                  part.copyIn(pp.#parts[i]);
                }
              }
              p = pp;
              pp = p.#parent;
            }
          }
          return this;
        }
        push(...parts) {
          for (const p of parts) {
            if (p === '') continue;
            /* c8 ignore start */
            if (
              typeof p !== 'string' &&
              !(p instanceof AST && p.#parent === this)
            ) {
              throw new Error('invalid part: ' + p);
            }
            /* c8 ignore stop */
            this.#parts.push(p);
          }
        }
        toJSON() {
          const ret =
            this.type === null
              ? this.#parts
                  .slice()
                  .map((p) => (typeof p === 'string' ? p : p.toJSON()))
              : [this.type, ...this.#parts.map((p) => p.toJSON())];
          if (this.isStart() && !this.type) ret.unshift([]);
          if (
            this.isEnd() &&
            (this === this.#root ||
              (this.#root.#filledNegs && this.#parent?.type === '!'))
          ) {
            ret.push({});
          }
          return ret;
        }
        isStart() {
          if (this.#root === this) return true;
          // if (this.type) return !!this.#parent?.isStart()
          if (!this.#parent?.isStart()) return false;
          if (this.#parentIndex === 0) return true;
          // if everything AHEAD of this is a negation, then it's still the "start"
          const p = this.#parent;
          for (let i = 0; i < this.#parentIndex; i++) {
            const pp = p.#parts[i];
            if (!(pp instanceof AST && pp.type === '!')) {
              return false;
            }
          }
          return true;
        }
        isEnd() {
          if (this.#root === this) return true;
          if (this.#parent?.type === '!') return true;
          if (!this.#parent?.isEnd()) return false;
          if (!this.type) return this.#parent?.isEnd();
          // if not root, it'll always have a parent
          /* c8 ignore start */
          const pl = this.#parent ? this.#parent.#parts.length : 0;
          /* c8 ignore stop */
          return this.#parentIndex === pl - 1;
        }
        copyIn(part) {
          if (typeof part === 'string') this.push(part);
          else this.push(part.clone(this));
        }
        clone(parent) {
          const c = new AST(this.type, parent);
          for (const p of this.#parts) {
            c.copyIn(p);
          }
          return c;
        }
        static #parseAST(str, ast, pos, opt) {
          let escaping = false;
          let inBrace = false;
          let braceStart = -1;
          let braceNeg = false;
          if (ast.type === null) {
            // outside of a extglob, append until we find a start
            let i = pos;
            let acc = '';
            while (i < str.length) {
              const c = str.charAt(i++);
              // still accumulate escapes at this point, but we do ignore
              // starts that are escaped
              if (escaping || c === '\\') {
                escaping = !escaping;
                acc += c;
                continue;
              }
              if (inBrace) {
                if (i === braceStart + 1) {
                  if (c === '^' || c === '!') {
                    braceNeg = true;
                  }
                } else if (c === ']' && !(i === braceStart + 2 && braceNeg)) {
                  inBrace = false;
                }
                acc += c;
                continue;
              } else if (c === '[') {
                inBrace = true;
                braceStart = i;
                braceNeg = false;
                acc += c;
                continue;
              }
              if (!opt.noext && isExtglobType(c) && str.charAt(i) === '(') {
                ast.push(acc);
                acc = '';
                const ext = new AST(c, ast);
                i = AST.#parseAST(str, ext, i, opt);
                ast.push(ext);
                continue;
              }
              acc += c;
            }
            ast.push(acc);
            return i;
          }
          // some kind of extglob, pos is at the (
          // find the next | or )
          let i = pos + 1;
          let part = new AST(null, ast);
          const parts = [];
          let acc = '';
          while (i < str.length) {
            const c = str.charAt(i++);
            // still accumulate escapes at this point, but we do ignore
            // starts that are escaped
            if (escaping || c === '\\') {
              escaping = !escaping;
              acc += c;
              continue;
            }
            if (inBrace) {
              if (i === braceStart + 1) {
                if (c === '^' || c === '!') {
                  braceNeg = true;
                }
              } else if (c === ']' && !(i === braceStart + 2 && braceNeg)) {
                inBrace = false;
              }
              acc += c;
              continue;
            } else if (c === '[') {
              inBrace = true;
              braceStart = i;
              braceNeg = false;
              acc += c;
              continue;
            }
            if (isExtglobType(c) && str.charAt(i) === '(') {
              part.push(acc);
              acc = '';
              const ext = new AST(c, part);
              part.push(ext);
              i = AST.#parseAST(str, ext, i, opt);
              continue;
            }
            if (c === '|') {
              part.push(acc);
              acc = '';
              parts.push(part);
              part = new AST(null, ast);
              continue;
            }
            if (c === ')') {
              if (acc === '' && ast.#parts.length === 0) {
                ast.#emptyExt = true;
              }
              part.push(acc);
              acc = '';
              ast.push(...parts, part);
              return i;
            }
            acc += c;
          }
          // unfinished extglob
          // if we got here, it was a malformed extglob! not an extglob, but
          // maybe something else in there.
          ast.type = null;
          ast.#hasMagic = undefined;
          ast.#parts = [str.substring(pos - 1)];
          return i;
        }
        static fromGlob(pattern, options = {}) {
          const ast = new AST(null, undefined, options);
          AST.#parseAST(pattern, ast, 0, options);
          return ast;
        }
        // returns the regular expression if there's magic, or the unescaped
        // string if not.
        toMMPattern() {
          // should only be called on root
          /* c8 ignore start */
          if (this !== this.#root) return this.#root.toMMPattern();
          /* c8 ignore stop */
          const glob = this.toString();
          const [re, body, hasMagic, uflag] = this.toRegExpSource();
          // if we're in nocase mode, and not nocaseMagicOnly, then we do
          // still need a regular expression if we have to case-insensitively
          // match capital/lowercase characters.
          const anyMagic =
            hasMagic ||
            this.#hasMagic ||
            (this.#options.nocase &&
              !this.#options.nocaseMagicOnly &&
              glob.toUpperCase() !== glob.toLowerCase());
          if (!anyMagic) {
            return body;
          }
          const flags = (this.#options.nocase ? 'i' : '') + (uflag ? 'u' : '');
          return Object.assign(new RegExp(`^${re}$`, flags), {
            _src: re,
            _glob: glob,
          });
        }
        get options() {
          return this.#options;
        }
        // returns the string match, the regexp source, whether there's magic
        // in the regexp (so a regular expression is required) and whether or
        // not the uflag is needed for the regular expression (for posix classes)
        // TODO: instead of injecting the start/end at this point, just return
        // the BODY of the regexp, along with the start/end portions suitable
        // for binding the start/end in either a joined full-path makeRe context
        // (where we bind to (^|/), or a standalone matchPart context (where
        // we bind to ^, and not /).  Otherwise slashes get duped!
        //
        // In part-matching mode, the start is:
        // - if not isStart: nothing
        // - if traversal possible, but not allowed: ^(?!\.\.?$)
        // - if dots allowed or not possible: ^
        // - if dots possible and not allowed: ^(?!\.)
        // end is:
        // - if not isEnd(): nothing
        // - else: $
        //
        // In full-path matching mode, we put the slash at the START of the
        // pattern, so start is:
        // - if first pattern: same as part-matching mode
        // - if not isStart(): nothing
        // - if traversal possible, but not allowed: /(?!\.\.?(?:$|/))
        // - if dots allowed or not possible: /
        // - if dots possible and not allowed: /(?!\.)
        // end is:
        // - if last pattern, same as part-matching mode
        // - else nothing
        //
        // Always put the (?:$|/) on negated tails, though, because that has to be
        // there to bind the end of the negated pattern portion, and it's easier to
        // just stick it in now rather than try to inject it later in the middle of
        // the pattern.
        //
        // We can just always return the same end, and leave it up to the caller
        // to know whether it's going to be used joined or in parts.
        // And, if the start is adjusted slightly, can do the same there:
        // - if not isStart: nothing
        // - if traversal possible, but not allowed: (?:/|^)(?!\.\.?$)
        // - if dots allowed or not possible: (?:/|^)
        // - if dots possible and not allowed: (?:/|^)(?!\.)
        //
        // But it's better to have a simpler binding without a conditional, for
        // performance, so probably better to return both start options.
        //
        // Then the caller just ignores the end if it's not the first pattern,
        // and the start always gets applied.
        //
        // But that's always going to be $ if it's the ending pattern, or nothing,
        // so the caller can just attach $ at the end of the pattern when building.
        //
        // So the todo is:
        // - better detect what kind of start is needed
        // - return both flavors of starting pattern
        // - attach $ at the end of the pattern when creating the actual RegExp
        //
        // Ah, but wait, no, that all only applies to the root when the first pattern
        // is not an extglob. If the first pattern IS an extglob, then we need all
        // that dot prevention biz to live in the extglob portions, because eg
        // +(*|.x*) can match .xy but not .yx.
        //
        // So, return the two flavors if it's #root and the first child is not an
        // AST, otherwise leave it to the child AST to handle it, and there,
        // use the (?:^|/) style of start binding.
        //
        // Even simplified further:
        // - Since the start for a join is eg /(?!\.) and the start for a part
        // is ^(?!\.), we can just prepend (?!\.) to the pattern (either root
        // or start or whatever) and prepend ^ or / at the Regexp construction.
        toRegExpSource(allowDot) {
          const dot = allowDot ?? !!this.#options.dot;
          if (this.#root === this) this.#fillNegs();
          if (!this.type) {
            const noEmpty = this.isStart() && this.isEnd();
            const src = this.#parts
              .map((p) => {
                const [re, _, hasMagic, uflag] =
                  typeof p === 'string'
                    ? AST.#parseGlob(p, this.#hasMagic, noEmpty)
                    : p.toRegExpSource(allowDot);
                this.#hasMagic = this.#hasMagic || hasMagic;
                this.#uflag = this.#uflag || uflag;
                return re;
              })
              .join('');
            let start = '';
            if (this.isStart()) {
              if (typeof this.#parts[0] === 'string') {
                // this is the string that will match the start of the pattern,
                // so we need to protect against dots and such.
                // '.' and '..' cannot match unless the pattern is that exactly,
                // even if it starts with . or dot:true is set.
                const dotTravAllowed =
                  this.#parts.length === 1 && justDots.has(this.#parts[0]);
                if (!dotTravAllowed) {
                  const aps = addPatternStart;
                  // check if we have a possibility of matching . or ..,
                  // and prevent that.
                  const needNoTrav =
                    // dots are allowed, and the pattern starts with [ or .
                    (dot && aps.has(src.charAt(0))) ||
                    // the pattern starts with \., and then [ or .
                    (src.startsWith('\\.') && aps.has(src.charAt(2))) ||
                    // the pattern starts with \.\., and then [ or .
                    (src.startsWith('\\.\\.') && aps.has(src.charAt(4)));
                  // no need to prevent dots if it can't match a dot, or if a
                  // sub-pattern will be preventing it anyway.
                  const needNoDot = !dot && !allowDot && aps.has(src.charAt(0));
                  start = needNoTrav
                    ? startNoTraversal
                    : needNoDot
                      ? startNoDot
                      : '';
                }
              }
            }
            // append the "end of path portion" pattern to negation tails
            let end = '';
            if (
              this.isEnd() &&
              this.#root.#filledNegs &&
              this.#parent?.type === '!'
            ) {
              end = '(?:$|\\/)';
            }
            const final = start + src + end;
            return [
              final,
              (0, unescape_js_1.unescape)(src),
              (this.#hasMagic = !!this.#hasMagic),
              this.#uflag,
            ];
          }
          // We need to calculate the body *twice* if it's a repeat pattern
          // at the start, once in nodot mode, then again in dot mode, so a
          // pattern like *(?) can match 'x.y'
          const repeated = this.type === '*' || this.type === '+';
          // some kind of extglob
          const start = this.type === '!' ? '(?:(?!(?:' : '(?:';
          let body = this.#partsToRegExp(dot);
          if (this.isStart() && this.isEnd() && !body && this.type !== '!') {
            // invalid extglob, has to at least be *something* present, if it's
            // the entire path portion.
            const s = this.toString();
            this.#parts = [s];
            this.type = null;
            this.#hasMagic = undefined;
            return [
              s,
              (0, unescape_js_1.unescape)(this.toString()),
              false,
              false,
            ];
          }
          // XXX abstract out this map method
          let bodyDotAllowed =
            !repeated || allowDot || dot || !startNoDot
              ? ''
              : this.#partsToRegExp(true);
          if (bodyDotAllowed === body) {
            bodyDotAllowed = '';
          }
          if (bodyDotAllowed) {
            body = `(?:${body})(?:${bodyDotAllowed})*?`;
          }
          // an empty !() is exactly equivalent to a starNoEmpty
          let final = '';
          if (this.type === '!' && this.#emptyExt) {
            final = (this.isStart() && !dot ? startNoDot : '') + starNoEmpty;
          } else {
            const close =
              this.type === '!'
                ? // !() must match something,but !(x) can match ''
                  '))' +
                  (this.isStart() && !dot && !allowDot ? startNoDot : '') +
                  star +
                  ')'
                : this.type === '@'
                  ? ')'
                  : this.type === '?'
                    ? ')?'
                    : this.type === '+' && bodyDotAllowed
                      ? ')'
                      : this.type === '*' && bodyDotAllowed
                        ? `)?`
                        : `)${this.type}`;
            final = start + body + close;
          }
          return [
            final,
            (0, unescape_js_1.unescape)(body),
            (this.#hasMagic = !!this.#hasMagic),
            this.#uflag,
          ];
        }
        #partsToRegExp(dot) {
          return this.#parts
            .map((p) => {
              // extglob ASTs should only contain parent ASTs
              /* c8 ignore start */
              if (typeof p === 'string') {
                throw new Error('string type in extglob ast??');
              }
              /* c8 ignore stop */
              // can ignore hasMagic, because extglobs are already always magic
              const [re, _, _hasMagic, uflag] = p.toRegExpSource(dot);
              this.#uflag = this.#uflag || uflag;
              return re;
            })
            .filter((p) => !(this.isStart() && this.isEnd()) || !!p)
            .join('|');
        }
        static #parseGlob(glob, hasMagic, noEmpty = false) {
          let escaping = false;
          let re = '';
          let uflag = false;
          for (let i = 0; i < glob.length; i++) {
            const c = glob.charAt(i);
            if (escaping) {
              escaping = false;
              re += (reSpecials.has(c) ? '\\' : '') + c;
              continue;
            }
            if (c === '\\') {
              if (i === glob.length - 1) {
                re += '\\\\';
              } else {
                escaping = true;
              }
              continue;
            }
            if (c === '[') {
              const [src, needUflag, consumed, magic] = (0,
              brace_expressions_js_1.parseClass)(glob, i);
              if (consumed) {
                re += src;
                uflag = uflag || needUflag;
                i += consumed - 1;
                hasMagic = hasMagic || magic;
                continue;
              }
            }
            if (c === '*') {
              if (noEmpty && glob === '*') re += starNoEmpty;
              else re += star;
              hasMagic = true;
              continue;
            }
            if (c === '?') {
              re += qmark;
              hasMagic = true;
              continue;
            }
            re += regExpEscape(c);
          }
          return [re, (0, unescape_js_1.unescape)(glob), !!hasMagic, uflag];
        }
      }
      exports.AST = AST;
      //# sourceMappingURL=ast.js.map

      /***/
    },

    /***/ 607: /***/ (__unused_webpack_module, exports) => {
      'use strict';

      // translate the various posix character classes into unicode properties
      // this works across all unicode locales
      Object.defineProperty(exports, '__esModule', { value: true });
      exports.parseClass = void 0;
      // { <posix class>: [<translation>, /u flag required, negated]
      const posixClasses = {
        '[:alnum:]': ['\\p{L}\\p{Nl}\\p{Nd}', true],
        '[:alpha:]': ['\\p{L}\\p{Nl}', true],
        '[:ascii:]': ['\\x' + '00-\\x' + '7f', false],
        '[:blank:]': ['\\p{Zs}\\t', true],
        '[:cntrl:]': ['\\p{Cc}', true],
        '[:digit:]': ['\\p{Nd}', true],
        '[:graph:]': ['\\p{Z}\\p{C}', true, true],
        '[:lower:]': ['\\p{Ll}', true],
        '[:print:]': ['\\p{C}', true],
        '[:punct:]': ['\\p{P}', true],
        '[:space:]': ['\\p{Z}\\t\\r\\n\\v\\f', true],
        '[:upper:]': ['\\p{Lu}', true],
        '[:word:]': ['\\p{L}\\p{Nl}\\p{Nd}\\p{Pc}', true],
        '[:xdigit:]': ['A-Fa-f0-9', false],
      };
      // only need to escape a few things inside of brace expressions
      // escapes: [ \ ] -
      const braceEscape = (s) => s.replace(/[[\]\\-]/g, '\\$&');
      // escape all regexp magic characters
      const regexpEscape = (s) => s.replace(/[-[\]{}()*+?.,\\^$|#\s]/g, '\\$&');
      // everything has already been escaped, we just have to join
      const rangesToString = (ranges) => ranges.join('');
      // takes a glob string at a posix brace expression, and returns
      // an equivalent regular expression source, and boolean indicating
      // whether the /u flag needs to be applied, and the number of chars
      // consumed to parse the character class.
      // This also removes out of order ranges, and returns ($.) if the
      // entire class just no good.
      const parseClass = (glob, position) => {
        const pos = position;
        /* c8 ignore start */
        if (glob.charAt(pos) !== '[') {
          throw new Error('not in a brace expression');
        }
        /* c8 ignore stop */
        const ranges = [];
        const negs = [];
        let i = pos + 1;
        let sawStart = false;
        let uflag = false;
        let escaping = false;
        let negate = false;
        let endPos = pos;
        let rangeStart = '';
        WHILE: while (i < glob.length) {
          const c = glob.charAt(i);
          if ((c === '!' || c === '^') && i === pos + 1) {
            negate = true;
            i++;
            continue;
          }
          if (c === ']' && sawStart && !escaping) {
            endPos = i + 1;
            break;
          }
          sawStart = true;
          if (c === '\\') {
            if (!escaping) {
              escaping = true;
              i++;
              continue;
            }
            // escaped \ char, fall through and treat like normal char
          }
          if (c === '[' && !escaping) {
            // either a posix class, a collation equivalent, or just a [
            for (const [cls, [unip, u, neg]] of Object.entries(posixClasses)) {
              if (glob.startsWith(cls, i)) {
                // invalid, [a-[] is fine, but not [a-[:alpha]]
                if (rangeStart) {
                  return ['$.', false, glob.length - pos, true];
                }
                i += cls.length;
                if (neg) negs.push(unip);
                else ranges.push(unip);
                uflag = uflag || u;
                continue WHILE;
              }
            }
          }
          // now it's just a normal character, effectively
          escaping = false;
          if (rangeStart) {
            // throw this range away if it's not valid, but others
            // can still match.
            if (c > rangeStart) {
              ranges.push(braceEscape(rangeStart) + '-' + braceEscape(c));
            } else if (c === rangeStart) {
              ranges.push(braceEscape(c));
            }
            rangeStart = '';
            i++;
            continue;
          }
          // now might be the start of a range.
          // can be either c-d or c-] or c<more...>] or c] at this point
          if (glob.startsWith('-]', i + 1)) {
            ranges.push(braceEscape(c + '-'));
            i += 2;
            continue;
          }
          if (glob.startsWith('-', i + 1)) {
            rangeStart = c;
            i += 2;
            continue;
          }
          // not the start of a range, just a single character
          ranges.push(braceEscape(c));
          i++;
        }
        if (endPos < i) {
          // didn't see the end of the class, not a valid class,
          // but might still be valid as a literal match.
          return ['', false, 0, false];
        }
        // if we got no ranges and no negates, then we have a range that
        // cannot possibly match anything, and that poisons the whole glob
        if (!ranges.length && !negs.length) {
          return ['$.', false, glob.length - pos, true];
        }
        // if we got one positive range, and it's a single character, then that's
        // not actually a magic pattern, it's just that one literal character.
        // we should not treat that as "magic", we should just return the literal
        // character. [_] is a perfectly valid way to escape glob magic chars.
        if (
          negs.length === 0 &&
          ranges.length === 1 &&
          /^\\?.$/.test(ranges[0]) &&
          !negate
        ) {
          const r = ranges[0].length === 2 ? ranges[0].slice(-1) : ranges[0];
          return [regexpEscape(r), false, endPos - pos, false];
        }
        const sranges =
          '[' + (negate ? '^' : '') + rangesToString(ranges) + ']';
        const snegs = '[' + (negate ? '' : '^') + rangesToString(negs) + ']';
        const comb =
          ranges.length && negs.length
            ? '(' + sranges + '|' + snegs + ')'
            : ranges.length
              ? sranges
              : snegs;
        return [comb, uflag, endPos - pos, true];
      };
      exports.parseClass = parseClass;
      //# sourceMappingURL=brace-expressions.js.map

      /***/
    },

    /***/ 4399: /***/ (__unused_webpack_module, exports) => {
      'use strict';

      Object.defineProperty(exports, '__esModule', { value: true });
      exports.escape = void 0;
      /**
       * Escape all magic characters in a glob pattern.
       *
       * If the {@link windowsPathsNoEscape | GlobOptions.windowsPathsNoEscape}
       * option is used, then characters are escaped by wrapping in `[]`, because
       * a magic character wrapped in a character class can only be satisfied by
       * that exact character.  In this mode, `\` is _not_ escaped, because it is
       * not interpreted as a magic character, but instead as a path separator.
       */
      const escape = (s, { windowsPathsNoEscape = false } = {}) => {
        // don't need to escape +@! because we escape the parens
        // that make those magic, and escaping ! as [!] isn't valid,
        // because [!]] is a valid glob class meaning not ']'.
        return windowsPathsNoEscape
          ? s.replace(/[?*()[\]]/g, '[$&]')
          : s.replace(/[?*()[\]\\]/g, '\\$&');
      };
      exports.escape = escape;
      //# sourceMappingURL=escape.js.map

      /***/
    },

    /***/ 854: /***/ function (
      __unused_webpack_module,
      exports,
      __webpack_require__,
    ) {
      'use strict';

      var __importDefault =
        (this && this.__importDefault) ||
        function (mod) {
          return mod && mod.__esModule ? mod : { default: mod };
        };
      Object.defineProperty(exports, '__esModule', { value: true });
      exports.unescape =
        exports.escape =
        exports.AST =
        exports.Minimatch =
        exports.match =
        exports.makeRe =
        exports.braceExpand =
        exports.defaults =
        exports.filter =
        exports.GLOBSTAR =
        exports.sep =
        exports.minimatch =
          void 0;
      const brace_expansion_1 = __importDefault(__webpack_require__(1716));
      const assert_valid_pattern_js_1 = __webpack_require__(4486);
      const ast_js_1 = __webpack_require__(6078);
      const escape_js_1 = __webpack_require__(4399);
      const unescape_js_1 = __webpack_require__(888);
      const minimatch = (p, pattern, options = {}) => {
        (0, assert_valid_pattern_js_1.assertValidPattern)(pattern);
        // shortcut: comments match nothing.
        if (!options.nocomment && pattern.charAt(0) === '#') {
          return false;
        }
        return new Minimatch(pattern, options).match(p);
      };
      exports.minimatch = minimatch;
      // Optimized checking for the most common glob patterns.
      const starDotExtRE = /^\*+([^+@!?\*\[\(]*)$/;
      const starDotExtTest = (ext) => (f) =>
        !f.startsWith('.') && f.endsWith(ext);
      const starDotExtTestDot = (ext) => (f) => f.endsWith(ext);
      const starDotExtTestNocase = (ext) => {
        ext = ext.toLowerCase();
        return (f) => !f.startsWith('.') && f.toLowerCase().endsWith(ext);
      };
      const starDotExtTestNocaseDot = (ext) => {
        ext = ext.toLowerCase();
        return (f) => f.toLowerCase().endsWith(ext);
      };
      const starDotStarRE = /^\*+\.\*+$/;
      const starDotStarTest = (f) => !f.startsWith('.') && f.includes('.');
      const starDotStarTestDot = (f) =>
        f !== '.' && f !== '..' && f.includes('.');
      const dotStarRE = /^\.\*+$/;
      const dotStarTest = (f) => f !== '.' && f !== '..' && f.startsWith('.');
      const starRE = /^\*+$/;
      const starTest = (f) => f.length !== 0 && !f.startsWith('.');
      const starTestDot = (f) => f.length !== 0 && f !== '.' && f !== '..';
      const qmarksRE = /^\?+([^+@!?\*\[\(]*)?$/;
      const qmarksTestNocase = ([$0, ext = '']) => {
        const noext = qmarksTestNoExt([$0]);
        if (!ext) return noext;
        ext = ext.toLowerCase();
        return (f) => noext(f) && f.toLowerCase().endsWith(ext);
      };
      const qmarksTestNocaseDot = ([$0, ext = '']) => {
        const noext = qmarksTestNoExtDot([$0]);
        if (!ext) return noext;
        ext = ext.toLowerCase();
        return (f) => noext(f) && f.toLowerCase().endsWith(ext);
      };
      const qmarksTestDot = ([$0, ext = '']) => {
        const noext = qmarksTestNoExtDot([$0]);
        return !ext ? noext : (f) => noext(f) && f.endsWith(ext);
      };
      const qmarksTest = ([$0, ext = '']) => {
        const noext = qmarksTestNoExt([$0]);
        return !ext ? noext : (f) => noext(f) && f.endsWith(ext);
      };
      const qmarksTestNoExt = ([$0]) => {
        const len = $0.length;
        return (f) => f.length === len && !f.startsWith('.');
      };
      const qmarksTestNoExtDot = ([$0]) => {
        const len = $0.length;
        return (f) => f.length === len && f !== '.' && f !== '..';
      };
      /* c8 ignore start */
      const defaultPlatform =
        typeof process === 'object' && process
          ? (typeof process.env === 'object' &&
              process.env &&
              process.env.__MINIMATCH_TESTING_PLATFORM__) ||
            process.platform
          : 'posix';
      const path = {
        win32: { sep: '\\' },
        posix: { sep: '/' },
      };
      /* c8 ignore stop */
      exports.sep =
        defaultPlatform === 'win32' ? path.win32.sep : path.posix.sep;
      exports.minimatch.sep = exports.sep;
      exports.GLOBSTAR = Symbol('globstar **');
      exports.minimatch.GLOBSTAR = exports.GLOBSTAR;
      // any single thing other than /
      // don't need to escape / when using new RegExp()
      const qmark = '[^/]';
      // * => any number of characters
      const star = qmark + '*?';
      // ** when dots are allowed.  Anything goes, except .. and .
      // not (^ or / followed by one or two dots followed by $ or /),
      // followed by anything, any number of times.
      const twoStarDot = '(?:(?!(?:\\/|^)(?:\\.{1,2})($|\\/)).)*?';
      // not a ^ or / followed by a dot,
      // followed by anything, any number of times.
      const twoStarNoDot = '(?:(?!(?:\\/|^)\\.).)*?';
      const filter =
        (pattern, options = {}) =>
        (p) =>
          (0, exports.minimatch)(p, pattern, options);
      exports.filter = filter;
      exports.minimatch.filter = exports.filter;
      const ext = (a, b = {}) => Object.assign({}, a, b);
      const defaults = (def) => {
        if (!def || typeof def !== 'object' || !Object.keys(def).length) {
          return exports.minimatch;
        }
        const orig = exports.minimatch;
        const m = (p, pattern, options = {}) =>
          orig(p, pattern, ext(def, options));
        return Object.assign(m, {
          Minimatch: class Minimatch extends orig.Minimatch {
            constructor(pattern, options = {}) {
              super(pattern, ext(def, options));
            }
            static defaults(options) {
              return orig.defaults(ext(def, options)).Minimatch;
            }
          },
          AST: class AST extends orig.AST {
            /* c8 ignore start */
            constructor(type, parent, options = {}) {
              super(type, parent, ext(def, options));
            }
            /* c8 ignore stop */
            static fromGlob(pattern, options = {}) {
              return orig.AST.fromGlob(pattern, ext(def, options));
            }
          },
          unescape: (s, options = {}) => orig.unescape(s, ext(def, options)),
          escape: (s, options = {}) => orig.escape(s, ext(def, options)),
          filter: (pattern, options = {}) =>
            orig.filter(pattern, ext(def, options)),
          defaults: (options) => orig.defaults(ext(def, options)),
          makeRe: (pattern, options = {}) =>
            orig.makeRe(pattern, ext(def, options)),
          braceExpand: (pattern, options = {}) =>
            orig.braceExpand(pattern, ext(def, options)),
          match: (list, pattern, options = {}) =>
            orig.match(list, pattern, ext(def, options)),
          sep: orig.sep,
          GLOBSTAR: exports.GLOBSTAR,
        });
      };
      exports.defaults = defaults;
      exports.minimatch.defaults = exports.defaults;
      // Brace expansion:
      // a{b,c}d -> abd acd
      // a{b,}c -> abc ac
      // a{0..3}d -> a0d a1d a2d a3d
      // a{b,c{d,e}f}g -> abg acdfg acefg
      // a{b,c}d{e,f}g -> abdeg acdeg abdeg abdfg
      //
      // Invalid sets are not expanded.
      // a{2..}b -> a{2..}b
      // a{b}c -> a{b}c
      const braceExpand = (pattern, options = {}) => {
        (0, assert_valid_pattern_js_1.assertValidPattern)(pattern);
        // Thanks to Yeting Li <https://github.com/yetingli> for
        // improving this regexp to avoid a ReDOS vulnerability.
        if (options.nobrace || !/\{(?:(?!\{).)*\}/.test(pattern)) {
          // shortcut. no need to expand.
          return [pattern];
        }
        return (0, brace_expansion_1.default)(pattern);
      };
      exports.braceExpand = braceExpand;
      exports.minimatch.braceExpand = exports.braceExpand;
      // parse a component of the expanded set.
      // At this point, no pattern may contain "/" in it
      // so we're going to return a 2d array, where each entry is the full
      // pattern, split on '/', and then turned into a regular expression.
      // A regexp is made at the end which joins each array with an
      // escaped /, and another full one which joins each regexp with |.
      //
      // Following the lead of Bash 4.1, note that "**" only has special meaning
      // when it is the *only* thing in a path portion.  Otherwise, any series
      // of * is equivalent to a single *.  Globstar behavior is enabled by
      // default, and can be disabled by setting options.noglobstar.
      const makeRe = (pattern, options = {}) =>
        new Minimatch(pattern, options).makeRe();
      exports.makeRe = makeRe;
      exports.minimatch.makeRe = exports.makeRe;
      const match = (list, pattern, options = {}) => {
        const mm = new Minimatch(pattern, options);
        list = list.filter((f) => mm.match(f));
        if (mm.options.nonull && !list.length) {
          list.push(pattern);
        }
        return list;
      };
      exports.match = match;
      exports.minimatch.match = exports.match;
      // replace stuff like \* with *
      const globMagic = /[?*]|[+@!]\(.*?\)|\[|\]/;
      const regExpEscape = (s) => s.replace(/[-[\]{}()*+?.,\\^$|#\s]/g, '\\$&');
      class Minimatch {
        options;
        set;
        pattern;
        windowsPathsNoEscape;
        nonegate;
        negate;
        comment;
        empty;
        preserveMultipleSlashes;
        partial;
        globSet;
        globParts;
        nocase;
        isWindows;
        platform;
        windowsNoMagicRoot;
        regexp;
        constructor(pattern, options = {}) {
          (0, assert_valid_pattern_js_1.assertValidPattern)(pattern);
          options = options || {};
          this.options = options;
          this.pattern = pattern;
          this.platform = options.platform || defaultPlatform;
          this.isWindows = this.platform === 'win32';
          this.windowsPathsNoEscape =
            !!options.windowsPathsNoEscape ||
            options.allowWindowsEscape === false;
          if (this.windowsPathsNoEscape) {
            this.pattern = this.pattern.replace(/\\/g, '/');
          }
          this.preserveMultipleSlashes = !!options.preserveMultipleSlashes;
          this.regexp = null;
          this.negate = false;
          this.nonegate = !!options.nonegate;
          this.comment = false;
          this.empty = false;
          this.partial = !!options.partial;
          this.nocase = !!this.options.nocase;
          this.windowsNoMagicRoot =
            options.windowsNoMagicRoot !== undefined
              ? options.windowsNoMagicRoot
              : !!(this.isWindows && this.nocase);
          this.globSet = [];
          this.globParts = [];
          this.set = [];
          // make the set of regexps etc.
          this.make();
        }
        hasMagic() {
          if (this.options.magicalBraces && this.set.length > 1) {
            return true;
          }
          for (const pattern of this.set) {
            for (const part of pattern) {
              if (typeof part !== 'string') return true;
            }
          }
          return false;
        }
        debug(..._) {}
        make() {
          const pattern = this.pattern;
          const options = this.options;
          // empty patterns and comments match nothing.
          if (!options.nocomment && pattern.charAt(0) === '#') {
            this.comment = true;
            return;
          }
          if (!pattern) {
            this.empty = true;
            return;
          }
          // step 1: figure out negation, etc.
          this.parseNegate();
          // step 2: expand braces
          this.globSet = [...new Set(this.braceExpand())];
          if (options.debug) {
            this.debug = (...args) => console.error(...args);
          }
          this.debug(this.pattern, this.globSet);
          // step 3: now we have a set, so turn each one into a series of
          // path-portion matching patterns.
          // These will be regexps, except in the case of "**", which is
          // set to the GLOBSTAR object for globstar behavior,
          // and will not contain any / characters
          //
          // First, we preprocess to make the glob pattern sets a bit simpler
          // and deduped.  There are some perf-killing patterns that can cause
          // problems with a glob walk, but we can simplify them down a bit.
          const rawGlobParts = this.globSet.map((s) => this.slashSplit(s));
          this.globParts = this.preprocess(rawGlobParts);
          this.debug(this.pattern, this.globParts);
          // glob --> regexps
          let set = this.globParts.map((s, _, __) => {
            if (this.isWindows && this.windowsNoMagicRoot) {
              // check if it's a drive or unc path.
              const isUNC =
                s[0] === '' &&
                s[1] === '' &&
                (s[2] === '?' || !globMagic.test(s[2])) &&
                !globMagic.test(s[3]);
              const isDrive = /^[a-z]:/i.test(s[0]);
              if (isUNC) {
                return [
                  ...s.slice(0, 4),
                  ...s.slice(4).map((ss) => this.parse(ss)),
                ];
              } else if (isDrive) {
                return [s[0], ...s.slice(1).map((ss) => this.parse(ss))];
              }
            }
            return s.map((ss) => this.parse(ss));
          });
          this.debug(this.pattern, set);
          // filter out everything that didn't compile properly.
          this.set = set.filter((s) => s.indexOf(false) === -1);
          // do not treat the ? in UNC paths as magic
          if (this.isWindows) {
            for (let i = 0; i < this.set.length; i++) {
              const p = this.set[i];
              if (
                p[0] === '' &&
                p[1] === '' &&
                this.globParts[i][2] === '?' &&
                typeof p[3] === 'string' &&
                /^[a-z]:$/i.test(p[3])
              ) {
                p[2] = '?';
              }
            }
          }
          this.debug(this.pattern, this.set);
        }
        // various transforms to equivalent pattern sets that are
        // faster to process in a filesystem walk.  The goal is to
        // eliminate what we can, and push all ** patterns as far
        // to the right as possible, even if it increases the number
        // of patterns that we have to process.
        preprocess(globParts) {
          // if we're not in globstar mode, then turn all ** into *
          if (this.options.noglobstar) {
            for (let i = 0; i < globParts.length; i++) {
              for (let j = 0; j < globParts[i].length; j++) {
                if (globParts[i][j] === '**') {
                  globParts[i][j] = '*';
                }
              }
            }
          }
          const { optimizationLevel = 1 } = this.options;
          if (optimizationLevel >= 2) {
            // aggressive optimization for the purpose of fs walking
            globParts = this.firstPhasePreProcess(globParts);
            globParts = this.secondPhasePreProcess(globParts);
          } else if (optimizationLevel >= 1) {
            // just basic optimizations to remove some .. parts
            globParts = this.levelOneOptimize(globParts);
          } else {
            // just collapse multiple ** portions into one
            globParts = this.adjascentGlobstarOptimize(globParts);
          }
          return globParts;
        }
        // just get rid of adjascent ** portions
        adjascentGlobstarOptimize(globParts) {
          return globParts.map((parts) => {
            let gs = -1;
            while (-1 !== (gs = parts.indexOf('**', gs + 1))) {
              let i = gs;
              while (parts[i + 1] === '**') {
                i++;
              }
              if (i !== gs) {
                parts.splice(gs, i - gs);
              }
            }
            return parts;
          });
        }
        // get rid of adjascent ** and resolve .. portions
        levelOneOptimize(globParts) {
          return globParts.map((parts) => {
            parts = parts.reduce((set, part) => {
              const prev = set[set.length - 1];
              if (part === '**' && prev === '**') {
                return set;
              }
              if (part === '..') {
                if (prev && prev !== '..' && prev !== '.' && prev !== '**') {
                  set.pop();
                  return set;
                }
              }
              set.push(part);
              return set;
            }, []);
            return parts.length === 0 ? [''] : parts;
          });
        }
        levelTwoFileOptimize(parts) {
          if (!Array.isArray(parts)) {
            parts = this.slashSplit(parts);
          }
          let didSomething = false;
          do {
            didSomething = false;
            // <pre>/<e>/<rest> -> <pre>/<rest>
            if (!this.preserveMultipleSlashes) {
              for (let i = 1; i < parts.length - 1; i++) {
                const p = parts[i];
                // don't squeeze out UNC patterns
                if (i === 1 && p === '' && parts[0] === '') continue;
                if (p === '.' || p === '') {
                  didSomething = true;
                  parts.splice(i, 1);
                  i--;
                }
              }
              if (
                parts[0] === '.' &&
                parts.length === 2 &&
                (parts[1] === '.' || parts[1] === '')
              ) {
                didSomething = true;
                parts.pop();
              }
            }
            // <pre>/<p>/../<rest> -> <pre>/<rest>
            let dd = 0;
            while (-1 !== (dd = parts.indexOf('..', dd + 1))) {
              const p = parts[dd - 1];
              if (p && p !== '.' && p !== '..' && p !== '**') {
                didSomething = true;
                parts.splice(dd - 1, 2);
                dd -= 2;
              }
            }
          } while (didSomething);
          return parts.length === 0 ? [''] : parts;
        }
        // First phase: single-pattern processing
        // <pre> is 1 or more portions
        // <rest> is 1 or more portions
        // <p> is any portion other than ., .., '', or **
        // <e> is . or ''
        //
        // **/.. is *brutal* for filesystem walking performance, because
        // it effectively resets the recursive walk each time it occurs,
        // and ** cannot be reduced out by a .. pattern part like a regexp
        // or most strings (other than .., ., and '') can be.
        //
        // <pre>/**/../<p>/<p>/<rest> -> {<pre>/../<p>/<p>/<rest>,<pre>/**/<p>/<p>/<rest>}
        // <pre>/<e>/<rest> -> <pre>/<rest>
        // <pre>/<p>/../<rest> -> <pre>/<rest>
        // **/**/<rest> -> **/<rest>
        //
        // **/*/<rest> -> */**/<rest> <== not valid because ** doesn't follow
        // this WOULD be allowed if ** did follow symlinks, or * didn't
        firstPhasePreProcess(globParts) {
          let didSomething = false;
          do {
            didSomething = false;
            // <pre>/**/../<p>/<p>/<rest> -> {<pre>/../<p>/<p>/<rest>,<pre>/**/<p>/<p>/<rest>}
            for (let parts of globParts) {
              let gs = -1;
              while (-1 !== (gs = parts.indexOf('**', gs + 1))) {
                let gss = gs;
                while (parts[gss + 1] === '**') {
                  // <pre>/**/**/<rest> -> <pre>/**/<rest>
                  gss++;
                }
                // eg, if gs is 2 and gss is 4, that means we have 3 **
                // parts, and can remove 2 of them.
                if (gss > gs) {
                  parts.splice(gs + 1, gss - gs);
                }
                let next = parts[gs + 1];
                const p = parts[gs + 2];
                const p2 = parts[gs + 3];
                if (next !== '..') continue;
                if (
                  !p ||
                  p === '.' ||
                  p === '..' ||
                  !p2 ||
                  p2 === '.' ||
                  p2 === '..'
                ) {
                  continue;
                }
                didSomething = true;
                // edit parts in place, and push the new one
                parts.splice(gs, 1);
                const other = parts.slice(0);
                other[gs] = '**';
                globParts.push(other);
                gs--;
              }
              // <pre>/<e>/<rest> -> <pre>/<rest>
              if (!this.preserveMultipleSlashes) {
                for (let i = 1; i < parts.length - 1; i++) {
                  const p = parts[i];
                  // don't squeeze out UNC patterns
                  if (i === 1 && p === '' && parts[0] === '') continue;
                  if (p === '.' || p === '') {
                    didSomething = true;
                    parts.splice(i, 1);
                    i--;
                  }
                }
                if (
                  parts[0] === '.' &&
                  parts.length === 2 &&
                  (parts[1] === '.' || parts[1] === '')
                ) {
                  didSomething = true;
                  parts.pop();
                }
              }
              // <pre>/<p>/../<rest> -> <pre>/<rest>
              let dd = 0;
              while (-1 !== (dd = parts.indexOf('..', dd + 1))) {
                const p = parts[dd - 1];
                if (p && p !== '.' && p !== '..' && p !== '**') {
                  didSomething = true;
                  const needDot = dd === 1 && parts[dd + 1] === '**';
                  const splin = needDot ? ['.'] : [];
                  parts.splice(dd - 1, 2, ...splin);
                  if (parts.length === 0) parts.push('');
                  dd -= 2;
                }
              }
            }
          } while (didSomething);
          return globParts;
        }
        // second phase: multi-pattern dedupes
        // {<pre>/*/<rest>,<pre>/<p>/<rest>} -> <pre>/*/<rest>
        // {<pre>/<rest>,<pre>/<rest>} -> <pre>/<rest>
        // {<pre>/**/<rest>,<pre>/<rest>} -> <pre>/**/<rest>
        //
        // {<pre>/**/<rest>,<pre>/**/<p>/<rest>} -> <pre>/**/<rest>
        // ^-- not valid because ** doens't follow symlinks
        secondPhasePreProcess(globParts) {
          for (let i = 0; i < globParts.length - 1; i++) {
            for (let j = i + 1; j < globParts.length; j++) {
              const matched = this.partsMatch(
                globParts[i],
                globParts[j],
                !this.preserveMultipleSlashes,
              );
              if (matched) {
                globParts[i] = [];
                globParts[j] = matched;
                break;
              }
            }
          }
          return globParts.filter((gs) => gs.length);
        }
        partsMatch(a, b, emptyGSMatch = false) {
          let ai = 0;
          let bi = 0;
          let result = [];
          let which = '';
          while (ai < a.length && bi < b.length) {
            if (a[ai] === b[bi]) {
              result.push(which === 'b' ? b[bi] : a[ai]);
              ai++;
              bi++;
            } else if (emptyGSMatch && a[ai] === '**' && b[bi] === a[ai + 1]) {
              result.push(a[ai]);
              ai++;
            } else if (emptyGSMatch && b[bi] === '**' && a[ai] === b[bi + 1]) {
              result.push(b[bi]);
              bi++;
            } else if (
              a[ai] === '*' &&
              b[bi] &&
              (this.options.dot || !b[bi].startsWith('.')) &&
              b[bi] !== '**'
            ) {
              if (which === 'b') return false;
              which = 'a';
              result.push(a[ai]);
              ai++;
              bi++;
            } else if (
              b[bi] === '*' &&
              a[ai] &&
              (this.options.dot || !a[ai].startsWith('.')) &&
              a[ai] !== '**'
            ) {
              if (which === 'a') return false;
              which = 'b';
              result.push(b[bi]);
              ai++;
              bi++;
            } else {
              return false;
            }
          }
          // if we fall out of the loop, it means they two are identical
          // as long as their lengths match
          return a.length === b.length && result;
        }
        parseNegate() {
          if (this.nonegate) return;
          const pattern = this.pattern;
          let negate = false;
          let negateOffset = 0;
          for (
            let i = 0;
            i < pattern.length && pattern.charAt(i) === '!';
            i++
          ) {
            negate = !negate;
            negateOffset++;
          }
          if (negateOffset) this.pattern = pattern.slice(negateOffset);
          this.negate = negate;
        }
        // set partial to true to test if, for example,
        // "/a/b" matches the start of "/*/b/*/d"
        // Partial means, if you run out of file before you run
        // out of pattern, then that's fine, as long as all
        // the parts match.
        matchOne(file, pattern, partial = false) {
          const options = this.options;
          // UNC paths like //?/X:/... can match X:/... and vice versa
          // Drive letters in absolute drive or unc paths are always compared
          // case-insensitively.
          if (this.isWindows) {
            const fileDrive =
              typeof file[0] === 'string' && /^[a-z]:$/i.test(file[0]);
            const fileUNC =
              !fileDrive &&
              file[0] === '' &&
              file[1] === '' &&
              file[2] === '?' &&
              /^[a-z]:$/i.test(file[3]);
            const patternDrive =
              typeof pattern[0] === 'string' && /^[a-z]:$/i.test(pattern[0]);
            const patternUNC =
              !patternDrive &&
              pattern[0] === '' &&
              pattern[1] === '' &&
              pattern[2] === '?' &&
              typeof pattern[3] === 'string' &&
              /^[a-z]:$/i.test(pattern[3]);
            const fdi = fileUNC ? 3 : fileDrive ? 0 : undefined;
            const pdi = patternUNC ? 3 : patternDrive ? 0 : undefined;
            if (typeof fdi === 'number' && typeof pdi === 'number') {
              const [fd, pd] = [file[fdi], pattern[pdi]];
              if (fd.toLowerCase() === pd.toLowerCase()) {
                pattern[pdi] = fd;
                if (pdi > fdi) {
                  pattern = pattern.slice(pdi);
                } else if (fdi > pdi) {
                  file = file.slice(fdi);
                }
              }
            }
          }
          // resolve and reduce . and .. portions in the file as well.
          // dont' need to do the second phase, because it's only one string[]
          const { optimizationLevel = 1 } = this.options;
          if (optimizationLevel >= 2) {
            file = this.levelTwoFileOptimize(file);
          }
          this.debug('matchOne', this, { file, pattern });
          this.debug('matchOne', file.length, pattern.length);
          for (
            var fi = 0, pi = 0, fl = file.length, pl = pattern.length;
            fi < fl && pi < pl;
            fi++, pi++
          ) {
            this.debug('matchOne loop');
            var p = pattern[pi];
            var f = file[fi];
            this.debug(pattern, p, f);
            // should be impossible.
            // some invalid regexp stuff in the set.
            /* c8 ignore start */
            if (p === false) {
              return false;
            }
            /* c8 ignore stop */
            if (p === exports.GLOBSTAR) {
              this.debug('GLOBSTAR', [pattern, p, f]);
              // "**"
              // a/**/b/**/c would match the following:
              // a/b/x/y/z/c
              // a/x/y/z/b/c
              // a/b/x/b/x/c
              // a/b/c
              // To do this, take the rest of the pattern after
              // the **, and see if it would match the file remainder.
              // If so, return success.
              // If not, the ** "swallows" a segment, and try again.
              // This is recursively awful.
              //
              // a/**/b/**/c matching a/b/x/y/z/c
              // - a matches a
              // - doublestar
              //   - matchOne(b/x/y/z/c, b/**/c)
              //     - b matches b
              //     - doublestar
              //       - matchOne(x/y/z/c, c) -> no
              //       - matchOne(y/z/c, c) -> no
              //       - matchOne(z/c, c) -> no
              //       - matchOne(c, c) yes, hit
              var fr = fi;
              var pr = pi + 1;
              if (pr === pl) {
                this.debug('** at the end');
                // a ** at the end will just swallow the rest.
                // We have found a match.
                // however, it will not swallow /.x, unless
                // options.dot is set.
                // . and .. are *never* matched by **, for explosively
                // exponential reasons.
                for (; fi < fl; fi++) {
                  if (
                    file[fi] === '.' ||
                    file[fi] === '..' ||
                    (!options.dot && file[fi].charAt(0) === '.')
                  )
                    return false;
                }
                return true;
              }
              // ok, let's see if we can swallow whatever we can.
              while (fr < fl) {
                var swallowee = file[fr];
                this.debug(
                  '\nglobstar while',
                  file,
                  fr,
                  pattern,
                  pr,
                  swallowee,
                );
                // XXX remove this slice.  Just pass the start index.
                if (this.matchOne(file.slice(fr), pattern.slice(pr), partial)) {
                  this.debug('globstar found match!', fr, fl, swallowee);
                  // found a match.
                  return true;
                } else {
                  // can't swallow "." or ".." ever.
                  // can only swallow ".foo" when explicitly asked.
                  if (
                    swallowee === '.' ||
                    swallowee === '..' ||
                    (!options.dot && swallowee.charAt(0) === '.')
                  ) {
                    this.debug('dot detected!', file, fr, pattern, pr);
                    break;
                  }
                  // ** swallows a segment, and continue.
                  this.debug('globstar swallow a segment, and continue');
                  fr++;
                }
              }
              // no match was found.
              // However, in partial mode, we can't say this is necessarily over.
              /* c8 ignore start */
              if (partial) {
                // ran out of file
                this.debug('\n>>> no match, partial?', file, fr, pattern, pr);
                if (fr === fl) {
                  return true;
                }
              }
              /* c8 ignore stop */
              return false;
            }
            // something other than **
            // non-magic patterns just have to match exactly
            // patterns with magic have been turned into regexps.
            let hit;
            if (typeof p === 'string') {
              hit = f === p;
              this.debug('string match', p, f, hit);
            } else {
              hit = p.test(f);
              this.debug('pattern match', p, f, hit);
            }
            if (!hit) return false;
          }
          // Note: ending in / means that we'll get a final ""
          // at the end of the pattern.  This can only match a
          // corresponding "" at the end of the file.
          // If the file ends in /, then it can only match a
          // a pattern that ends in /, unless the pattern just
          // doesn't have any more for it. But, a/b/ should *not*
          // match "a/b/*", even though "" matches against the
          // [^/]*? pattern, except in partial mode, where it might
          // simply not be reached yet.
          // However, a/b/ should still satisfy a/*
          // now either we fell off the end of the pattern, or we're done.
          if (fi === fl && pi === pl) {
            // ran out of pattern and filename at the same time.
            // an exact hit!
            return true;
          } else if (fi === fl) {
            // ran out of file, but still had pattern left.
            // this is ok if we're doing the match as part of
            // a glob fs traversal.
            return partial;
          } else if (pi === pl) {
            // ran out of pattern, still have file left.
            // this is only acceptable if we're on the very last
            // empty segment of a file with a trailing slash.
            // a/* should match a/b/
            return fi === fl - 1 && file[fi] === '';
            /* c8 ignore start */
          } else {
            // should be unreachable.
            throw new Error('wtf?');
          }
          /* c8 ignore stop */
        }
        braceExpand() {
          return (0, exports.braceExpand)(this.pattern, this.options);
        }
        parse(pattern) {
          (0, assert_valid_pattern_js_1.assertValidPattern)(pattern);
          const options = this.options;
          // shortcuts
          if (pattern === '**') return exports.GLOBSTAR;
          if (pattern === '') return '';
          // far and away, the most common glob pattern parts are
          // *, *.*, and *.<ext>  Add a fast check method for those.
          let m;
          let fastTest = null;
          if ((m = pattern.match(starRE))) {
            fastTest = options.dot ? starTestDot : starTest;
          } else if ((m = pattern.match(starDotExtRE))) {
            fastTest = (
              options.nocase
                ? options.dot
                  ? starDotExtTestNocaseDot
                  : starDotExtTestNocase
                : options.dot
                  ? starDotExtTestDot
                  : starDotExtTest
            )(m[1]);
          } else if ((m = pattern.match(qmarksRE))) {
            fastTest = (
              options.nocase
                ? options.dot
                  ? qmarksTestNocaseDot
                  : qmarksTestNocase
                : options.dot
                  ? qmarksTestDot
                  : qmarksTest
            )(m);
          } else if ((m = pattern.match(starDotStarRE))) {
            fastTest = options.dot ? starDotStarTestDot : starDotStarTest;
          } else if ((m = pattern.match(dotStarRE))) {
            fastTest = dotStarTest;
          }
          const re = ast_js_1.AST.fromGlob(pattern, this.options).toMMPattern();
          if (fastTest && typeof re === 'object') {
            // Avoids overriding in frozen environments
            Reflect.defineProperty(re, 'test', { value: fastTest });
          }
          return re;
        }
        makeRe() {
          if (this.regexp || this.regexp === false) return this.regexp;
          // at this point, this.set is a 2d array of partial
          // pattern strings, or "**".
          //
          // It's better to use .match().  This function shouldn't
          // be used, really, but it's pretty convenient sometimes,
          // when you just want to work with a regex.
          const set = this.set;
          if (!set.length) {
            this.regexp = false;
            return this.regexp;
          }
          const options = this.options;
          const twoStar = options.noglobstar
            ? star
            : options.dot
              ? twoStarDot
              : twoStarNoDot;
          const flags = new Set(options.nocase ? ['i'] : []);
          // regexpify non-globstar patterns
          // if ** is only item, then we just do one twoStar
          // if ** is first, and there are more, prepend (\/|twoStar\/)? to next
          // if ** is last, append (\/twoStar|) to previous
          // if ** is in the middle, append (\/|\/twoStar\/) to previous
          // then filter out GLOBSTAR symbols
          let re = set
            .map((pattern) => {
              const pp = pattern.map((p) => {
                if (p instanceof RegExp) {
                  for (const f of p.flags.split('')) flags.add(f);
                }
                return typeof p === 'string'
                  ? regExpEscape(p)
                  : p === exports.GLOBSTAR
                    ? exports.GLOBSTAR
                    : p._src;
              });
              pp.forEach((p, i) => {
                const next = pp[i + 1];
                const prev = pp[i - 1];
                if (p !== exports.GLOBSTAR || prev === exports.GLOBSTAR) {
                  return;
                }
                if (prev === undefined) {
                  if (next !== undefined && next !== exports.GLOBSTAR) {
                    pp[i + 1] = '(?:\\/|' + twoStar + '\\/)?' + next;
                  } else {
                    pp[i] = twoStar;
                  }
                } else if (next === undefined) {
                  pp[i - 1] = prev + '(?:\\/|' + twoStar + ')?';
                } else if (next !== exports.GLOBSTAR) {
                  pp[i - 1] = prev + '(?:\\/|\\/' + twoStar + '\\/)' + next;
                  pp[i + 1] = exports.GLOBSTAR;
                }
              });
              return pp.filter((p) => p !== exports.GLOBSTAR).join('/');
            })
            .join('|');
          // need to wrap in parens if we had more than one thing with |,
          // otherwise only the first will be anchored to ^ and the last to $
          const [open, close] = set.length > 1 ? ['(?:', ')'] : ['', ''];
          // must match entire pattern
          // ending in a * or ** will make it less strict.
          re = '^' + open + re + close + '$';
          // can match anything, as long as it's not this.
          if (this.negate) re = '^(?!' + re + ').+$';
          try {
            this.regexp = new RegExp(re, [...flags].join(''));
            /* c8 ignore start */
          } catch (ex) {
            // should be impossible
            this.regexp = false;
          }
          /* c8 ignore stop */
          return this.regexp;
        }
        slashSplit(p) {
          // if p starts with // on windows, we preserve that
          // so that UNC paths aren't broken.  Otherwise, any number of
          // / characters are coalesced into one, unless
          // preserveMultipleSlashes is set to true.
          if (this.preserveMultipleSlashes) {
            return p.split('/');
          } else if (this.isWindows && /^\/\/[^\/]+/.test(p)) {
            // add an extra '' for the one we lose
            return ['', ...p.split(/\/+/)];
          } else {
            return p.split(/\/+/);
          }
        }
        match(f, partial = this.partial) {
          this.debug('match', f, this.pattern);
          // short-circuit in the case of busted things.
          // comments, etc.
          if (this.comment) {
            return false;
          }
          if (this.empty) {
            return f === '';
          }
          if (f === '/' && partial) {
            return true;
          }
          const options = this.options;
          // windows: need to use /, not \
          if (this.isWindows) {
            f = f.split('\\').join('/');
          }
          // treat the test path as a set of pathparts.
          const ff = this.slashSplit(f);
          this.debug(this.pattern, 'split', ff);
          // just ONE of the pattern sets in this.set needs to match
          // in order for it to be valid.  If negating, then just one
          // match means that we have failed.
          // Either way, return on the first hit.
          const set = this.set;
          this.debug(this.pattern, 'set', set);
          // Find the basename of the path by looking for the last non-empty segment
          let filename = ff[ff.length - 1];
          if (!filename) {
            for (let i = ff.length - 2; !filename && i >= 0; i--) {
              filename = ff[i];
            }
          }
          for (let i = 0; i < set.length; i++) {
            const pattern = set[i];
            let file = ff;
            if (options.matchBase && pattern.length === 1) {
              file = [filename];
            }
            const hit = this.matchOne(file, pattern, partial);
            if (hit) {
              if (options.flipNegate) {
                return true;
              }
              return !this.negate;
            }
          }
          // didn't get any hits.  this is success if it's a negative
          // pattern, failure otherwise.
          if (options.flipNegate) {
            return false;
          }
          return this.negate;
        }
        static defaults(def) {
          return exports.minimatch.defaults(def).Minimatch;
        }
      }
      exports.Minimatch = Minimatch;
      /* c8 ignore start */
      var ast_js_2 = __webpack_require__(6078);
      Object.defineProperty(exports, 'AST', {
        enumerable: true,
        get: function () {
          return ast_js_2.AST;
        },
      });
      var escape_js_2 = __webpack_require__(4399);
      Object.defineProperty(exports, 'escape', {
        enumerable: true,
        get: function () {
          return escape_js_2.escape;
        },
      });
      var unescape_js_2 = __webpack_require__(888);
      Object.defineProperty(exports, 'unescape', {
        enumerable: true,
        get: function () {
          return unescape_js_2.unescape;
        },
      });
      /* c8 ignore stop */
      exports.minimatch.AST = ast_js_1.AST;
      exports.minimatch.Minimatch = Minimatch;
      exports.minimatch.escape = escape_js_1.escape;
      exports.minimatch.unescape = unescape_js_1.unescape;
      //# sourceMappingURL=index.js.map

      /***/
    },

    /***/ 888: /***/ (__unused_webpack_module, exports) => {
      'use strict';

      Object.defineProperty(exports, '__esModule', { value: true });
      exports.unescape = void 0;
      /**
       * Un-escape a string that has been escaped with {@link escape}.
       *
       * If the {@link windowsPathsNoEscape} option is used, then square-brace
       * escapes are removed, but not backslash escapes.  For example, it will turn
       * the string `'[*]'` into `*`, but it will not turn `'\\*'` into `'*'`,
       * becuase `\` is a path separator in `windowsPathsNoEscape` mode.
       *
       * When `windowsPathsNoEscape` is not set, then both brace escapes and
       * backslash escapes are removed.
       *
       * Slashes (and backslashes in `windowsPathsNoEscape` mode) cannot be escaped
       * or unescaped.
       */
      const unescape = (s, { windowsPathsNoEscape = false } = {}) => {
        return windowsPathsNoEscape
          ? s.replace(/\[([^\/\\])\]/g, '$1')
          : s
              .replace(/((?!\\).|^)\[([^\/\\])\]/g, '$1$2')
              .replace(/\\([^\/])/g, '$1');
      };
      exports.unescape = unescape;
      //# sourceMappingURL=unescape.js.map

      /***/
    },

    /***/ 2225: /***/ function (
      __unused_webpack_module,
      exports,
      __webpack_require__,
    ) {
      'use strict';

      var __importDefault =
        (this && this.__importDefault) ||
        function (mod) {
          return mod && mod.__esModule ? mod : { default: mod };
        };
      Object.defineProperty(exports, '__esModule', { value: true });
      exports.Minipass =
        exports.isWritable =
        exports.isReadable =
        exports.isStream =
          void 0;
      const proc =
        typeof process === 'object' && process
          ? process
          : {
              stdout: null,
              stderr: null,
            };
      const node_events_1 = __webpack_require__(8474);
      const node_stream_1 = __importDefault(__webpack_require__(7075));
      const node_string_decoder_1 = __webpack_require__(6193);
      /**
       * Return true if the argument is a Minipass stream, Node stream, or something
       * else that Minipass can interact with.
       */
      const isStream = (s) =>
        !!s &&
        typeof s === 'object' &&
        (s instanceof Minipass ||
          s instanceof node_stream_1.default ||
          (0, exports.isReadable)(s) ||
          (0, exports.isWritable)(s));
      exports.isStream = isStream;
      /**
       * Return true if the argument is a valid {@link Minipass.Readable}
       */
      const isReadable = (s) =>
        !!s &&
        typeof s === 'object' &&
        s instanceof node_events_1.EventEmitter &&
        typeof s.pipe === 'function' &&
        // node core Writable streams have a pipe() method, but it throws
        s.pipe !== node_stream_1.default.Writable.prototype.pipe;
      exports.isReadable = isReadable;
      /**
       * Return true if the argument is a valid {@link Minipass.Writable}
       */
      const isWritable = (s) =>
        !!s &&
        typeof s === 'object' &&
        s instanceof node_events_1.EventEmitter &&
        typeof s.write === 'function' &&
        typeof s.end === 'function';
      exports.isWritable = isWritable;
      const EOF = Symbol('EOF');
      const MAYBE_EMIT_END = Symbol('maybeEmitEnd');
      const EMITTED_END = Symbol('emittedEnd');
      const EMITTING_END = Symbol('emittingEnd');
      const EMITTED_ERROR = Symbol('emittedError');
      const CLOSED = Symbol('closed');
      const READ = Symbol('read');
      const FLUSH = Symbol('flush');
      const FLUSHCHUNK = Symbol('flushChunk');
      const ENCODING = Symbol('encoding');
      const DECODER = Symbol('decoder');
      const FLOWING = Symbol('flowing');
      const PAUSED = Symbol('paused');
      const RESUME = Symbol('resume');
      const BUFFER = Symbol('buffer');
      const PIPES = Symbol('pipes');
      const BUFFERLENGTH = Symbol('bufferLength');
      const BUFFERPUSH = Symbol('bufferPush');
      const BUFFERSHIFT = Symbol('bufferShift');
      const OBJECTMODE = Symbol('objectMode');
      // internal event when stream is destroyed
      const DESTROYED = Symbol('destroyed');
      // internal event when stream has an error
      const ERROR = Symbol('error');
      const EMITDATA = Symbol('emitData');
      const EMITEND = Symbol('emitEnd');
      const EMITEND2 = Symbol('emitEnd2');
      const ASYNC = Symbol('async');
      const ABORT = Symbol('abort');
      const ABORTED = Symbol('aborted');
      const SIGNAL = Symbol('signal');
      const DATALISTENERS = Symbol('dataListeners');
      const DISCARDED = Symbol('discarded');
      const defer = (fn) => Promise.resolve().then(fn);
      const nodefer = (fn) => fn();
      const isEndish = (ev) =>
        ev === 'end' || ev === 'finish' || ev === 'prefinish';
      const isArrayBufferLike = (b) =>
        b instanceof ArrayBuffer ||
        (!!b &&
          typeof b === 'object' &&
          b.constructor &&
          b.constructor.name === 'ArrayBuffer' &&
          b.byteLength >= 0);
      const isArrayBufferView = (b) =>
        !Buffer.isBuffer(b) && ArrayBuffer.isView(b);
      /**
       * Internal class representing a pipe to a destination stream.
       *
       * @internal
       */
      class Pipe {
        src;
        dest;
        opts;
        ondrain;
        constructor(src, dest, opts) {
          this.src = src;
          this.dest = dest;
          this.opts = opts;
          this.ondrain = () => src[RESUME]();
          this.dest.on('drain', this.ondrain);
        }
        unpipe() {
          this.dest.removeListener('drain', this.ondrain);
        }
        // only here for the prototype
        /* c8 ignore start */
        proxyErrors(_er) {}
        /* c8 ignore stop */
        end() {
          this.unpipe();
          if (this.opts.end) this.dest.end();
        }
      }
      /**
       * Internal class representing a pipe to a destination stream where
       * errors are proxied.
       *
       * @internal
       */
      class PipeProxyErrors extends Pipe {
        unpipe() {
          this.src.removeListener('error', this.proxyErrors);
          super.unpipe();
        }
        constructor(src, dest, opts) {
          super(src, dest, opts);
          this.proxyErrors = (er) => dest.emit('error', er);
          src.on('error', this.proxyErrors);
        }
      }
      const isObjectModeOptions = (o) => !!o.objectMode;
      const isEncodingOptions = (o) =>
        !o.objectMode && !!o.encoding && o.encoding !== 'buffer';
      /**
       * Main export, the Minipass class
       *
       * `RType` is the type of data emitted, defaults to Buffer
       *
       * `WType` is the type of data to be written, if RType is buffer or string,
       * then any {@link Minipass.ContiguousData} is allowed.
       *
       * `Events` is the set of event handler signatures that this object
       * will emit, see {@link Minipass.Events}
       */
      class Minipass extends node_events_1.EventEmitter {
        [FLOWING] = false;
        [PAUSED] = false;
        [PIPES] = [];
        [BUFFER] = [];
        [OBJECTMODE];
        [ENCODING];
        [ASYNC];
        [DECODER];
        [EOF] = false;
        [EMITTED_END] = false;
        [EMITTING_END] = false;
        [CLOSED] = false;
        [EMITTED_ERROR] = null;
        [BUFFERLENGTH] = 0;
        [DESTROYED] = false;
        [SIGNAL];
        [ABORTED] = false;
        [DATALISTENERS] = 0;
        [DISCARDED] = false;
        /**
         * true if the stream can be written
         */
        writable = true;
        /**
         * true if the stream can be read
         */
        readable = true;
        /**
         * If `RType` is Buffer, then options do not need to be provided.
         * Otherwise, an options object must be provided to specify either
         * {@link Minipass.SharedOptions.objectMode} or
         * {@link Minipass.SharedOptions.encoding}, as appropriate.
         */
        constructor(...args) {
          const options = args[0] || {};
          super();
          if (options.objectMode && typeof options.encoding === 'string') {
            throw new TypeError(
              'Encoding and objectMode may not be used together',
            );
          }
          if (isObjectModeOptions(options)) {
            this[OBJECTMODE] = true;
            this[ENCODING] = null;
          } else if (isEncodingOptions(options)) {
            this[ENCODING] = options.encoding;
            this[OBJECTMODE] = false;
          } else {
            this[OBJECTMODE] = false;
            this[ENCODING] = null;
          }
          this[ASYNC] = !!options.async;
          this[DECODER] = this[ENCODING]
            ? new node_string_decoder_1.StringDecoder(this[ENCODING])
            : null;
          //@ts-ignore - private option for debugging and testing
          if (options && options.debugExposeBuffer === true) {
            Object.defineProperty(this, 'buffer', { get: () => this[BUFFER] });
          }
          //@ts-ignore - private option for debugging and testing
          if (options && options.debugExposePipes === true) {
            Object.defineProperty(this, 'pipes', { get: () => this[PIPES] });
          }
          const { signal } = options;
          if (signal) {
            this[SIGNAL] = signal;
            if (signal.aborted) {
              this[ABORT]();
            } else {
              signal.addEventListener('abort', () => this[ABORT]());
            }
          }
        }
        /**
         * The amount of data stored in the buffer waiting to be read.
         *
         * For Buffer strings, this will be the total byte length.
         * For string encoding streams, this will be the string character length,
         * according to JavaScript's `string.length` logic.
         * For objectMode streams, this is a count of the items waiting to be
         * emitted.
         */
        get bufferLength() {
          return this[BUFFERLENGTH];
        }
        /**
         * The `BufferEncoding` currently in use, or `null`
         */
        get encoding() {
          return this[ENCODING];
        }
        /**
         * @deprecated - This is a read only property
         */
        set encoding(_enc) {
          throw new Error('Encoding must be set at instantiation time');
        }
        /**
         * @deprecated - Encoding may only be set at instantiation time
         */
        setEncoding(_enc) {
          throw new Error('Encoding must be set at instantiation time');
        }
        /**
         * True if this is an objectMode stream
         */
        get objectMode() {
          return this[OBJECTMODE];
        }
        /**
         * @deprecated - This is a read-only property
         */
        set objectMode(_om) {
          throw new Error('objectMode must be set at instantiation time');
        }
        /**
         * true if this is an async stream
         */
        get ['async']() {
          return this[ASYNC];
        }
        /**
         * Set to true to make this stream async.
         *
         * Once set, it cannot be unset, as this would potentially cause incorrect
         * behavior.  Ie, a sync stream can be made async, but an async stream
         * cannot be safely made sync.
         */
        set ['async'](a) {
          this[ASYNC] = this[ASYNC] || !!a;
        }
        // drop everything and get out of the flow completely
        [ABORT]() {
          this[ABORTED] = true;
          this.emit('abort', this[SIGNAL]?.reason);
          this.destroy(this[SIGNAL]?.reason);
        }
        /**
         * True if the stream has been aborted.
         */
        get aborted() {
          return this[ABORTED];
        }
        /**
         * No-op setter. Stream aborted status is set via the AbortSignal provided
         * in the constructor options.
         */
        set aborted(_) {}
        write(chunk, encoding, cb) {
          if (this[ABORTED]) return false;
          if (this[EOF]) throw new Error('write after end');
          if (this[DESTROYED]) {
            this.emit(
              'error',
              Object.assign(
                new Error('Cannot call write after a stream was destroyed'),
                { code: 'ERR_STREAM_DESTROYED' },
              ),
            );
            return true;
          }
          if (typeof encoding === 'function') {
            cb = encoding;
            encoding = 'utf8';
          }
          if (!encoding) encoding = 'utf8';
          const fn = this[ASYNC] ? defer : nodefer;
          // convert array buffers and typed array views into buffers
          // at some point in the future, we may want to do the opposite!
          // leave strings and buffers as-is
          // anything is only allowed if in object mode, so throw
          if (!this[OBJECTMODE] && !Buffer.isBuffer(chunk)) {
            if (isArrayBufferView(chunk)) {
              //@ts-ignore - sinful unsafe type changing
              chunk = Buffer.from(
                chunk.buffer,
                chunk.byteOffset,
                chunk.byteLength,
              );
            } else if (isArrayBufferLike(chunk)) {
              //@ts-ignore - sinful unsafe type changing
              chunk = Buffer.from(chunk);
            } else if (typeof chunk !== 'string') {
              throw new Error(
                'Non-contiguous data written to non-objectMode stream',
              );
            }
          }
          // handle object mode up front, since it's simpler
          // this yields better performance, fewer checks later.
          if (this[OBJECTMODE]) {
            // maybe impossible?
            /* c8 ignore start */
            if (this[FLOWING] && this[BUFFERLENGTH] !== 0) this[FLUSH](true);
            /* c8 ignore stop */
            if (this[FLOWING]) this.emit('data', chunk);
            else this[BUFFERPUSH](chunk);
            if (this[BUFFERLENGTH] !== 0) this.emit('readable');
            if (cb) fn(cb);
            return this[FLOWING];
          }
          // at this point the chunk is a buffer or string
          // don't buffer it up or send it to the decoder
          if (!chunk.length) {
            if (this[BUFFERLENGTH] !== 0) this.emit('readable');
            if (cb) fn(cb);
            return this[FLOWING];
          }
          // fast-path writing strings of same encoding to a stream with
          // an empty buffer, skipping the buffer/decoder dance
          if (
            typeof chunk === 'string' &&
            // unless it is a string already ready for us to use
            !(encoding === this[ENCODING] && !this[DECODER]?.lastNeed)
          ) {
            //@ts-ignore - sinful unsafe type change
            chunk = Buffer.from(chunk, encoding);
          }
          if (Buffer.isBuffer(chunk) && this[ENCODING]) {
            //@ts-ignore - sinful unsafe type change
            chunk = this[DECODER].write(chunk);
          }
          // Note: flushing CAN potentially switch us into not-flowing mode
          if (this[FLOWING] && this[BUFFERLENGTH] !== 0) this[FLUSH](true);
          if (this[FLOWING]) this.emit('data', chunk);
          else this[BUFFERPUSH](chunk);
          if (this[BUFFERLENGTH] !== 0) this.emit('readable');
          if (cb) fn(cb);
          return this[FLOWING];
        }
        /**
         * Low-level explicit read method.
         *
         * In objectMode, the argument is ignored, and one item is returned if
         * available.
         *
         * `n` is the number of bytes (or in the case of encoding streams,
         * characters) to consume. If `n` is not provided, then the entire buffer
         * is returned, or `null` is returned if no data is available.
         *
         * If `n` is greater that the amount of data in the internal buffer,
         * then `null` is returned.
         */
        read(n) {
          if (this[DESTROYED]) return null;
          this[DISCARDED] = false;
          if (
            this[BUFFERLENGTH] === 0 ||
            n === 0 ||
            (n && n > this[BUFFERLENGTH])
          ) {
            this[MAYBE_EMIT_END]();
            return null;
          }
          if (this[OBJECTMODE]) n = null;
          if (this[BUFFER].length > 1 && !this[OBJECTMODE]) {
            // not object mode, so if we have an encoding, then RType is string
            // otherwise, must be Buffer
            this[BUFFER] = [
              this[ENCODING]
                ? this[BUFFER].join('')
                : Buffer.concat(this[BUFFER], this[BUFFERLENGTH]),
            ];
          }
          const ret = this[READ](n || null, this[BUFFER][0]);
          this[MAYBE_EMIT_END]();
          return ret;
        }
        [READ](n, chunk) {
          if (this[OBJECTMODE]) this[BUFFERSHIFT]();
          else {
            const c = chunk;
            if (n === c.length || n === null) this[BUFFERSHIFT]();
            else if (typeof c === 'string') {
              this[BUFFER][0] = c.slice(n);
              chunk = c.slice(0, n);
              this[BUFFERLENGTH] -= n;
            } else {
              this[BUFFER][0] = c.subarray(n);
              chunk = c.subarray(0, n);
              this[BUFFERLENGTH] -= n;
            }
          }
          this.emit('data', chunk);
          if (!this[BUFFER].length && !this[EOF]) this.emit('drain');
          return chunk;
        }
        end(chunk, encoding, cb) {
          if (typeof chunk === 'function') {
            cb = chunk;
            chunk = undefined;
          }
          if (typeof encoding === 'function') {
            cb = encoding;
            encoding = 'utf8';
          }
          if (chunk !== undefined) this.write(chunk, encoding);
          if (cb) this.once('end', cb);
          this[EOF] = true;
          this.writable = false;
          // if we haven't written anything, then go ahead and emit,
          // even if we're not reading.
          // we'll re-emit if a new 'end' listener is added anyway.
          // This makes MP more suitable to write-only use cases.
          if (this[FLOWING] || !this[PAUSED]) this[MAYBE_EMIT_END]();
          return this;
        }
        // don't let the internal resume be overwritten
        [RESUME]() {
          if (this[DESTROYED]) return;
          if (!this[DATALISTENERS] && !this[PIPES].length) {
            this[DISCARDED] = true;
          }
          this[PAUSED] = false;
          this[FLOWING] = true;
          this.emit('resume');
          if (this[BUFFER].length) this[FLUSH]();
          else if (this[EOF]) this[MAYBE_EMIT_END]();
          else this.emit('drain');
        }
        /**
         * Resume the stream if it is currently in a paused state
         *
         * If called when there are no pipe destinations or `data` event listeners,
         * this will place the stream in a "discarded" state, where all data will
         * be thrown away. The discarded state is removed if a pipe destination or
         * data handler is added, if pause() is called, or if any synchronous or
         * asynchronous iteration is started.
         */
        resume() {
          return this[RESUME]();
        }
        /**
         * Pause the stream
         */
        pause() {
          this[FLOWING] = false;
          this[PAUSED] = true;
          this[DISCARDED] = false;
        }
        /**
         * true if the stream has been forcibly destroyed
         */
        get destroyed() {
          return this[DESTROYED];
        }
        /**
         * true if the stream is currently in a flowing state, meaning that
         * any writes will be immediately emitted.
         */
        get flowing() {
          return this[FLOWING];
        }
        /**
         * true if the stream is currently in a paused state
         */
        get paused() {
          return this[PAUSED];
        }
        [BUFFERPUSH](chunk) {
          if (this[OBJECTMODE]) this[BUFFERLENGTH] += 1;
          else this[BUFFERLENGTH] += chunk.length;
          this[BUFFER].push(chunk);
        }
        [BUFFERSHIFT]() {
          if (this[OBJECTMODE]) this[BUFFERLENGTH] -= 1;
          else this[BUFFERLENGTH] -= this[BUFFER][0].length;
          return this[BUFFER].shift();
        }
        [FLUSH](noDrain = false) {
          do {} while (
            this[FLUSHCHUNK](this[BUFFERSHIFT]()) &&
            this[BUFFER].length
          );
          if (!noDrain && !this[BUFFER].length && !this[EOF])
            this.emit('drain');
        }
        [FLUSHCHUNK](chunk) {
          this.emit('data', chunk);
          return this[FLOWING];
        }
        /**
         * Pipe all data emitted by this stream into the destination provided.
         *
         * Triggers the flow of data.
         */
        pipe(dest, opts) {
          if (this[DESTROYED]) return dest;
          this[DISCARDED] = false;
          const ended = this[EMITTED_END];
          opts = opts || {};
          if (dest === proc.stdout || dest === proc.stderr) opts.end = false;
          else opts.end = opts.end !== false;
          opts.proxyErrors = !!opts.proxyErrors;
          // piping an ended stream ends immediately
          if (ended) {
            if (opts.end) dest.end();
          } else {
            // "as" here just ignores the WType, which pipes don't care about,
            // since they're only consuming from us, and writing to the dest
            this[PIPES].push(
              !opts.proxyErrors
                ? new Pipe(this, dest, opts)
                : new PipeProxyErrors(this, dest, opts),
            );
            if (this[ASYNC]) defer(() => this[RESUME]());
            else this[RESUME]();
          }
          return dest;
        }
        /**
         * Fully unhook a piped destination stream.
         *
         * If the destination stream was the only consumer of this stream (ie,
         * there are no other piped destinations or `'data'` event listeners)
         * then the flow of data will stop until there is another consumer or
         * {@link Minipass#resume} is explicitly called.
         */
        unpipe(dest) {
          const p = this[PIPES].find((p) => p.dest === dest);
          if (p) {
            if (this[PIPES].length === 1) {
              if (this[FLOWING] && this[DATALISTENERS] === 0) {
                this[FLOWING] = false;
              }
              this[PIPES] = [];
            } else this[PIPES].splice(this[PIPES].indexOf(p), 1);
            p.unpipe();
          }
        }
        /**
         * Alias for {@link Minipass#on}
         */
        addListener(ev, handler) {
          return this.on(ev, handler);
        }
        /**
         * Mostly identical to `EventEmitter.on`, with the following
         * behavior differences to prevent data loss and unnecessary hangs:
         *
         * - Adding a 'data' event handler will trigger the flow of data
         *
         * - Adding a 'readable' event handler when there is data waiting to be read
         *   will cause 'readable' to be emitted immediately.
         *
         * - Adding an 'endish' event handler ('end', 'finish', etc.) which has
         *   already passed will cause the event to be emitted immediately and all
         *   handlers removed.
         *
         * - Adding an 'error' event handler after an error has been emitted will
         *   cause the event to be re-emitted immediately with the error previously
         *   raised.
         */
        on(ev, handler) {
          const ret = super.on(ev, handler);
          if (ev === 'data') {
            this[DISCARDED] = false;
            this[DATALISTENERS]++;
            if (!this[PIPES].length && !this[FLOWING]) {
              this[RESUME]();
            }
          } else if (ev === 'readable' && this[BUFFERLENGTH] !== 0) {
            super.emit('readable');
          } else if (isEndish(ev) && this[EMITTED_END]) {
            super.emit(ev);
            this.removeAllListeners(ev);
          } else if (ev === 'error' && this[EMITTED_ERROR]) {
            const h = handler;
            if (this[ASYNC]) defer(() => h.call(this, this[EMITTED_ERROR]));
            else h.call(this, this[EMITTED_ERROR]);
          }
          return ret;
        }
        /**
         * Alias for {@link Minipass#off}
         */
        removeListener(ev, handler) {
          return this.off(ev, handler);
        }
        /**
         * Mostly identical to `EventEmitter.off`
         *
         * If a 'data' event handler is removed, and it was the last consumer
         * (ie, there are no pipe destinations or other 'data' event listeners),
         * then the flow of data will stop until there is another consumer or
         * {@link Minipass#resume} is explicitly called.
         */
        off(ev, handler) {
          const ret = super.off(ev, handler);
          // if we previously had listeners, and now we don't, and we don't
          // have any pipes, then stop the flow, unless it's been explicitly
          // put in a discarded flowing state via stream.resume().
          if (ev === 'data') {
            this[DATALISTENERS] = this.listeners('data').length;
            if (
              this[DATALISTENERS] === 0 &&
              !this[DISCARDED] &&
              !this[PIPES].length
            ) {
              this[FLOWING] = false;
            }
          }
          return ret;
        }
        /**
         * Mostly identical to `EventEmitter.removeAllListeners`
         *
         * If all 'data' event handlers are removed, and they were the last consumer
         * (ie, there are no pipe destinations), then the flow of data will stop
         * until there is another consumer or {@link Minipass#resume} is explicitly
         * called.
         */
        removeAllListeners(ev) {
          const ret = super.removeAllListeners(ev);
          if (ev === 'data' || ev === undefined) {
            this[DATALISTENERS] = 0;
            if (!this[DISCARDED] && !this[PIPES].length) {
              this[FLOWING] = false;
            }
          }
          return ret;
        }
        /**
         * true if the 'end' event has been emitted
         */
        get emittedEnd() {
          return this[EMITTED_END];
        }
        [MAYBE_EMIT_END]() {
          if (
            !this[EMITTING_END] &&
            !this[EMITTED_END] &&
            !this[DESTROYED] &&
            this[BUFFER].length === 0 &&
            this[EOF]
          ) {
            this[EMITTING_END] = true;
            this.emit('end');
            this.emit('prefinish');
            this.emit('finish');
            if (this[CLOSED]) this.emit('close');
            this[EMITTING_END] = false;
          }
        }
        /**
         * Mostly identical to `EventEmitter.emit`, with the following
         * behavior differences to prevent data loss and unnecessary hangs:
         *
         * If the stream has been destroyed, and the event is something other
         * than 'close' or 'error', then `false` is returned and no handlers
         * are called.
         *
         * If the event is 'end', and has already been emitted, then the event
         * is ignored. If the stream is in a paused or non-flowing state, then
         * the event will be deferred until data flow resumes. If the stream is
         * async, then handlers will be called on the next tick rather than
         * immediately.
         *
         * If the event is 'close', and 'end' has not yet been emitted, then
         * the event will be deferred until after 'end' is emitted.
         *
         * If the event is 'error', and an AbortSignal was provided for the stream,
         * and there are no listeners, then the event is ignored, matching the
         * behavior of node core streams in the presense of an AbortSignal.
         *
         * If the event is 'finish' or 'prefinish', then all listeners will be
         * removed after emitting the event, to prevent double-firing.
         */
        emit(ev, ...args) {
          const data = args[0];
          // error and close are only events allowed after calling destroy()
          if (
            ev !== 'error' &&
            ev !== 'close' &&
            ev !== DESTROYED &&
            this[DESTROYED]
          ) {
            return false;
          } else if (ev === 'data') {
            return !this[OBJECTMODE] && !data
              ? false
              : this[ASYNC]
                ? (defer(() => this[EMITDATA](data)), true)
                : this[EMITDATA](data);
          } else if (ev === 'end') {
            return this[EMITEND]();
          } else if (ev === 'close') {
            this[CLOSED] = true;
            // don't emit close before 'end' and 'finish'
            if (!this[EMITTED_END] && !this[DESTROYED]) return false;
            const ret = super.emit('close');
            this.removeAllListeners('close');
            return ret;
          } else if (ev === 'error') {
            this[EMITTED_ERROR] = data;
            super.emit(ERROR, data);
            const ret =
              !this[SIGNAL] || this.listeners('error').length
                ? super.emit('error', data)
                : false;
            this[MAYBE_EMIT_END]();
            return ret;
          } else if (ev === 'resume') {
            const ret = super.emit('resume');
            this[MAYBE_EMIT_END]();
            return ret;
          } else if (ev === 'finish' || ev === 'prefinish') {
            const ret = super.emit(ev);
            this.removeAllListeners(ev);
            return ret;
          }
          // Some other unknown event
          const ret = super.emit(ev, ...args);
          this[MAYBE_EMIT_END]();
          return ret;
        }
        [EMITDATA](data) {
          for (const p of this[PIPES]) {
            if (p.dest.write(data) === false) this.pause();
          }
          const ret = this[DISCARDED] ? false : super.emit('data', data);
          this[MAYBE_EMIT_END]();
          return ret;
        }
        [EMITEND]() {
          if (this[EMITTED_END]) return false;
          this[EMITTED_END] = true;
          this.readable = false;
          return this[ASYNC]
            ? (defer(() => this[EMITEND2]()), true)
            : this[EMITEND2]();
        }
        [EMITEND2]() {
          if (this[DECODER]) {
            const data = this[DECODER].end();
            if (data) {
              for (const p of this[PIPES]) {
                p.dest.write(data);
              }
              if (!this[DISCARDED]) super.emit('data', data);
            }
          }
          for (const p of this[PIPES]) {
            p.end();
          }
          const ret = super.emit('end');
          this.removeAllListeners('end');
          return ret;
        }
        /**
         * Return a Promise that resolves to an array of all emitted data once
         * the stream ends.
         */
        async collect() {
          const buf = Object.assign([], {
            dataLength: 0,
          });
          if (!this[OBJECTMODE]) buf.dataLength = 0;
          // set the promise first, in case an error is raised
          // by triggering the flow here.
          const p = this.promise();
          this.on('data', (c) => {
            buf.push(c);
            if (!this[OBJECTMODE]) buf.dataLength += c.length;
          });
          await p;
          return buf;
        }
        /**
         * Return a Promise that resolves to the concatenation of all emitted data
         * once the stream ends.
         *
         * Not allowed on objectMode streams.
         */
        async concat() {
          if (this[OBJECTMODE]) {
            throw new Error('cannot concat in objectMode');
          }
          const buf = await this.collect();
          return this[ENCODING]
            ? buf.join('')
            : Buffer.concat(buf, buf.dataLength);
        }
        /**
         * Return a void Promise that resolves once the stream ends.
         */
        async promise() {
          return new Promise((resolve, reject) => {
            this.on(DESTROYED, () => reject(new Error('stream destroyed')));
            this.on('error', (er) => reject(er));
            this.on('end', () => resolve());
          });
        }
        /**
         * Asynchronous `for await of` iteration.
         *
         * This will continue emitting all chunks until the stream terminates.
         */
        [Symbol.asyncIterator]() {
          // set this up front, in case the consumer doesn't call next()
          // right away.
          this[DISCARDED] = false;
          let stopped = false;
          const stop = async () => {
            this.pause();
            stopped = true;
            return { value: undefined, done: true };
          };
          const next = () => {
            if (stopped) return stop();
            const res = this.read();
            if (res !== null)
              return Promise.resolve({ done: false, value: res });
            if (this[EOF]) return stop();
            let resolve;
            let reject;
            const onerr = (er) => {
              this.off('data', ondata);
              this.off('end', onend);
              this.off(DESTROYED, ondestroy);
              stop();
              reject(er);
            };
            const ondata = (value) => {
              this.off('error', onerr);
              this.off('end', onend);
              this.off(DESTROYED, ondestroy);
              this.pause();
              resolve({ value, done: !!this[EOF] });
            };
            const onend = () => {
              this.off('error', onerr);
              this.off('data', ondata);
              this.off(DESTROYED, ondestroy);
              stop();
              resolve({ done: true, value: undefined });
            };
            const ondestroy = () => onerr(new Error('stream destroyed'));
            return new Promise((res, rej) => {
              reject = rej;
              resolve = res;
              this.once(DESTROYED, ondestroy);
              this.once('error', onerr);
              this.once('end', onend);
              this.once('data', ondata);
            });
          };
          return {
            next,
            throw: stop,
            return: stop,
            [Symbol.asyncIterator]() {
              return this;
            },
          };
        }
        /**
         * Synchronous `for of` iteration.
         *
         * The iteration will terminate when the internal buffer runs out, even
         * if the stream has not yet terminated.
         */
        [Symbol.iterator]() {
          // set this up front, in case the consumer doesn't call next()
          // right away.
          this[DISCARDED] = false;
          let stopped = false;
          const stop = () => {
            this.pause();
            this.off(ERROR, stop);
            this.off(DESTROYED, stop);
            this.off('end', stop);
            stopped = true;
            return { done: true, value: undefined };
          };
          const next = () => {
            if (stopped) return stop();
            const value = this.read();
            return value === null ? stop() : { done: false, value };
          };
          this.once('end', stop);
          this.once(ERROR, stop);
          this.once(DESTROYED, stop);
          return {
            next,
            throw: stop,
            return: stop,
            [Symbol.iterator]() {
              return this;
            },
          };
        }
        /**
         * Destroy a stream, preventing it from being used for any further purpose.
         *
         * If the stream has a `close()` method, then it will be called on
         * destruction.
         *
         * After destruction, any attempt to write data, read data, or emit most
         * events will be ignored.
         *
         * If an error argument is provided, then it will be emitted in an
         * 'error' event.
         */
        destroy(er) {
          if (this[DESTROYED]) {
            if (er) this.emit('error', er);
            else this.emit(DESTROYED);
            return this;
          }
          this[DESTROYED] = true;
          this[DISCARDED] = true;
          // throw away all buffered data, it's never coming out
          this[BUFFER].length = 0;
          this[BUFFERLENGTH] = 0;
          const wc = this;
          if (typeof wc.close === 'function' && !this[CLOSED]) wc.close();
          if (er) this.emit('error', er);
          // if no error to emit, still reject pending promises
          else this.emit(DESTROYED);
          return this;
        }
        /**
         * Alias for {@link isStream}
         *
         * Former export location, maintained for backwards compatibility.
         *
         * @deprecated
         */
        static get isStream() {
          return exports.isStream;
        }
      }
      exports.Minipass = Minipass;
      //# sourceMappingURL=index.js.map

      /***/
    },

    /***/ 642: /***/ function (
      __unused_webpack_module,
      exports,
      __webpack_require__,
    ) {
      'use strict';

      var __createBinding =
        (this && this.__createBinding) ||
        (Object.create
          ? function (o, m, k, k2) {
              if (k2 === undefined) k2 = k;
              var desc = Object.getOwnPropertyDescriptor(m, k);
              if (
                !desc ||
                ('get' in desc
                  ? !m.__esModule
                  : desc.writable || desc.configurable)
              ) {
                desc = {
                  enumerable: true,
                  get: function () {
                    return m[k];
                  },
                };
              }
              Object.defineProperty(o, k2, desc);
            }
          : function (o, m, k, k2) {
              if (k2 === undefined) k2 = k;
              o[k2] = m[k];
            });
      var __setModuleDefault =
        (this && this.__setModuleDefault) ||
        (Object.create
          ? function (o, v) {
              Object.defineProperty(o, 'default', {
                enumerable: true,
                value: v,
              });
            }
          : function (o, v) {
              o['default'] = v;
            });
      var __importStar =
        (this && this.__importStar) ||
        function (mod) {
          if (mod && mod.__esModule) return mod;
          var result = {};
          if (mod != null)
            for (var k in mod)
              if (
                k !== 'default' &&
                Object.prototype.hasOwnProperty.call(mod, k)
              )
                __createBinding(result, mod, k);
          __setModuleDefault(result, mod);
          return result;
        };
      Object.defineProperty(exports, '__esModule', { value: true });
      exports.PathScurry =
        exports.Path =
        exports.PathScurryDarwin =
        exports.PathScurryPosix =
        exports.PathScurryWin32 =
        exports.PathScurryBase =
        exports.PathPosix =
        exports.PathWin32 =
        exports.PathBase =
        exports.ChildrenCache =
        exports.ResolveCache =
          void 0;
      const lru_cache_1 = __webpack_require__(4606);
      const node_path_1 = __webpack_require__(6760);
      const node_url_1 = __webpack_require__(3136);
      const fs_1 = __webpack_require__(9896);
      const actualFS = __importStar(__webpack_require__(3024));
      const realpathSync = fs_1.realpathSync.native;
      // TODO: test perf of fs/promises realpath vs realpathCB,
      // since the promises one uses realpath.native
      const promises_1 = __webpack_require__(1455);
      const minipass_1 = __webpack_require__(2225);
      const defaultFS = {
        lstatSync: fs_1.lstatSync,
        readdir: fs_1.readdir,
        readdirSync: fs_1.readdirSync,
        readlinkSync: fs_1.readlinkSync,
        realpathSync,
        promises: {
          lstat: promises_1.lstat,
          readdir: promises_1.readdir,
          readlink: promises_1.readlink,
          realpath: promises_1.realpath,
        },
      };
      // if they just gave us require('fs') then use our default
      const fsFromOption = (fsOption) =>
        !fsOption || fsOption === defaultFS || fsOption === actualFS
          ? defaultFS
          : {
              ...defaultFS,
              ...fsOption,
              promises: {
                ...defaultFS.promises,
                ...(fsOption.promises || {}),
              },
            };
      // turn something like //?/c:/ into c:\
      const uncDriveRegexp = /^\\\\\?\\([a-z]:)\\?$/i;
      const uncToDrive = (rootPath) =>
        rootPath.replace(/\//g, '\\').replace(uncDriveRegexp, '$1\\');
      // windows paths are separated by either / or \
      const eitherSep = /[\\\/]/;
      const UNKNOWN = 0; // may not even exist, for all we know
      const IFIFO = 0b0001;
      const IFCHR = 0b0010;
      const IFDIR = 0b0100;
      const IFBLK = 0b0110;
      const IFREG = 0b1000;
      const IFLNK = 0b1010;
      const IFSOCK = 0b1100;
      const IFMT = 0b1111;
      // mask to unset low 4 bits
      const IFMT_UNKNOWN = ~IFMT;
      // set after successfully calling readdir() and getting entries.
      const READDIR_CALLED = 0b0000_0001_0000;
      // set after a successful lstat()
      const LSTAT_CALLED = 0b0000_0010_0000;
      // set if an entry (or one of its parents) is definitely not a dir
      const ENOTDIR = 0b0000_0100_0000;
      // set if an entry (or one of its parents) does not exist
      // (can also be set on lstat errors like EACCES or ENAMETOOLONG)
      const ENOENT = 0b0000_1000_0000;
      // cannot have child entries -- also verify &IFMT is either IFDIR or IFLNK
      // set if we fail to readlink
      const ENOREADLINK = 0b0001_0000_0000;
      // set if we know realpath() will fail
      const ENOREALPATH = 0b0010_0000_0000;
      const ENOCHILD = ENOTDIR | ENOENT | ENOREALPATH;
      const TYPEMASK = 0b0011_1111_1111;
      const entToType = (s) =>
        s.isFile()
          ? IFREG
          : s.isDirectory()
            ? IFDIR
            : s.isSymbolicLink()
              ? IFLNK
              : s.isCharacterDevice()
                ? IFCHR
                : s.isBlockDevice()
                  ? IFBLK
                  : s.isSocket()
                    ? IFSOCK
                    : s.isFIFO()
                      ? IFIFO
                      : UNKNOWN;
      // normalize unicode path names
      const normalizeCache = new Map();
      const normalize = (s) => {
        const c = normalizeCache.get(s);
        if (c) return c;
        const n = s.normalize('NFKD');
        normalizeCache.set(s, n);
        return n;
      };
      const normalizeNocaseCache = new Map();
      const normalizeNocase = (s) => {
        const c = normalizeNocaseCache.get(s);
        if (c) return c;
        const n = normalize(s.toLowerCase());
        normalizeNocaseCache.set(s, n);
        return n;
      };
      /**
       * An LRUCache for storing resolved path strings or Path objects.
       * @internal
       */
      class ResolveCache extends lru_cache_1.LRUCache {
        constructor() {
          super({ max: 256 });
        }
      }
      exports.ResolveCache = ResolveCache;
      // In order to prevent blowing out the js heap by allocating hundreds of
      // thousands of Path entries when walking extremely large trees, the "children"
      // in this tree are represented by storing an array of Path entries in an
      // LRUCache, indexed by the parent.  At any time, Path.children() may return an
      // empty array, indicating that it doesn't know about any of its children, and
      // thus has to rebuild that cache.  This is fine, it just means that we don't
      // benefit as much from having the cached entries, but huge directory walks
      // don't blow out the stack, and smaller ones are still as fast as possible.
      //
      //It does impose some complexity when building up the readdir data, because we
      //need to pass a reference to the children array that we started with.
      /**
       * an LRUCache for storing child entries.
       * @internal
       */
      class ChildrenCache extends lru_cache_1.LRUCache {
        constructor(maxSize = 16 * 1024) {
          super({
            maxSize,
            // parent + children
            sizeCalculation: (a) => a.length + 1,
          });
        }
      }
      exports.ChildrenCache = ChildrenCache;
      const setAsCwd = Symbol('PathScurry setAsCwd');
      /**
       * Path objects are sort of like a super-powered
       * {@link https://nodejs.org/docs/latest/api/fs.html#class-fsdirent fs.Dirent}
       *
       * Each one represents a single filesystem entry on disk, which may or may not
       * exist. It includes methods for reading various types of information via
       * lstat, readlink, and readdir, and caches all information to the greatest
       * degree possible.
       *
       * Note that fs operations that would normally throw will instead return an
       * "empty" value. This is in order to prevent excessive overhead from error
       * stack traces.
       */
      class PathBase {
        /**
         * the basename of this path
         *
         * **Important**: *always* test the path name against any test string
         * usingthe {@link isNamed} method, and not by directly comparing this
         * string. Otherwise, unicode path strings that the system sees as identical
         * will not be properly treated as the same path, leading to incorrect
         * behavior and possible security issues.
         */
        name;
        /**
         * the Path entry corresponding to the path root.
         *
         * @internal
         */
        root;
        /**
         * All roots found within the current PathScurry family
         *
         * @internal
         */
        roots;
        /**
         * a reference to the parent path, or undefined in the case of root entries
         *
         * @internal
         */
        parent;
        /**
         * boolean indicating whether paths are compared case-insensitively
         * @internal
         */
        nocase;
        /**
         * boolean indicating that this path is the current working directory
         * of the PathScurry collection that contains it.
         */
        isCWD = false;
        // potential default fs override
        #fs;
        // Stats fields
        #dev;
        get dev() {
          return this.#dev;
        }
        #mode;
        get mode() {
          return this.#mode;
        }
        #nlink;
        get nlink() {
          return this.#nlink;
        }
        #uid;
        get uid() {
          return this.#uid;
        }
        #gid;
        get gid() {
          return this.#gid;
        }
        #rdev;
        get rdev() {
          return this.#rdev;
        }
        #blksize;
        get blksize() {
          return this.#blksize;
        }
        #ino;
        get ino() {
          return this.#ino;
        }
        #size;
        get size() {
          return this.#size;
        }
        #blocks;
        get blocks() {
          return this.#blocks;
        }
        #atimeMs;
        get atimeMs() {
          return this.#atimeMs;
        }
        #mtimeMs;
        get mtimeMs() {
          return this.#mtimeMs;
        }
        #ctimeMs;
        get ctimeMs() {
          return this.#ctimeMs;
        }
        #birthtimeMs;
        get birthtimeMs() {
          return this.#birthtimeMs;
        }
        #atime;
        get atime() {
          return this.#atime;
        }
        #mtime;
        get mtime() {
          return this.#mtime;
        }
        #ctime;
        get ctime() {
          return this.#ctime;
        }
        #birthtime;
        get birthtime() {
          return this.#birthtime;
        }
        #matchName;
        #depth;
        #fullpath;
        #fullpathPosix;
        #relative;
        #relativePosix;
        #type;
        #children;
        #linkTarget;
        #realpath;
        /**
         * This property is for compatibility with the Dirent class as of
         * Node v20, where Dirent['parentPath'] refers to the path of the
         * directory that was passed to readdir. For root entries, it's the path
         * to the entry itself.
         */
        get parentPath() {
          return (this.parent || this).fullpath();
        }
        /**
         * Deprecated alias for Dirent['parentPath'] Somewhat counterintuitively,
         * this property refers to the *parent* path, not the path object itself.
         */
        get path() {
          return this.parentPath;
        }
        /**
         * Do not create new Path objects directly.  They should always be accessed
         * via the PathScurry class or other methods on the Path class.
         *
         * @internal
         */
        constructor(name, type = UNKNOWN, root, roots, nocase, children, opts) {
          this.name = name;
          this.#matchName = nocase ? normalizeNocase(name) : normalize(name);
          this.#type = type & TYPEMASK;
          this.nocase = nocase;
          this.roots = roots;
          this.root = root || this;
          this.#children = children;
          this.#fullpath = opts.fullpath;
          this.#relative = opts.relative;
          this.#relativePosix = opts.relativePosix;
          this.parent = opts.parent;
          if (this.parent) {
            this.#fs = this.parent.#fs;
          } else {
            this.#fs = fsFromOption(opts.fs);
          }
        }
        /**
         * Returns the depth of the Path object from its root.
         *
         * For example, a path at `/foo/bar` would have a depth of 2.
         */
        depth() {
          if (this.#depth !== undefined) return this.#depth;
          if (!this.parent) return (this.#depth = 0);
          return (this.#depth = this.parent.depth() + 1);
        }
        /**
         * @internal
         */
        childrenCache() {
          return this.#children;
        }
        /**
         * Get the Path object referenced by the string path, resolved from this Path
         */
        resolve(path) {
          if (!path) {
            return this;
          }
          const rootPath = this.getRootString(path);
          const dir = path.substring(rootPath.length);
          const dirParts = dir.split(this.splitSep);
          const result = rootPath
            ? this.getRoot(rootPath).#resolveParts(dirParts)
            : this.#resolveParts(dirParts);
          return result;
        }
        #resolveParts(dirParts) {
          let p = this;
          for (const part of dirParts) {
            p = p.child(part);
          }
          return p;
        }
        /**
         * Returns the cached children Path objects, if still available.  If they
         * have fallen out of the cache, then returns an empty array, and resets the
         * READDIR_CALLED bit, so that future calls to readdir() will require an fs
         * lookup.
         *
         * @internal
         */
        children() {
          const cached = this.#children.get(this);
          if (cached) {
            return cached;
          }
          const children = Object.assign([], { provisional: 0 });
          this.#children.set(this, children);
          this.#type &= ~READDIR_CALLED;
          return children;
        }
        /**
         * Resolves a path portion and returns or creates the child Path.
         *
         * Returns `this` if pathPart is `''` or `'.'`, or `parent` if pathPart is
         * `'..'`.
         *
         * This should not be called directly.  If `pathPart` contains any path
         * separators, it will lead to unsafe undefined behavior.
         *
         * Use `Path.resolve()` instead.
         *
         * @internal
         */
        child(pathPart, opts) {
          if (pathPart === '' || pathPart === '.') {
            return this;
          }
          if (pathPart === '..') {
            return this.parent || this;
          }
          // find the child
          const children = this.children();
          const name = this.nocase
            ? normalizeNocase(pathPart)
            : normalize(pathPart);
          for (const p of children) {
            if (p.#matchName === name) {
              return p;
            }
          }
          // didn't find it, create provisional child, since it might not
          // actually exist.  If we know the parent isn't a dir, then
          // in fact it CAN'T exist.
          const s = this.parent ? this.sep : '';
          const fullpath = this.#fullpath
            ? this.#fullpath + s + pathPart
            : undefined;
          const pchild = this.newChild(pathPart, UNKNOWN, {
            ...opts,
            parent: this,
            fullpath,
          });
          if (!this.canReaddir()) {
            pchild.#type |= ENOENT;
          }
          // don't have to update provisional, because if we have real children,
          // then provisional is set to children.length, otherwise a lower number
          children.push(pchild);
          return pchild;
        }
        /**
         * The relative path from the cwd. If it does not share an ancestor with
         * the cwd, then this ends up being equivalent to the fullpath()
         */
        relative() {
          if (this.isCWD) return '';
          if (this.#relative !== undefined) {
            return this.#relative;
          }
          const name = this.name;
          const p = this.parent;
          if (!p) {
            return (this.#relative = this.name);
          }
          const pv = p.relative();
          return pv + (!pv || !p.parent ? '' : this.sep) + name;
        }
        /**
         * The relative path from the cwd, using / as the path separator.
         * If it does not share an ancestor with
         * the cwd, then this ends up being equivalent to the fullpathPosix()
         * On posix systems, this is identical to relative().
         */
        relativePosix() {
          if (this.sep === '/') return this.relative();
          if (this.isCWD) return '';
          if (this.#relativePosix !== undefined) return this.#relativePosix;
          const name = this.name;
          const p = this.parent;
          if (!p) {
            return (this.#relativePosix = this.fullpathPosix());
          }
          const pv = p.relativePosix();
          return pv + (!pv || !p.parent ? '' : '/') + name;
        }
        /**
         * The fully resolved path string for this Path entry
         */
        fullpath() {
          if (this.#fullpath !== undefined) {
            return this.#fullpath;
          }
          const name = this.name;
          const p = this.parent;
          if (!p) {
            return (this.#fullpath = this.name);
          }
          const pv = p.fullpath();
          const fp = pv + (!p.parent ? '' : this.sep) + name;
          return (this.#fullpath = fp);
        }
        /**
         * On platforms other than windows, this is identical to fullpath.
         *
         * On windows, this is overridden to return the forward-slash form of the
         * full UNC path.
         */
        fullpathPosix() {
          if (this.#fullpathPosix !== undefined) return this.#fullpathPosix;
          if (this.sep === '/') return (this.#fullpathPosix = this.fullpath());
          if (!this.parent) {
            const p = this.fullpath().replace(/\\/g, '/');
            if (/^[a-z]:\//i.test(p)) {
              return (this.#fullpathPosix = `//?/${p}`);
            } else {
              return (this.#fullpathPosix = p);
            }
          }
          const p = this.parent;
          const pfpp = p.fullpathPosix();
          const fpp = pfpp + (!pfpp || !p.parent ? '' : '/') + this.name;
          return (this.#fullpathPosix = fpp);
        }
        /**
         * Is the Path of an unknown type?
         *
         * Note that we might know *something* about it if there has been a previous
         * filesystem operation, for example that it does not exist, or is not a
         * link, or whether it has child entries.
         */
        isUnknown() {
          return (this.#type & IFMT) === UNKNOWN;
        }
        isType(type) {
          return this[`is${type}`]();
        }
        getType() {
          return this.isUnknown()
            ? 'Unknown'
            : this.isDirectory()
              ? 'Directory'
              : this.isFile()
                ? 'File'
                : this.isSymbolicLink()
                  ? 'SymbolicLink'
                  : this.isFIFO()
                    ? 'FIFO'
                    : this.isCharacterDevice()
                      ? 'CharacterDevice'
                      : this.isBlockDevice()
                        ? 'BlockDevice'
                        : /* c8 ignore start */ this.isSocket()
                          ? 'Socket'
                          : 'Unknown';
          /* c8 ignore stop */
        }
        /**
         * Is the Path a regular file?
         */
        isFile() {
          return (this.#type & IFMT) === IFREG;
        }
        /**
         * Is the Path a directory?
         */
        isDirectory() {
          return (this.#type & IFMT) === IFDIR;
        }
        /**
         * Is the path a character device?
         */
        isCharacterDevice() {
          return (this.#type & IFMT) === IFCHR;
        }
        /**
         * Is the path a block device?
         */
        isBlockDevice() {
          return (this.#type & IFMT) === IFBLK;
        }
        /**
         * Is the path a FIFO pipe?
         */
        isFIFO() {
          return (this.#type & IFMT) === IFIFO;
        }
        /**
         * Is the path a socket?
         */
        isSocket() {
          return (this.#type & IFMT) === IFSOCK;
        }
        /**
         * Is the path a symbolic link?
         */
        isSymbolicLink() {
          return (this.#type & IFLNK) === IFLNK;
        }
        /**
         * Return the entry if it has been subject of a successful lstat, or
         * undefined otherwise.
         *
         * Does not read the filesystem, so an undefined result *could* simply
         * mean that we haven't called lstat on it.
         */
        lstatCached() {
          return this.#type & LSTAT_CALLED ? this : undefined;
        }
        /**
         * Return the cached link target if the entry has been the subject of a
         * successful readlink, or undefined otherwise.
         *
         * Does not read the filesystem, so an undefined result *could* just mean we
         * don't have any cached data. Only use it if you are very sure that a
         * readlink() has been called at some point.
         */
        readlinkCached() {
          return this.#linkTarget;
        }
        /**
         * Returns the cached realpath target if the entry has been the subject
         * of a successful realpath, or undefined otherwise.
         *
         * Does not read the filesystem, so an undefined result *could* just mean we
         * don't have any cached data. Only use it if you are very sure that a
         * realpath() has been called at some point.
         */
        realpathCached() {
          return this.#realpath;
        }
        /**
         * Returns the cached child Path entries array if the entry has been the
         * subject of a successful readdir(), or [] otherwise.
         *
         * Does not read the filesystem, so an empty array *could* just mean we
         * don't have any cached data. Only use it if you are very sure that a
         * readdir() has been called recently enough to still be valid.
         */
        readdirCached() {
          const children = this.children();
          return children.slice(0, children.provisional);
        }
        /**
         * Return true if it's worth trying to readlink.  Ie, we don't (yet) have
         * any indication that readlink will definitely fail.
         *
         * Returns false if the path is known to not be a symlink, if a previous
         * readlink failed, or if the entry does not exist.
         */
        canReadlink() {
          if (this.#linkTarget) return true;
          if (!this.parent) return false;
          // cases where it cannot possibly succeed
          const ifmt = this.#type & IFMT;
          return !(
            (ifmt !== UNKNOWN && ifmt !== IFLNK) ||
            this.#type & ENOREADLINK ||
            this.#type & ENOENT
          );
        }
        /**
         * Return true if readdir has previously been successfully called on this
         * path, indicating that cachedReaddir() is likely valid.
         */
        calledReaddir() {
          return !!(this.#type & READDIR_CALLED);
        }
        /**
         * Returns true if the path is known to not exist. That is, a previous lstat
         * or readdir failed to verify its existence when that would have been
         * expected, or a parent entry was marked either enoent or enotdir.
         */
        isENOENT() {
          return !!(this.#type & ENOENT);
        }
        /**
         * Return true if the path is a match for the given path name.  This handles
         * case sensitivity and unicode normalization.
         *
         * Note: even on case-sensitive systems, it is **not** safe to test the
         * equality of the `.name` property to determine whether a given pathname
         * matches, due to unicode normalization mismatches.
         *
         * Always use this method instead of testing the `path.name` property
         * directly.
         */
        isNamed(n) {
          return !this.nocase
            ? this.#matchName === normalize(n)
            : this.#matchName === normalizeNocase(n);
        }
        /**
         * Return the Path object corresponding to the target of a symbolic link.
         *
         * If the Path is not a symbolic link, or if the readlink call fails for any
         * reason, `undefined` is returned.
         *
         * Result is cached, and thus may be outdated if the filesystem is mutated.
         */
        async readlink() {
          const target = this.#linkTarget;
          if (target) {
            return target;
          }
          if (!this.canReadlink()) {
            return undefined;
          }
          /* c8 ignore start */
          // already covered by the canReadlink test, here for ts grumples
          if (!this.parent) {
            return undefined;
          }
          /* c8 ignore stop */
          try {
            const read = await this.#fs.promises.readlink(this.fullpath());
            const linkTarget = (await this.parent.realpath())?.resolve(read);
            if (linkTarget) {
              return (this.#linkTarget = linkTarget);
            }
          } catch (er) {
            this.#readlinkFail(er.code);
            return undefined;
          }
        }
        /**
         * Synchronous {@link PathBase.readlink}
         */
        readlinkSync() {
          const target = this.#linkTarget;
          if (target) {
            return target;
          }
          if (!this.canReadlink()) {
            return undefined;
          }
          /* c8 ignore start */
          // already covered by the canReadlink test, here for ts grumples
          if (!this.parent) {
            return undefined;
          }
          /* c8 ignore stop */
          try {
            const read = this.#fs.readlinkSync(this.fullpath());
            const linkTarget = this.parent.realpathSync()?.resolve(read);
            if (linkTarget) {
              return (this.#linkTarget = linkTarget);
            }
          } catch (er) {
            this.#readlinkFail(er.code);
            return undefined;
          }
        }
        #readdirSuccess(children) {
          // succeeded, mark readdir called bit
          this.#type |= READDIR_CALLED;
          // mark all remaining provisional children as ENOENT
          for (let p = children.provisional; p < children.length; p++) {
            const c = children[p];
            if (c) c.#markENOENT();
          }
        }
        #markENOENT() {
          // mark as UNKNOWN and ENOENT
          if (this.#type & ENOENT) return;
          this.#type = (this.#type | ENOENT) & IFMT_UNKNOWN;
          this.#markChildrenENOENT();
        }
        #markChildrenENOENT() {
          // all children are provisional and do not exist
          const children = this.children();
          children.provisional = 0;
          for (const p of children) {
            p.#markENOENT();
          }
        }
        #markENOREALPATH() {
          this.#type |= ENOREALPATH;
          this.#markENOTDIR();
        }
        // save the information when we know the entry is not a dir
        #markENOTDIR() {
          // entry is not a directory, so any children can't exist.
          // this *should* be impossible, since any children created
          // after it's been marked ENOTDIR should be marked ENOENT,
          // so it won't even get to this point.
          /* c8 ignore start */
          if (this.#type & ENOTDIR) return;
          /* c8 ignore stop */
          let t = this.#type;
          // this could happen if we stat a dir, then delete it,
          // then try to read it or one of its children.
          if ((t & IFMT) === IFDIR) t &= IFMT_UNKNOWN;
          this.#type = t | ENOTDIR;
          this.#markChildrenENOENT();
        }
        #readdirFail(code = '') {
          // markENOTDIR and markENOENT also set provisional=0
          if (code === 'ENOTDIR' || code === 'EPERM') {
            this.#markENOTDIR();
          } else if (code === 'ENOENT') {
            this.#markENOENT();
          } else {
            this.children().provisional = 0;
          }
        }
        #lstatFail(code = '') {
          // Windows just raises ENOENT in this case, disable for win CI
          /* c8 ignore start */
          if (code === 'ENOTDIR') {
            // already know it has a parent by this point
            const p = this.parent;
            p.#markENOTDIR();
          } else if (code === 'ENOENT') {
            /* c8 ignore stop */
            this.#markENOENT();
          }
        }
        #readlinkFail(code = '') {
          let ter = this.#type;
          ter |= ENOREADLINK;
          if (code === 'ENOENT') ter |= ENOENT;
          // windows gets a weird error when you try to readlink a file
          if (code === 'EINVAL' || code === 'UNKNOWN') {
            // exists, but not a symlink, we don't know WHAT it is, so remove
            // all IFMT bits.
            ter &= IFMT_UNKNOWN;
          }
          this.#type = ter;
          // windows just gets ENOENT in this case.  We do cover the case,
          // just disabled because it's impossible on Windows CI
          /* c8 ignore start */
          if (code === 'ENOTDIR' && this.parent) {
            this.parent.#markENOTDIR();
          }
          /* c8 ignore stop */
        }
        #readdirAddChild(e, c) {
          return (
            this.#readdirMaybePromoteChild(e, c) ||
            this.#readdirAddNewChild(e, c)
          );
        }
        #readdirAddNewChild(e, c) {
          // alloc new entry at head, so it's never provisional
          const type = entToType(e);
          const child = this.newChild(e.name, type, { parent: this });
          const ifmt = child.#type & IFMT;
          if (ifmt !== IFDIR && ifmt !== IFLNK && ifmt !== UNKNOWN) {
            child.#type |= ENOTDIR;
          }
          c.unshift(child);
          c.provisional++;
          return child;
        }
        #readdirMaybePromoteChild(e, c) {
          for (let p = c.provisional; p < c.length; p++) {
            const pchild = c[p];
            const name = this.nocase
              ? normalizeNocase(e.name)
              : normalize(e.name);
            if (name !== pchild.#matchName) {
              continue;
            }
            return this.#readdirPromoteChild(e, pchild, p, c);
          }
        }
        #readdirPromoteChild(e, p, index, c) {
          const v = p.name;
          // retain any other flags, but set ifmt from dirent
          p.#type = (p.#type & IFMT_UNKNOWN) | entToType(e);
          // case sensitivity fixing when we learn the true name.
          if (v !== e.name) p.name = e.name;
          // just advance provisional index (potentially off the list),
          // otherwise we have to splice/pop it out and re-insert at head
          if (index !== c.provisional) {
            if (index === c.length - 1) c.pop();
            else c.splice(index, 1);
            c.unshift(p);
          }
          c.provisional++;
          return p;
        }
        /**
         * Call lstat() on this Path, and update all known information that can be
         * determined.
         *
         * Note that unlike `fs.lstat()`, the returned value does not contain some
         * information, such as `mode`, `dev`, `nlink`, and `ino`.  If that
         * information is required, you will need to call `fs.lstat` yourself.
         *
         * If the Path refers to a nonexistent file, or if the lstat call fails for
         * any reason, `undefined` is returned.  Otherwise the updated Path object is
         * returned.
         *
         * Results are cached, and thus may be out of date if the filesystem is
         * mutated.
         */
        async lstat() {
          if ((this.#type & ENOENT) === 0) {
            try {
              this.#applyStat(await this.#fs.promises.lstat(this.fullpath()));
              return this;
            } catch (er) {
              this.#lstatFail(er.code);
            }
          }
        }
        /**
         * synchronous {@link PathBase.lstat}
         */
        lstatSync() {
          if ((this.#type & ENOENT) === 0) {
            try {
              this.#applyStat(this.#fs.lstatSync(this.fullpath()));
              return this;
            } catch (er) {
              this.#lstatFail(er.code);
            }
          }
        }
        #applyStat(st) {
          const {
            atime,
            atimeMs,
            birthtime,
            birthtimeMs,
            blksize,
            blocks,
            ctime,
            ctimeMs,
            dev,
            gid,
            ino,
            mode,
            mtime,
            mtimeMs,
            nlink,
            rdev,
            size,
            uid,
          } = st;
          this.#atime = atime;
          this.#atimeMs = atimeMs;
          this.#birthtime = birthtime;
          this.#birthtimeMs = birthtimeMs;
          this.#blksize = blksize;
          this.#blocks = blocks;
          this.#ctime = ctime;
          this.#ctimeMs = ctimeMs;
          this.#dev = dev;
          this.#gid = gid;
          this.#ino = ino;
          this.#mode = mode;
          this.#mtime = mtime;
          this.#mtimeMs = mtimeMs;
          this.#nlink = nlink;
          this.#rdev = rdev;
          this.#size = size;
          this.#uid = uid;
          const ifmt = entToType(st);
          // retain any other flags, but set the ifmt
          this.#type = (this.#type & IFMT_UNKNOWN) | ifmt | LSTAT_CALLED;
          if (ifmt !== UNKNOWN && ifmt !== IFDIR && ifmt !== IFLNK) {
            this.#type |= ENOTDIR;
          }
        }
        #onReaddirCB = [];
        #readdirCBInFlight = false;
        #callOnReaddirCB(children) {
          this.#readdirCBInFlight = false;
          const cbs = this.#onReaddirCB.slice();
          this.#onReaddirCB.length = 0;
          cbs.forEach((cb) => cb(null, children));
        }
        /**
         * Standard node-style callback interface to get list of directory entries.
         *
         * If the Path cannot or does not contain any children, then an empty array
         * is returned.
         *
         * Results are cached, and thus may be out of date if the filesystem is
         * mutated.
         *
         * @param cb The callback called with (er, entries).  Note that the `er`
         * param is somewhat extraneous, as all readdir() errors are handled and
         * simply result in an empty set of entries being returned.
         * @param allowZalgo Boolean indicating that immediately known results should
         * *not* be deferred with `queueMicrotask`. Defaults to `false`. Release
         * zalgo at your peril, the dark pony lord is devious and unforgiving.
         */
        readdirCB(cb, allowZalgo = false) {
          if (!this.canReaddir()) {
            if (allowZalgo) cb(null, []);
            else queueMicrotask(() => cb(null, []));
            return;
          }
          const children = this.children();
          if (this.calledReaddir()) {
            const c = children.slice(0, children.provisional);
            if (allowZalgo) cb(null, c);
            else queueMicrotask(() => cb(null, c));
            return;
          }
          // don't have to worry about zalgo at this point.
          this.#onReaddirCB.push(cb);
          if (this.#readdirCBInFlight) {
            return;
          }
          this.#readdirCBInFlight = true;
          // else read the directory, fill up children
          // de-provisionalize any provisional children.
          const fullpath = this.fullpath();
          this.#fs.readdir(fullpath, { withFileTypes: true }, (er, entries) => {
            if (er) {
              this.#readdirFail(er.code);
              children.provisional = 0;
            } else {
              // if we didn't get an error, we always get entries.
              //@ts-ignore
              for (const e of entries) {
                this.#readdirAddChild(e, children);
              }
              this.#readdirSuccess(children);
            }
            this.#callOnReaddirCB(children.slice(0, children.provisional));
            return;
          });
        }
        #asyncReaddirInFlight;
        /**
         * Return an array of known child entries.
         *
         * If the Path cannot or does not contain any children, then an empty array
         * is returned.
         *
         * Results are cached, and thus may be out of date if the filesystem is
         * mutated.
         */
        async readdir() {
          if (!this.canReaddir()) {
            return [];
          }
          const children = this.children();
          if (this.calledReaddir()) {
            return children.slice(0, children.provisional);
          }
          // else read the directory, fill up children
          // de-provisionalize any provisional children.
          const fullpath = this.fullpath();
          if (this.#asyncReaddirInFlight) {
            await this.#asyncReaddirInFlight;
          } else {
            /* c8 ignore start */
            let resolve = () => {};
            /* c8 ignore stop */
            this.#asyncReaddirInFlight = new Promise((res) => (resolve = res));
            try {
              for (const e of await this.#fs.promises.readdir(fullpath, {
                withFileTypes: true,
              })) {
                this.#readdirAddChild(e, children);
              }
              this.#readdirSuccess(children);
            } catch (er) {
              this.#readdirFail(er.code);
              children.provisional = 0;
            }
            this.#asyncReaddirInFlight = undefined;
            resolve();
          }
          return children.slice(0, children.provisional);
        }
        /**
         * synchronous {@link PathBase.readdir}
         */
        readdirSync() {
          if (!this.canReaddir()) {
            return [];
          }
          const children = this.children();
          if (this.calledReaddir()) {
            return children.slice(0, children.provisional);
          }
          // else read the directory, fill up children
          // de-provisionalize any provisional children.
          const fullpath = this.fullpath();
          try {
            for (const e of this.#fs.readdirSync(fullpath, {
              withFileTypes: true,
            })) {
              this.#readdirAddChild(e, children);
            }
            this.#readdirSuccess(children);
          } catch (er) {
            this.#readdirFail(er.code);
            children.provisional = 0;
          }
          return children.slice(0, children.provisional);
        }
        canReaddir() {
          if (this.#type & ENOCHILD) return false;
          const ifmt = IFMT & this.#type;
          // we always set ENOTDIR when setting IFMT, so should be impossible
          /* c8 ignore start */
          if (!(ifmt === UNKNOWN || ifmt === IFDIR || ifmt === IFLNK)) {
            return false;
          }
          /* c8 ignore stop */
          return true;
        }
        shouldWalk(dirs, walkFilter) {
          return (
            (this.#type & IFDIR) === IFDIR &&
            !(this.#type & ENOCHILD) &&
            !dirs.has(this) &&
            (!walkFilter || walkFilter(this))
          );
        }
        /**
         * Return the Path object corresponding to path as resolved
         * by realpath(3).
         *
         * If the realpath call fails for any reason, `undefined` is returned.
         *
         * Result is cached, and thus may be outdated if the filesystem is mutated.
         * On success, returns a Path object.
         */
        async realpath() {
          if (this.#realpath) return this.#realpath;
          if ((ENOREALPATH | ENOREADLINK | ENOENT) & this.#type)
            return undefined;
          try {
            const rp = await this.#fs.promises.realpath(this.fullpath());
            return (this.#realpath = this.resolve(rp));
          } catch (_) {
            this.#markENOREALPATH();
          }
        }
        /**
         * Synchronous {@link realpath}
         */
        realpathSync() {
          if (this.#realpath) return this.#realpath;
          if ((ENOREALPATH | ENOREADLINK | ENOENT) & this.#type)
            return undefined;
          try {
            const rp = this.#fs.realpathSync(this.fullpath());
            return (this.#realpath = this.resolve(rp));
          } catch (_) {
            this.#markENOREALPATH();
          }
        }
        /**
         * Internal method to mark this Path object as the scurry cwd,
         * called by {@link PathScurry#chdir}
         *
         * @internal
         */
        [setAsCwd](oldCwd) {
          if (oldCwd === this) return;
          oldCwd.isCWD = false;
          this.isCWD = true;
          const changed = new Set([]);
          let rp = [];
          let p = this;
          while (p && p.parent) {
            changed.add(p);
            p.#relative = rp.join(this.sep);
            p.#relativePosix = rp.join('/');
            p = p.parent;
            rp.push('..');
          }
          // now un-memoize parents of old cwd
          p = oldCwd;
          while (p && p.parent && !changed.has(p)) {
            p.#relative = undefined;
            p.#relativePosix = undefined;
            p = p.parent;
          }
        }
      }
      exports.PathBase = PathBase;
      /**
       * Path class used on win32 systems
       *
       * Uses `'\\'` as the path separator for returned paths, either `'\\'` or `'/'`
       * as the path separator for parsing paths.
       */
      class PathWin32 extends PathBase {
        /**
         * Separator for generating path strings.
         */
        sep = '\\';
        /**
         * Separator for parsing path strings.
         */
        splitSep = eitherSep;
        /**
         * Do not create new Path objects directly.  They should always be accessed
         * via the PathScurry class or other methods on the Path class.
         *
         * @internal
         */
        constructor(name, type = UNKNOWN, root, roots, nocase, children, opts) {
          super(name, type, root, roots, nocase, children, opts);
        }
        /**
         * @internal
         */
        newChild(name, type = UNKNOWN, opts = {}) {
          return new PathWin32(
            name,
            type,
            this.root,
            this.roots,
            this.nocase,
            this.childrenCache(),
            opts,
          );
        }
        /**
         * @internal
         */
        getRootString(path) {
          return node_path_1.win32.parse(path).root;
        }
        /**
         * @internal
         */
        getRoot(rootPath) {
          rootPath = uncToDrive(rootPath.toUpperCase());
          if (rootPath === this.root.name) {
            return this.root;
          }
          // ok, not that one, check if it matches another we know about
          for (const [compare, root] of Object.entries(this.roots)) {
            if (this.sameRoot(rootPath, compare)) {
              return (this.roots[rootPath] = root);
            }
          }
          // otherwise, have to create a new one.
          return (this.roots[rootPath] = new PathScurryWin32(
            rootPath,
            this,
          ).root);
        }
        /**
         * @internal
         */
        sameRoot(rootPath, compare = this.root.name) {
          // windows can (rarely) have case-sensitive filesystem, but
          // UNC and drive letters are always case-insensitive, and canonically
          // represented uppercase.
          rootPath = rootPath
            .toUpperCase()
            .replace(/\//g, '\\')
            .replace(uncDriveRegexp, '$1\\');
          return rootPath === compare;
        }
      }
      exports.PathWin32 = PathWin32;
      /**
       * Path class used on all posix systems.
       *
       * Uses `'/'` as the path separator.
       */
      class PathPosix extends PathBase {
        /**
         * separator for parsing path strings
         */
        splitSep = '/';
        /**
         * separator for generating path strings
         */
        sep = '/';
        /**
         * Do not create new Path objects directly.  They should always be accessed
         * via the PathScurry class or other methods on the Path class.
         *
         * @internal
         */
        constructor(name, type = UNKNOWN, root, roots, nocase, children, opts) {
          super(name, type, root, roots, nocase, children, opts);
        }
        /**
         * @internal
         */
        getRootString(path) {
          return path.startsWith('/') ? '/' : '';
        }
        /**
         * @internal
         */
        getRoot(_rootPath) {
          return this.root;
        }
        /**
         * @internal
         */
        newChild(name, type = UNKNOWN, opts = {}) {
          return new PathPosix(
            name,
            type,
            this.root,
            this.roots,
            this.nocase,
            this.childrenCache(),
            opts,
          );
        }
      }
      exports.PathPosix = PathPosix;
      /**
       * The base class for all PathScurry classes, providing the interface for path
       * resolution and filesystem operations.
       *
       * Typically, you should *not* instantiate this class directly, but rather one
       * of the platform-specific classes, or the exported {@link PathScurry} which
       * defaults to the current platform.
       */
      class PathScurryBase {
        /**
         * The root Path entry for the current working directory of this Scurry
         */
        root;
        /**
         * The string path for the root of this Scurry's current working directory
         */
        rootPath;
        /**
         * A collection of all roots encountered, referenced by rootPath
         */
        roots;
        /**
         * The Path entry corresponding to this PathScurry's current working directory.
         */
        cwd;
        #resolveCache;
        #resolvePosixCache;
        #children;
        /**
         * Perform path comparisons case-insensitively.
         *
         * Defaults true on Darwin and Windows systems, false elsewhere.
         */
        nocase;
        #fs;
        /**
         * This class should not be instantiated directly.
         *
         * Use PathScurryWin32, PathScurryDarwin, PathScurryPosix, or PathScurry
         *
         * @internal
         */
        constructor(
          cwd = process.cwd(),
          pathImpl,
          sep,
          { nocase, childrenCacheSize = 16 * 1024, fs = defaultFS } = {},
        ) {
          this.#fs = fsFromOption(fs);
          if (cwd instanceof URL || cwd.startsWith('file://')) {
            cwd = (0, node_url_1.fileURLToPath)(cwd);
          }
          // resolve and split root, and then add to the store.
          // this is the only time we call path.resolve()
          const cwdPath = pathImpl.resolve(cwd);
          this.roots = Object.create(null);
          this.rootPath = this.parseRootPath(cwdPath);
          this.#resolveCache = new ResolveCache();
          this.#resolvePosixCache = new ResolveCache();
          this.#children = new ChildrenCache(childrenCacheSize);
          const split = cwdPath.substring(this.rootPath.length).split(sep);
          // resolve('/') leaves '', splits to [''], we don't want that.
          if (split.length === 1 && !split[0]) {
            split.pop();
          }
          /* c8 ignore start */
          if (nocase === undefined) {
            throw new TypeError(
              'must provide nocase setting to PathScurryBase ctor',
            );
          }
          /* c8 ignore stop */
          this.nocase = nocase;
          this.root = this.newRoot(this.#fs);
          this.roots[this.rootPath] = this.root;
          let prev = this.root;
          let len = split.length - 1;
          const joinSep = pathImpl.sep;
          let abs = this.rootPath;
          let sawFirst = false;
          for (const part of split) {
            const l = len--;
            prev = prev.child(part, {
              relative: new Array(l).fill('..').join(joinSep),
              relativePosix: new Array(l).fill('..').join('/'),
              fullpath: (abs += (sawFirst ? '' : joinSep) + part),
            });
            sawFirst = true;
          }
          this.cwd = prev;
        }
        /**
         * Get the depth of a provided path, string, or the cwd
         */
        depth(path = this.cwd) {
          if (typeof path === 'string') {
            path = this.cwd.resolve(path);
          }
          return path.depth();
        }
        /**
         * Return the cache of child entries.  Exposed so subclasses can create
         * child Path objects in a platform-specific way.
         *
         * @internal
         */
        childrenCache() {
          return this.#children;
        }
        /**
         * Resolve one or more path strings to a resolved string
         *
         * Same interface as require('path').resolve.
         *
         * Much faster than path.resolve() when called multiple times for the same
         * path, because the resolved Path objects are cached.  Much slower
         * otherwise.
         */
        resolve(...paths) {
          // first figure out the minimum number of paths we have to test
          // we always start at cwd, but any absolutes will bump the start
          let r = '';
          for (let i = paths.length - 1; i >= 0; i--) {
            const p = paths[i];
            if (!p || p === '.') continue;
            r = r ? `${p}/${r}` : p;
            if (this.isAbsolute(p)) {
              break;
            }
          }
          const cached = this.#resolveCache.get(r);
          if (cached !== undefined) {
            return cached;
          }
          const result = this.cwd.resolve(r).fullpath();
          this.#resolveCache.set(r, result);
          return result;
        }
        /**
         * Resolve one or more path strings to a resolved string, returning
         * the posix path.  Identical to .resolve() on posix systems, but on
         * windows will return a forward-slash separated UNC path.
         *
         * Same interface as require('path').resolve.
         *
         * Much faster than path.resolve() when called multiple times for the same
         * path, because the resolved Path objects are cached.  Much slower
         * otherwise.
         */
        resolvePosix(...paths) {
          // first figure out the minimum number of paths we have to test
          // we always start at cwd, but any absolutes will bump the start
          let r = '';
          for (let i = paths.length - 1; i >= 0; i--) {
            const p = paths[i];
            if (!p || p === '.') continue;
            r = r ? `${p}/${r}` : p;
            if (this.isAbsolute(p)) {
              break;
            }
          }
          const cached = this.#resolvePosixCache.get(r);
          if (cached !== undefined) {
            return cached;
          }
          const result = this.cwd.resolve(r).fullpathPosix();
          this.#resolvePosixCache.set(r, result);
          return result;
        }
        /**
         * find the relative path from the cwd to the supplied path string or entry
         */
        relative(entry = this.cwd) {
          if (typeof entry === 'string') {
            entry = this.cwd.resolve(entry);
          }
          return entry.relative();
        }
        /**
         * find the relative path from the cwd to the supplied path string or
         * entry, using / as the path delimiter, even on Windows.
         */
        relativePosix(entry = this.cwd) {
          if (typeof entry === 'string') {
            entry = this.cwd.resolve(entry);
          }
          return entry.relativePosix();
        }
        /**
         * Return the basename for the provided string or Path object
         */
        basename(entry = this.cwd) {
          if (typeof entry === 'string') {
            entry = this.cwd.resolve(entry);
          }
          return entry.name;
        }
        /**
         * Return the dirname for the provided string or Path object
         */
        dirname(entry = this.cwd) {
          if (typeof entry === 'string') {
            entry = this.cwd.resolve(entry);
          }
          return (entry.parent || entry).fullpath();
        }
        async readdir(
          entry = this.cwd,
          opts = {
            withFileTypes: true,
          },
        ) {
          if (typeof entry === 'string') {
            entry = this.cwd.resolve(entry);
          } else if (!(entry instanceof PathBase)) {
            opts = entry;
            entry = this.cwd;
          }
          const { withFileTypes } = opts;
          if (!entry.canReaddir()) {
            return [];
          } else {
            const p = await entry.readdir();
            return withFileTypes ? p : p.map((e) => e.name);
          }
        }
        readdirSync(
          entry = this.cwd,
          opts = {
            withFileTypes: true,
          },
        ) {
          if (typeof entry === 'string') {
            entry = this.cwd.resolve(entry);
          } else if (!(entry instanceof PathBase)) {
            opts = entry;
            entry = this.cwd;
          }
          const { withFileTypes = true } = opts;
          if (!entry.canReaddir()) {
            return [];
          } else if (withFileTypes) {
            return entry.readdirSync();
          } else {
            return entry.readdirSync().map((e) => e.name);
          }
        }
        /**
         * Call lstat() on the string or Path object, and update all known
         * information that can be determined.
         *
         * Note that unlike `fs.lstat()`, the returned value does not contain some
         * information, such as `mode`, `dev`, `nlink`, and `ino`.  If that
         * information is required, you will need to call `fs.lstat` yourself.
         *
         * If the Path refers to a nonexistent file, or if the lstat call fails for
         * any reason, `undefined` is returned.  Otherwise the updated Path object is
         * returned.
         *
         * Results are cached, and thus may be out of date if the filesystem is
         * mutated.
         */
        async lstat(entry = this.cwd) {
          if (typeof entry === 'string') {
            entry = this.cwd.resolve(entry);
          }
          return entry.lstat();
        }
        /**
         * synchronous {@link PathScurryBase.lstat}
         */
        lstatSync(entry = this.cwd) {
          if (typeof entry === 'string') {
            entry = this.cwd.resolve(entry);
          }
          return entry.lstatSync();
        }
        async readlink(
          entry = this.cwd,
          { withFileTypes } = {
            withFileTypes: false,
          },
        ) {
          if (typeof entry === 'string') {
            entry = this.cwd.resolve(entry);
          } else if (!(entry instanceof PathBase)) {
            withFileTypes = entry.withFileTypes;
            entry = this.cwd;
          }
          const e = await entry.readlink();
          return withFileTypes ? e : e?.fullpath();
        }
        readlinkSync(
          entry = this.cwd,
          { withFileTypes } = {
            withFileTypes: false,
          },
        ) {
          if (typeof entry === 'string') {
            entry = this.cwd.resolve(entry);
          } else if (!(entry instanceof PathBase)) {
            withFileTypes = entry.withFileTypes;
            entry = this.cwd;
          }
          const e = entry.readlinkSync();
          return withFileTypes ? e : e?.fullpath();
        }
        async realpath(
          entry = this.cwd,
          { withFileTypes } = {
            withFileTypes: false,
          },
        ) {
          if (typeof entry === 'string') {
            entry = this.cwd.resolve(entry);
          } else if (!(entry instanceof PathBase)) {
            withFileTypes = entry.withFileTypes;
            entry = this.cwd;
          }
          const e = await entry.realpath();
          return withFileTypes ? e : e?.fullpath();
        }
        realpathSync(
          entry = this.cwd,
          { withFileTypes } = {
            withFileTypes: false,
          },
        ) {
          if (typeof entry === 'string') {
            entry = this.cwd.resolve(entry);
          } else if (!(entry instanceof PathBase)) {
            withFileTypes = entry.withFileTypes;
            entry = this.cwd;
          }
          const e = entry.realpathSync();
          return withFileTypes ? e : e?.fullpath();
        }
        async walk(entry = this.cwd, opts = {}) {
          if (typeof entry === 'string') {
            entry = this.cwd.resolve(entry);
          } else if (!(entry instanceof PathBase)) {
            opts = entry;
            entry = this.cwd;
          }
          const {
            withFileTypes = true,
            follow = false,
            filter,
            walkFilter,
          } = opts;
          const results = [];
          if (!filter || filter(entry)) {
            results.push(withFileTypes ? entry : entry.fullpath());
          }
          const dirs = new Set();
          const walk = (dir, cb) => {
            dirs.add(dir);
            dir.readdirCB((er, entries) => {
              /* c8 ignore start */
              if (er) {
                return cb(er);
              }
              /* c8 ignore stop */
              let len = entries.length;
              if (!len) return cb();
              const next = () => {
                if (--len === 0) {
                  cb();
                }
              };
              for (const e of entries) {
                if (!filter || filter(e)) {
                  results.push(withFileTypes ? e : e.fullpath());
                }
                if (follow && e.isSymbolicLink()) {
                  e.realpath()
                    .then((r) => (r?.isUnknown() ? r.lstat() : r))
                    .then((r) =>
                      r?.shouldWalk(dirs, walkFilter) ? walk(r, next) : next(),
                    );
                } else {
                  if (e.shouldWalk(dirs, walkFilter)) {
                    walk(e, next);
                  } else {
                    next();
                  }
                }
              }
            }, true); // zalgooooooo
          };
          const start = entry;
          return new Promise((res, rej) => {
            walk(start, (er) => {
              /* c8 ignore start */
              if (er) return rej(er);
              /* c8 ignore stop */
              res(results);
            });
          });
        }
        walkSync(entry = this.cwd, opts = {}) {
          if (typeof entry === 'string') {
            entry = this.cwd.resolve(entry);
          } else if (!(entry instanceof PathBase)) {
            opts = entry;
            entry = this.cwd;
          }
          const {
            withFileTypes = true,
            follow = false,
            filter,
            walkFilter,
          } = opts;
          const results = [];
          if (!filter || filter(entry)) {
            results.push(withFileTypes ? entry : entry.fullpath());
          }
          const dirs = new Set([entry]);
          for (const dir of dirs) {
            const entries = dir.readdirSync();
            for (const e of entries) {
              if (!filter || filter(e)) {
                results.push(withFileTypes ? e : e.fullpath());
              }
              let r = e;
              if (e.isSymbolicLink()) {
                if (!(follow && (r = e.realpathSync()))) continue;
                if (r.isUnknown()) r.lstatSync();
              }
              if (r.shouldWalk(dirs, walkFilter)) {
                dirs.add(r);
              }
            }
          }
          return results;
        }
        /**
         * Support for `for await`
         *
         * Alias for {@link PathScurryBase.iterate}
         *
         * Note: As of Node 19, this is very slow, compared to other methods of
         * walking.  Consider using {@link PathScurryBase.stream} if memory overhead
         * and backpressure are concerns, or {@link PathScurryBase.walk} if not.
         */
        [Symbol.asyncIterator]() {
          return this.iterate();
        }
        iterate(entry = this.cwd, options = {}) {
          // iterating async over the stream is significantly more performant,
          // especially in the warm-cache scenario, because it buffers up directory
          // entries in the background instead of waiting for a yield for each one.
          if (typeof entry === 'string') {
            entry = this.cwd.resolve(entry);
          } else if (!(entry instanceof PathBase)) {
            options = entry;
            entry = this.cwd;
          }
          return this.stream(entry, options)[Symbol.asyncIterator]();
        }
        /**
         * Iterating over a PathScurry performs a synchronous walk.
         *
         * Alias for {@link PathScurryBase.iterateSync}
         */
        [Symbol.iterator]() {
          return this.iterateSync();
        }
        *iterateSync(entry = this.cwd, opts = {}) {
          if (typeof entry === 'string') {
            entry = this.cwd.resolve(entry);
          } else if (!(entry instanceof PathBase)) {
            opts = entry;
            entry = this.cwd;
          }
          const {
            withFileTypes = true,
            follow = false,
            filter,
            walkFilter,
          } = opts;
          if (!filter || filter(entry)) {
            yield withFileTypes ? entry : entry.fullpath();
          }
          const dirs = new Set([entry]);
          for (const dir of dirs) {
            const entries = dir.readdirSync();
            for (const e of entries) {
              if (!filter || filter(e)) {
                yield withFileTypes ? e : e.fullpath();
              }
              let r = e;
              if (e.isSymbolicLink()) {
                if (!(follow && (r = e.realpathSync()))) continue;
                if (r.isUnknown()) r.lstatSync();
              }
              if (r.shouldWalk(dirs, walkFilter)) {
                dirs.add(r);
              }
            }
          }
        }
        stream(entry = this.cwd, opts = {}) {
          if (typeof entry === 'string') {
            entry = this.cwd.resolve(entry);
          } else if (!(entry instanceof PathBase)) {
            opts = entry;
            entry = this.cwd;
          }
          const {
            withFileTypes = true,
            follow = false,
            filter,
            walkFilter,
          } = opts;
          const results = new minipass_1.Minipass({ objectMode: true });
          if (!filter || filter(entry)) {
            results.write(withFileTypes ? entry : entry.fullpath());
          }
          const dirs = new Set();
          const queue = [entry];
          let processing = 0;
          const process = () => {
            let paused = false;
            while (!paused) {
              const dir = queue.shift();
              if (!dir) {
                if (processing === 0) results.end();
                return;
              }
              processing++;
              dirs.add(dir);
              const onReaddir = (er, entries, didRealpaths = false) => {
                /* c8 ignore start */
                if (er) return results.emit('error', er);
                /* c8 ignore stop */
                if (follow && !didRealpaths) {
                  const promises = [];
                  for (const e of entries) {
                    if (e.isSymbolicLink()) {
                      promises.push(
                        e
                          .realpath()
                          .then((r) => (r?.isUnknown() ? r.lstat() : r)),
                      );
                    }
                  }
                  if (promises.length) {
                    Promise.all(promises).then(() =>
                      onReaddir(null, entries, true),
                    );
                    return;
                  }
                }
                for (const e of entries) {
                  if (e && (!filter || filter(e))) {
                    if (!results.write(withFileTypes ? e : e.fullpath())) {
                      paused = true;
                    }
                  }
                }
                processing--;
                for (const e of entries) {
                  const r = e.realpathCached() || e;
                  if (r.shouldWalk(dirs, walkFilter)) {
                    queue.push(r);
                  }
                }
                if (paused && !results.flowing) {
                  results.once('drain', process);
                } else if (!sync) {
                  process();
                }
              };
              // zalgo containment
              let sync = true;
              dir.readdirCB(onReaddir, true);
              sync = false;
            }
          };
          process();
          return results;
        }
        streamSync(entry = this.cwd, opts = {}) {
          if (typeof entry === 'string') {
            entry = this.cwd.resolve(entry);
          } else if (!(entry instanceof PathBase)) {
            opts = entry;
            entry = this.cwd;
          }
          const {
            withFileTypes = true,
            follow = false,
            filter,
            walkFilter,
          } = opts;
          const results = new minipass_1.Minipass({ objectMode: true });
          const dirs = new Set();
          if (!filter || filter(entry)) {
            results.write(withFileTypes ? entry : entry.fullpath());
          }
          const queue = [entry];
          let processing = 0;
          const process = () => {
            let paused = false;
            while (!paused) {
              const dir = queue.shift();
              if (!dir) {
                if (processing === 0) results.end();
                return;
              }
              processing++;
              dirs.add(dir);
              const entries = dir.readdirSync();
              for (const e of entries) {
                if (!filter || filter(e)) {
                  if (!results.write(withFileTypes ? e : e.fullpath())) {
                    paused = true;
                  }
                }
              }
              processing--;
              for (const e of entries) {
                let r = e;
                if (e.isSymbolicLink()) {
                  if (!(follow && (r = e.realpathSync()))) continue;
                  if (r.isUnknown()) r.lstatSync();
                }
                if (r.shouldWalk(dirs, walkFilter)) {
                  queue.push(r);
                }
              }
            }
            if (paused && !results.flowing) results.once('drain', process);
          };
          process();
          return results;
        }
        chdir(path = this.cwd) {
          const oldCwd = this.cwd;
          this.cwd = typeof path === 'string' ? this.cwd.resolve(path) : path;
          this.cwd[setAsCwd](oldCwd);
        }
      }
      exports.PathScurryBase = PathScurryBase;
      /**
       * Windows implementation of {@link PathScurryBase}
       *
       * Defaults to case insensitve, uses `'\\'` to generate path strings.  Uses
       * {@link PathWin32} for Path objects.
       */
      class PathScurryWin32 extends PathScurryBase {
        /**
         * separator for generating path strings
         */
        sep = '\\';
        constructor(cwd = process.cwd(), opts = {}) {
          const { nocase = true } = opts;
          super(cwd, node_path_1.win32, '\\', { ...opts, nocase });
          this.nocase = nocase;
          for (let p = this.cwd; p; p = p.parent) {
            p.nocase = this.nocase;
          }
        }
        /**
         * @internal
         */
        parseRootPath(dir) {
          // if the path starts with a single separator, it's not a UNC, and we'll
          // just get separator as the root, and driveFromUNC will return \
          // In that case, mount \ on the root from the cwd.
          return node_path_1.win32.parse(dir).root.toUpperCase();
        }
        /**
         * @internal
         */
        newRoot(fs) {
          return new PathWin32(
            this.rootPath,
            IFDIR,
            undefined,
            this.roots,
            this.nocase,
            this.childrenCache(),
            { fs },
          );
        }
        /**
         * Return true if the provided path string is an absolute path
         */
        isAbsolute(p) {
          return (
            p.startsWith('/') || p.startsWith('\\') || /^[a-z]:(\/|\\)/i.test(p)
          );
        }
      }
      exports.PathScurryWin32 = PathScurryWin32;
      /**
       * {@link PathScurryBase} implementation for all posix systems other than Darwin.
       *
       * Defaults to case-sensitive matching, uses `'/'` to generate path strings.
       *
       * Uses {@link PathPosix} for Path objects.
       */
      class PathScurryPosix extends PathScurryBase {
        /**
         * separator for generating path strings
         */
        sep = '/';
        constructor(cwd = process.cwd(), opts = {}) {
          const { nocase = false } = opts;
          super(cwd, node_path_1.posix, '/', { ...opts, nocase });
          this.nocase = nocase;
        }
        /**
         * @internal
         */
        parseRootPath(_dir) {
          return '/';
        }
        /**
         * @internal
         */
        newRoot(fs) {
          return new PathPosix(
            this.rootPath,
            IFDIR,
            undefined,
            this.roots,
            this.nocase,
            this.childrenCache(),
            { fs },
          );
        }
        /**
         * Return true if the provided path string is an absolute path
         */
        isAbsolute(p) {
          return p.startsWith('/');
        }
      }
      exports.PathScurryPosix = PathScurryPosix;
      /**
       * {@link PathScurryBase} implementation for Darwin (macOS) systems.
       *
       * Defaults to case-insensitive matching, uses `'/'` for generating path
       * strings.
       *
       * Uses {@link PathPosix} for Path objects.
       */
      class PathScurryDarwin extends PathScurryPosix {
        constructor(cwd = process.cwd(), opts = {}) {
          const { nocase = true } = opts;
          super(cwd, { ...opts, nocase });
        }
      }
      exports.PathScurryDarwin = PathScurryDarwin;
      /**
       * Default {@link PathBase} implementation for the current platform.
       *
       * {@link PathWin32} on Windows systems, {@link PathPosix} on all others.
       */
      exports.Path = process.platform === 'win32' ? PathWin32 : PathPosix;
      /**
       * Default {@link PathScurryBase} implementation for the current platform.
       *
       * {@link PathScurryWin32} on Windows systems, {@link PathScurryDarwin} on
       * Darwin (macOS) systems, {@link PathScurryPosix} on all others.
       */
      exports.PathScurry =
        process.platform === 'win32'
          ? PathScurryWin32
          : process.platform === 'darwin'
            ? PathScurryDarwin
            : PathScurryPosix;
      //# sourceMappingURL=index.js.map

      /***/
    },

    /***/ 1033: /***/ (module) => {
      'use strict';
      module.exports = /*#__PURE__*/ JSON.parse(
        '{"100":"Continue","101":"Switching Protocols","102":"Processing","103":"Early Hints","200":"OK","201":"Created","202":"Accepted","203":"Non-Authoritative Information","204":"No Content","205":"Reset Content","206":"Partial Content","207":"Multi-Status","208":"Already Reported","226":"IM Used","300":"Multiple Choices","301":"Moved Permanently","302":"Found","303":"See Other","304":"Not Modified","305":"Use Proxy","307":"Temporary Redirect","308":"Permanent Redirect","400":"Bad Request","401":"Unauthorized","402":"Payment Required","403":"Forbidden","404":"Not Found","405":"Method Not Allowed","406":"Not Acceptable","407":"Proxy Authentication Required","408":"Request Timeout","409":"Conflict","410":"Gone","411":"Length Required","412":"Precondition Failed","413":"Payload Too Large","414":"URI Too Long","415":"Unsupported Media Type","416":"Range Not Satisfiable","417":"Expectation Failed","418":"I\'m a Teapot","421":"Misdirected Request","422":"Unprocessable Entity","423":"Locked","424":"Failed Dependency","425":"Too Early","426":"Upgrade Required","428":"Precondition Required","429":"Too Many Requests","431":"Request Header Fields Too Large","451":"Unavailable For Legal Reasons","500":"Internal Server Error","501":"Not Implemented","502":"Bad Gateway","503":"Service Unavailable","504":"Gateway Timeout","505":"HTTP Version Not Supported","506":"Variant Also Negotiates","507":"Insufficient Storage","508":"Loop Detected","509":"Bandwidth Limit Exceeded","510":"Not Extended","511":"Network Authentication Required"}',
      );

      /***/
    },

    /******/
  };
  /************************************************************************/
  /******/ // The module cache
  /******/ var __webpack_module_cache__ = {};
  /******/
  /******/ // The require function
  /******/ function __webpack_require__(moduleId) {
    /******/ // Check if module is in cache
    /******/ var cachedModule = __webpack_module_cache__[moduleId];
    /******/ if (cachedModule !== undefined) {
      /******/ return cachedModule.exports;
      /******/
    }
    /******/ // Create a new module (and put it into the cache)
    /******/ var module = (__webpack_module_cache__[moduleId] = {
      /******/ // no module.id needed
      /******/ // no module.loaded needed
      /******/ exports: {},
      /******/
    });
    /******/
    /******/ // Execute the module function
    /******/ __webpack_modules__[moduleId].call(
      module.exports,
      module,
      module.exports,
      __webpack_require__,
    );
    /******/
    /******/ // Return the exports of the module
    /******/ return module.exports;
    /******/
  }
  /******/
  /************************************************************************/
  var __webpack_exports__ = {};
  // This entry needs to be wrapped in an IIFE because it needs to be in strict mode.
  (() => {
    'use strict';
    var exports = __webpack_exports__;
    var __webpack_unused_export__;

    __webpack_unused_export__ = { value: true };
    const common_1 = __webpack_require__(3563);
    const core_1 = __webpack_require__(8781);
    const app_module_1 = __webpack_require__(3004);
    const core_2 = __webpack_require__(8781);
    const platform_fastify_1 = __webpack_require__(5560);
    const path_1 = __webpack_require__(6928);
    const fs_1 = __webpack_require__(9896);
    const static_1 = __webpack_require__(3351);
    const swagger_1 = __webpack_require__(9742);
    const transform_interceptor_1 = __webpack_require__(6150);
    const timeout_interceptor_1 = __webpack_require__(17);
    async function bootstrap() {
      const app = await core_1.NestFactory.create(
        app_module_1.AppModule,
        new platform_fastify_1.FastifyAdapter(),
      );
      app.setGlobalPrefix('api');
      app.useGlobalPipes(
        new common_1.ValidationPipe({
          whitelist: true,
          transform: true,
        }),
      );
      const config = new swagger_1.DocumentBuilder()
        .setTitle('接口文档')
        .setVersion('1.0')
        .build();
      const document = swagger_1.SwaggerModule.createDocument(app, config);
      swagger_1.SwaggerModule.setup('docs', app, document, {
        jsonDocumentUrl: 'docs/json',
        customSiteTitle: 'API Documentation',
        customJs: [
          'https://cdn.jsdelivr.net/npm/swagger-ui-dist@5.9.0/swagger-ui-bundle.js',
          'https://cdn.jsdelivr.net/npm/swagger-ui-dist@5.9.0/swagger-ui-standalone-preset.js',
        ],
        customCssUrl: [
          'https://cdn.jsdelivr.net/npm/swagger-ui-dist@5.9.0/swagger-ui.css',
        ],
        swaggerOptions: {
          persistAuthorization: true,
          displayRequestDuration: true,
          docExpansion: 'none',
          filter: true,
          showCommonExtensions: true,
        },
      });
      app.useGlobalInterceptors(
        new transform_interceptor_1.TransformInterceptor(
          new core_2.Reflector(),
        ),
      );
      app.useGlobalInterceptors(
        new timeout_interceptor_1.TimeoutInterceptor(60 * 1000),
      );
      await app.register(static_1.default, {
        root: (0, path_1.join)(process.cwd(), 'public'),
        prefix: '/',
        decorateReply: false,
        schemaHide: true,
        serve: false,
      });
      app
        .getHttpAdapter()
        .getInstance()
        .addHook('onRequest', (req, reply, done) => {
          if (req.url === '/' || req.url === '/index.html') {
            const filePath = (0, path_1.join)(
              process.cwd(),
              'public',
              'index.html',
            );
            try {
              const html = (0, fs_1.readFileSync)(filePath, 'utf-8');
              reply
                .status(200)
                .header('Content-Type', 'text/html; charset=utf-8')
                .send(html);
            } catch (error) {
              console.log('error', error);
              reply
                .status(500)
                .header('Content-Type', 'text/plain; charset=utf-8')
                .send('Internal Server Error');
            }
          }
          done();
        });
      await app.listen(8888, '0.0.0.0');
      console.log(`Server is running on: ${await app.getUrl()}`);
      console.log(`Docs is running on: ${await app.getUrl()}/docs`);
      console.log(`Demo API is running on: ${await app.getUrl()}/api/v1/demo`);
    }
    bootstrap();
  })();

  /******/
})();
