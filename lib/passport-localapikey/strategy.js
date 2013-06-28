/**
 * Module dependencies.
 */
var passport = require('passport')
  , util = require('util')
  , BadRequestError = require('./errors/badrequesterror');


/**
 * `Strategy` constructor.
 *
 * The local api key authentication strategy authenticates requests based on the
 * credentials submitted through an HTML-based login form.
 *
 * Applications must supply a `verify` callback which accepts `username` and
 * `password` credentials, and then calls the `done` callback supplying a
 * `user`, which should be set to `false` if the credentials are not valid.
 * If an exception occured, `err` should be set.
 *
 * Optionally, `options` can be used to change the fields in which the
 * credentials are found.
 *
 * Options:
 *   - `apiKeyField`  field name where the username is found, defaults to _apiKey_
 *   - `passReqToCallback`  when `true`, `req` is the first argument to the verify callback (default: `false`)
 *
 * Examples:
 *
 *     passport.use(new LocalAPIKeyStrategy(
 *       function(username, password, done) {
 *         User.findOne({ username: username, password: password }, function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function Strategy(options, verify) {
  if (typeof options == 'function') {
    verify = options;
    options = {};
  }
  if (!verify) throw new Error('local authentication strategy requires a verify function');
  
  this._apiKeyField = options.apiKeyField || 'apikey';
  
  passport.Strategy.call(this);
  this.name = 'localapikey';
  this._verify = verify;
  this._passReqToCallback = options.passReqToCallback;
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(Strategy, passport.Strategy);

/**
 * Authenticate request based on the contents of a form submission.
 *
 * @param {Object} req
 * @api protected
 */
Strategy.prototype.authenticate = function(req, options) {
  var apikey, cookies, lookup, self, verified;

  cookies = {};
  verified = function(err, user, info) {
    if (err) {
      return self.error(err);
    }
    if (!user) {
      return self.fail(info);
    }
    return self.success(user, info);
  };
  lookup = function(obj, field) {
    var chain, i, len, prop;

    if (!obj) {
      return null;
    }
    chain = field.split("]").join("").split("[");
    i = 0;
    len = chain.length;
    while (i < len) {
      prop = obj[chain[i]];
      if (typeof prop === "undefined") {
        return null;
      }
      if (typeof prop !== "object") {
        return prop;
      }
      obj = prop;
      i++;
    }
    return null;
  };
  if (!req.headers.cookie) {
    return this.fail(new BadRequestError(options.badRequestMessage || "Missing API Key"));
  }
  req.headers.cookie.split(';').forEach(function(cookie) {
    var parts;

    parts = cookie.split('=');
    return cookies[parts[0].trim()] = (parts[1] || '').trim();
  });
  options = options || {};
  apikey = cookies[this._apiKeyField] || lookup(req.body, this._apiKeyField) || lookup(req.query, this._apiKeyField);
  console.log(req.headers.cookie, apikey);
  if (!apikey) {
    return this.fail(new BadRequestError(options.badRequestMessage || "Missing API Key"));
  }
  self = this;
  if (self._passReqToCallback) {
    return this._verify(req, apikey, verified);
  } else {
    return this._verify(apikey, verified);
  }
}


/**
 * Expose `Strategy`.
 */ 
module.exports = Strategy;
