'use strict';

var Boom = require('boom');
var Hoek = require('hoek');
var Joi = require('joi');
var redis = require('redis');
var signature = require('cookie-signature');

var internals = {};

exports.register = function (server, options, next) {
  server.auth.scheme('cookie', internals.implementation);

  next();
};

exports.register.attributes = {
  pkg: require('./package.json')
};

internals.schema = Joi.object({
  clearInvalid: Joi.boolean().default(false),
  cookieName: Joi.string(),
  cookieValuePrefix: Joi.string().default('s:'),
  redirectTo: Joi.string().allow(false),
  redis: Joi.object().keys({
    host: Joi.string(),
    port: Joi.number().default(6379)
  }),
  secret: Joi.string(),
  sessionIDPrefix: Joi.string().default('sess:'),
  userProp: Joi.string().default('user'),
}).required();

internals.implementation = function (server, options) {
  var results = Joi.validate(options, internals.schema);
  Hoek.assert(!results.error, results.error);

  var settings = results.value;

  if (typeof settings.appendNext === 'boolean') {
    settings.appendNext = (settings.appendNext ? 'next' : '');
  }

  var redisClient = redis.createClient(settings.redis.port, settings.redis.host);

  function decodeCookieValue(val) {
    val = decodeURIComponent(val).trim();

    // quoted values
    if ('"' == val[0]) {
      val = val.slice(1, -1);
    }

    return val;
  }

  var scheme = {
    authenticate: function (request, reply) {
      var validate = function () {
        var rawCookieValue = request.state[settings.cookieName];

        if (!rawCookieValue) {
          return unauthenticated(Boom.unauthorized(null, 'cookie'));
        }

        rawCookieValue = decodeCookieValue(rawCookieValue);

        var sessionID;

        if (rawCookieValue.substr(0, 2) === settings.cookieValuePrefix) {
          sessionID = signature.unsign(rawCookieValue.slice(2), settings.secret);

          if (sessionID === false) {
            // cookie signature invalid
            sessionID = undefined;

            if (settings.clearInvalid) {
              reply.unstate(settings.cookieName);
            }

            return unauthenticated(Boom.unauthorized('Invalid cookie'));
          }
        } else {
          return unauthenticated(Boom.unauthorized(null, 'cookie'));
        }

        redisClient.get(settings.sessionIDPrefix + sessionID, function (err, data) {
          if (err) {
            return unauthenticated(Boom.unauthorized('Server error'));
          }

          if (!data) {
            return unauthenticated(Boom.unauthorized(null, 'cookie'));
          }

          data = data.toString();

          try {
            data = JSON.parse(data);
          } catch (er) {
            return unauthenticated(Boom.unauthorized('Invalid session data'));
          }

          if (!data[settings.userProp]) {
            return unauthenticated(Boom.unauthorized(null, 'cookie'));
          }

          return reply.continue({
            artifacts: data,
            credentials: data,
          });
        });
      };

      var unauthenticated = function (err, result) {
        var redirectTo = settings.redirectTo;

        if (!redirectTo) {
          return reply(err, null, result);
        }

        var uri = redirectTo;

        if (settings.appendNext) {
          if (uri.indexOf('?') !== -1) {
            uri += '&';
          }
          else {
            uri += '?';
          }

          uri += settings.appendNext + '=' + encodeURIComponent(request.url.path);
        }

        return reply('You are being redirected...', null, result).redirect(uri);
      };

      validate();
    }
  };

  return scheme;
};
