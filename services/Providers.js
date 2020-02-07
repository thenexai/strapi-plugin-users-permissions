'use strict';

/**
 * Module dependencies.
 */

// Public node modules.
const _ = require('lodash');
const request = require('request');
const appleSignin = require("apple-signin");

// Purest strategies.<
const Purest = require('purest');

/**
 * Connect thanks to a third-party provider.
 *
 *
 * @param {String}    provider
 * @param {String}    access_token
 *
 * @return  {*}
 */

exports.connect = (provider, query) => {
  const access_token = query.access_token || query.code || query.oauth_token;

  return new Promise((resolve, reject) => {
    if (!access_token) {
      return reject([null, { message: 'No access_token.' }]);
    }

    // Get the profile.
    getProfile(provider, query, async (err, profile) => {
      if (err) {
        return reject([null, err]);
      }

      // We need at least the mail.
      if (!profile.email) {
        return reject([null, { message: 'Email was not available.' }]);
      }

      try {
        const users = await strapi.query('user', 'users-permissions').find({
          email: profile.email,
        });

        const advanced = await strapi
          .store({
            environment: '',
            type: 'plugin',
            name: 'users-permissions',
            key: 'advanced',
          })
          .get();

        if (
          _.isEmpty(_.find(users, { provider })) &&
          !advanced.allow_register
        ) {
          return resolve([
            null,
            [{ messages: [{ id: 'Auth.advanced.allow_register' }] }],
            'Register action is actualy not available.',
          ]);
        }

        const user = _.find(users, { provider });

        if (!_.isEmpty(user)) {
          return resolve([user, null]);
        }

        if (
          !_.isEmpty(_.find(users, user => user.provider !== provider)) &&
          advanced.unique_email
        ) {
          return resolve([
            null,
            [{ messages: [{ id: 'Auth.form.error.email.taken' }] }],
            'Email is already taken.',
          ]);
        }

        // Retrieve default role.
        const defaultRole = await strapi
          .query('role', 'users-permissions')
          .findOne({ type: advanced.default_role }, []);

        // Create the new user.
        const params = _.assign(profile, {
          provider: provider,
          role: defaultRole.id,
          confirmed: true,
        });

        const createdUser = await strapi
          .query('user', 'users-permissions')
          .create(params);

        return resolve([createdUser, null]);
      } catch (err) {
        reject([null, err]);
      }
    });
  });
};

/**
 * Helper to get profiles
 *
 * @param {String}   provider
 * @param {Function} callback
 */

const getProfile = async (provider, query, callback) => {
  const access_token = query.access_token || query.code || query.oauth_token;

  const grant = await strapi
    .store({
      environment: '',
      type: 'plugin',
      name: 'users-permissions',
      key: 'grant',
    })
    .get();

  switch (provider) {
    case 'apple': {

      appleSignin.verifyIdToken(access_token).then(result => {
        var randomInt = Math.floor(Math.random() * Math.floor(9999));

        callback(null, {
          username: result.email.split('@')[0] + randomInt.toString(),
          email: result.email,
        });
      }).catch(error => {
        // Token is not verified
        callback(error);
      });

      break;
    }
    case 'discord': {
      const discord = new Purest({
        provider: 'discord',
        config: {
          discord: {
            'https://discordapp.com/api/': {
              __domain: {
                auth: {
                  auth: { bearer: '[0]' },
                },
              },
              '{endpoint}': {
                __path: {
                  alias: '__default',
                },
              },
            },
          },
        },
      });
      discord
        .query()
        .get('users/@me')
        .auth(access_token)
        .request((err, res, body) => {
          if (err) {
            callback(err);
          } else {
            // Combine username and discriminator because discord username is not unique
            var username = `${body.username}#${body.discriminator}`;
            callback(null, {
              username: username,
              email: body.email,
            });
          }
        });
      break;
    }
    case 'facebook': {
      const facebook = new Purest({
        provider: 'facebook',
      });

      facebook
        .query()
        .get('me?fields=name,email')
        .auth(access_token)
        .request((err, res, body) => {
          if (err) {
            callback(err);
          } else {
            callback(null, {
              username: body.name,
              email: body.email,
            });
          }
        });
      break;
    }
    case 'google': {
      const config = {
        google: {
          'https://www.googleapis.com': {
            __domain: {
              auth: {
                auth: { bearer: '[0]' },
              },
            },
            '{endpoint}': {
              __path: {
                alias: '__default',
              },
            },
            'oauth/[version]/{endpoint}': {
              __path: {
                alias: 'oauth',
                version: 'v3',
              },
            },
          },
        },
      };
      const google = new Purest({ provider: 'google', config });

      var randomInt = Math.floor(Math.random() * Math.floor(9999));

      google
        .query('oauth')
        .get('tokeninfo')
        .qs({ access_token })
        .request((err, res, body) => {
          if (err) {
            callback(err);
          } else {
            callback(null, {
              username: body.email.split('@')[0] + randomInt.toString(),
              email: body.email,
            });
          }
        });
      break;
    }
    case 'github': {
      const github = new Purest({
        provider: 'github',
        defaults: {
          headers: {
            'user-agent': 'strapi',
          },
        },
      });

      request.post(
        {
          url: 'https://github.com/login/oauth/access_token',
          form: {
            client_id: grant.github.key,
            client_secret: grant.github.secret,
            code: access_token,
          },
        },
        (err, res, body) => {
          github
            .query()
            .get('user')
            .auth(body.split('&')[0].split('=')[1])
            .request((err, res, userbody) => {
              if (err) {
                return callback(err);
              }

              // This is the public email on the github profile
              if (userbody.email) {
                return callback(null, {
                  username: userbody.login,
                  email: userbody.email,
                });
              }

              // Get the email with Github's user/emails API
              github
                .query()
                .get('user/emails')
                .auth(body.split('&')[0].split('=')[1])
                .request((err, res, emailsbody) => {
                  if (err) {
                    return callback(err);
                  }

                  return callback(null, {
                    username: userbody.login,
                    email: Array.isArray(emailsbody)
                      ? emailsbody.find(email => email.primary === true).email
                      : null,
                  });
                });
            });
        }
      );
      break;
    }
    case 'microsoft': {
      const microsoft = new Purest({
        provider: 'microsoft',
        config: {
          microsoft: {
            'https://graph.microsoft.com': {
              __domain: {
                auth: {
                  auth: { bearer: '[0]' },
                },
              },
              '[version]/{endpoint}': {
                __path: {
                  alias: '__default',
                  version: 'v1.0',
                },
              },
            },
          },
        },
      });

      microsoft
        .query()
        .get('me')
        .auth(access_token)
        .request((err, res, body) => {
          if (err) {
            callback(err);
          } else {
            callback(null, {
              username: body.userPrincipalName,
              email: body.userPrincipalName,
            });
          }
        });
      break;
    }
    case 'twitter': {
      const twitter = new Purest({
        provider: 'twitter',
        key: grant.twitter.key,
        secret: grant.twitter.secret,
      });

      twitter
        .query()
        .get('account/verify_credentials')
        .auth(access_token, query.access_secret)
        .qs({ screen_name: query['raw[screen_name]'], include_email: 'true' })
        .request((err, res, body) => {
          if (err) {
            callback(err);
          } else {
            callback(null, {
              username: body.screen_name,
              email: body.email,
            });
          }
        });
      break;
    }
    case 'instagram': {
      const instagram = new Purest({
        provider: 'instagram',
        key: grant.instagram.key,
        secret: grant.instagram.secret,
      });

      instagram
        .query()
        .get('users/self')
        .qs({ access_token })
        .request((err, res, body) => {
          if (err) {
            callback(err);
          } else {
            callback(null, {
              username: body.data.username,
              email: `${body.data.username}@strapi.io`, // dummy email as Instagram does not provide user email
            });
          }
        });
      break;
    }
    case 'vk': {
      const vk = new Purest({ provider: 'vk' });

      vk.query()
        .get('users.get')
        .auth(access_token)
        .qs({ id: query.raw.user_id, v: '5.013' })
        .request((err, res, body) => {
          if (err) {
            callback(err);
          } else {
            callback(null, {
              username: `${body.response[0].last_name} ${body.response[0].first_name}`,
              email: query.raw.email,
            });
          }
        });
      break;
    }
    default:
      callback({
        message: 'Unknown provider.',
      });
      break;
  }
};
