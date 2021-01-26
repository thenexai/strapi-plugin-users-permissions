'use strict';

/**
 * Module dependencies.
 */

// Public node modules.
const _ = require('lodash');
const request = require('request');

// Purest strategies.
const purest = require('purest')({ request });
const purestConfig = require('@purest/providers');
const { getAbsoluteServerUrl } = require('strapi-utils');
const jwt = require('jsonwebtoken');

// Custom Start
const AppleAuth = require('apple-auth');

const { Wechat } = require('wechat-jssdk');
const { google } = require('googleapis');
// Custom End

/**
 * Connect thanks to a third-party provider.
 *
 *
 * @param {String}    provider
 * @param {String}    access_token
 *
 * @return  {*}
 */

const connect = (provider, query) => {
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

        const user = _.find(users, { provider });

        if (_.isEmpty(user) && !advanced.allow_register) {
          return resolve([
            null,
            [{ messages: [{ id: 'Auth.advanced.allow_register' }] }],
            'Register action is actualy not available.',
          ]);
        }

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

        const createdUser = await strapi.query('user', 'users-permissions').create(params);

        // Custom Start: creating farm
        const farm = await strapi.services.farm.create({
          sheep: "1,2",
          ufo: 1,
          type: "new",
          owner: createdUser.id,
          created_by: createdUser.id,
          updated_by: createdUser.id,
        });
        // Custom End: creating farm

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

    case 'weixin': {
      const wx = new Wechat({
        "appId": grant.weixin.key,
        "appSecret": grant.weixin.secret,
      });
      wx.oauth.getUserInfo(access_token)
        .then(function (result) {
          // The gender of an ordinary user. 1: male; 2: female.
          var gender = "Secret";
          if (result.sex == 1) {
            gender = "Boy";
          } else if (result.sex == 2) {
            gender = "Girl";
          }
          var uid = "wx" + result.unionid;
          callback(null, {
            username: uid,
            email: uid + "@yoo.cash",
            name: result.nickname,
            gender: gender,
            providerAvatar: result.headimgurl,
            providerUID: result.unionid,
          });
        }).catch(error => {
          // Token is not verified
          callback(error);
        });
      break;
    }

    case 'apple': {
      const appleConfig = {
        // use the bundle ID as client ID for native apps, else use the service ID for web-auth flows
        // https://forums.developer.apple.com/thread/118135
        client_id: query.useBundleId === "true" ? grant.apple.key + '.app' : grant.apple.key + '.service',
        team_id: "C689VFQ237",
        // redirect_uri: "http://dev.yoo.cash/callback/sign_in_with_apple", // does not matter here, as this is already the callback that verifies the token after the redirection
        key_id: "WJ67SNFR3R",
        scope: "name email"
      };
      const auth = new AppleAuth(
        appleConfig,
        grant.apple.secret.replace(/\|/g, "\n"),
        "text"
      );
      // console.log(appleConfig);

      auth.accessToken(access_token).then(resp => {
        const idToken = jwt.decode(resp.id_token);
        const userID = "ap" + idToken.sub;

        // `userEmail` and `userName` will only be provided for the initial authorization with your app
        const userEmail = idToken.email;
        const userName = `${query.firstName} ${query.lastName}`;

        callback(null, {
          username: userID,
          providerUID: idToken.sub,
          email: userEmail,
          name: userName,
        });
      }).catch(error => {
        callback(error);
      })

      break;
    }

    case 'discord': {
      const discord = purest({
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
    case 'cognito': {
      // get the id_token
      const idToken = query.id_token;
      // decode the jwt token
      const tokenPayload = jwt.decode(idToken);
      if (!tokenPayload) {
        callback(new Error('unable to decode jwt token'));
      } else {
        callback(null, {
          username: tokenPayload['cognito:username'],
          email: tokenPayload.email,
        });
      }
      break;
    }
    case 'facebook': {
      const facebook = purest({
        provider: 'facebook',
        config: purestConfig,
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

      var oauth2Client = new google.auth.OAuth2();
      oauth2Client.setCredentials({ access_token: access_token });
      var oauth2 = google.oauth2({
        auth: oauth2Client,
        version: 'v2'
      });
      oauth2.userinfo.get(
        function (err, res) {
          if (err) {
            callback(err);
          } else {
            var uid = "gg" + res.data.id;
            callback(null, {
              username: uid,
              email: res.data.email,
              name: res.data.given_name + ' ' + res.data.family_name,
              providerAvatar: res.data.picture,
              providerUID: res.data.id,
            });
          }
        });

      // const google = purest({ provider: 'google', config: purestConfig });

      // google
      //   .query('oauth')
      //   .get('tokeninfo')
      //   .qs({ access_token })
      //   .request((err, res, body) => {
      //     if (err) {
      //       callback(err);
      //     } else {
      //       callback(null, {
      //         username: body.email.split('@')[0],
      //         email: body.email,
      //       });
      //     }
      //   });
      break;
    }
    case 'github': {
      const github = purest({
        provider: 'github',
        config: purestConfig,
        defaults: {
          headers: {
            'user-agent': 'strapi',
          },
        },
      });

      github
        .query()
        .get('user')
        .auth(access_token)
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
            .auth(access_token)
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
      break;
    }
    case 'microsoft': {
      const microsoft = purest({
        provider: 'microsoft',
        config: purestConfig,
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
      const twitter = purest({
        provider: 'twitter',
        config: purestConfig,
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
      const instagram = purest({
        provider: 'instagram',
        key: grant.instagram.key,
        secret: grant.instagram.secret,
        config: purestConfig,
      });

      instagram
        .query()
        .get('me')
        .qs({ access_token, fields: 'id,username' })
        .request((err, res, body) => {
          if (err) {
            callback(err);
          } else {
            callback(null, {
              username: body.username,
              email: `${body.username}@strapi.io`, // dummy email as Instagram does not provide user email
            });
          }
        });
      break;
    }
    case 'vk': {
      const vk = purest({
        provider: 'vk',
        config: purestConfig,
      });

      vk.query()
        .get('users.get')
        .qs({ access_token, id: query.raw.user_id, v: '5.122' })
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
    case 'twitch': {
      const twitch = purest({
        provider: 'twitch',
        config: {
          twitch: {
            'https://api.twitch.tv': {
              __domain: {
                auth: {
                  headers: {
                    Authorization: 'Bearer [0]',
                    'Client-ID': '[1]',
                  },
                },
              },
              'helix/{endpoint}': {
                __path: {
                  alias: '__default',
                },
              },
              'oauth2/{endpoint}': {
                __path: {
                  alias: 'oauth',
                },
              },
            },
          },
        },
      });

      twitch
        .get('users')
        .auth(access_token, grant.twitch.key)
        .request((err, res, body) => {
          if (err) {
            callback(err);
          } else {
            callback(null, {
              username: body.data[0].login,
              email: body.data[0].email,
            });
          }
        });
      break;
    }
    case 'linkedin': {
      const linkedIn = purest({
        provider: 'linkedin',
        config: {
          linkedin: {
            'https://api.linkedin.com': {
              __domain: {
                auth: [{ auth: { bearer: '[0]' } }],
              },
              '[version]/{endpoint}': {
                __path: {
                  alias: '__default',
                  version: 'v2',
                },
              },
            },
          },
        },
      });
      try {
        const getDetailsRequest = () => {
          return new Promise((resolve, reject) => {
            linkedIn
              .query()
              .get('me')
              .auth(access_token)
              .request((err, res, body) => {
                if (err) {
                  return reject(err);
                }
                resolve(body);
              });
          });
        };

        const getEmailRequest = () => {
          return new Promise((resolve, reject) => {
            linkedIn
              .query()
              .get('emailAddress?q=members&projection=(elements*(handle~))')
              .auth(access_token)
              .request((err, res, body) => {
                if (err) {
                  return reject(err);
                }
                resolve(body);
              });
          });
        };

        const { localizedFirstName } = await getDetailsRequest();
        const { elements } = await getEmailRequest();
        const email = elements[0]['handle~'];

        callback(null, {
          username: localizedFirstName,
          email: email.emailAddress,
        });
      } catch (err) {
        callback(err);
      }
      break;
    }
    case 'reddit': {
      const reddit = purest({
        provider: 'reddit',
        config: purestConfig,
        defaults: {
          headers: {
            'user-agent': 'strapi',
          },
        },
      });

      reddit
        .query('auth')
        .get('me')
        .auth(access_token)
        .request((err, res, body) => {
          if (err) {
            callback(err);
          } else {
            callback(null, {
              username: body.name,
              email: `${body.name}@strapi.io`, // dummy email as Reddit does not provide user email
            });
          }
        });
      break;
    }
    case 'auth0': {
      const purestAuth0Conf = {};
      purestAuth0Conf[`https://${grant.auth0.subdomain}.auth0.com`] = {
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
      };
      const auth0 = purest({
        provider: 'auth0',
        config: {
          auth0: purestAuth0Conf,
        },
      });

      auth0
        .get('userinfo')
        .auth(access_token)
        .request((err, res, body) => {
          if (err) {
            callback(err);
          } else {
            const username =
              body.username || body.nickname || body.name || body.email.split('@')[0];
            const email = body.email || `${username.replace(/\s+/g, '.')}@strapi.io`;

            callback(null, {
              username,
              email,
            });
          }
        });
      break;
    }
    default:
      callback(new Error('Unknown provider.'));
      break;
  }
};

const buildRedirectUri = (provider = '') =>
  `${getAbsoluteServerUrl(strapi.config)}/connect/${provider}/callback`;

module.exports = {
  connect,
  buildRedirectUri,
};
