'use strict';

/**
 * User.js controller
 *
 * @description: A set of functions called "actions" for managing `User`.
 */

const _ = require('lodash');
const adminUserController = require('./user/admin');
const apiUserController = require('./user/api');
const { sanitizeEntity } = require('strapi-utils');

const sanitizeUser = user =>
  sanitizeEntity(user, {
    model: strapi.query('user', 'users-permissions').model,
  });

const resolveController = ctx => {
  const {
    state: { isAuthenticatedAdmin },
  } = ctx;

  return isAuthenticatedAdmin ? adminUserController : apiUserController;
};

const resolveControllerMethod = method => ctx => {
  const controller = resolveController(ctx);
  const callbackFn = controller[method];

  if (!_.isFunction(callbackFn)) {
    return ctx.notFound();
  }

  return callbackFn(ctx);
};

module.exports = {
  create: resolveControllerMethod('create'),
  update: resolveControllerMethod('update'),

  /**
   * Retrieve user records.
   * @return {Object|Array}
   */
  async find(ctx, next, { populate } = {}) {
    let users;

    if (_.has(ctx.query, '_q')) {
      // use core strapi query to search for users
      users = await strapi.query('user', 'users-permissions').search(ctx.query, populate);
    } else {
      users = await strapi.plugins['users-permissions'].services.user.fetchAll(ctx.query, populate);
    }

    ctx.body = users.map(sanitizeUser);
  },

  /**
   * Retrieve a user record.
   * @return {Object}
   */
  async findOne(ctx) {
    const { id } = ctx.params;
    let data = await strapi.plugins['users-permissions'].services.user.fetch({
      id,
    });

    if (data) {
      data = sanitizeUser(data);
    }

    // Send 200 `ok`
    ctx.body = data;
  },

  /**
   * Retrieve user count.
   * @return {Number}
   */
  async count(ctx) {
    if (_.has(ctx.query, '_q')) {
      return await strapi.plugins['users-permissions'].services.user.countSearch(ctx.query);
    }
    ctx.body = await strapi.plugins['users-permissions'].services.user.count(ctx.query);
  },

  /**
   * Destroy a/an user record.
   * @return {Object}
   */
  async destroy(ctx) {
    const { id } = ctx.params;
    const data = await strapi.plugins['users-permissions'].services.user.remove({ id });
    ctx.send(sanitizeUser(data));
  },

  async destroyAll(ctx) {
    const {
      request: { query },
    } = ctx;

    const toRemove = Object.values(_.omit(query, 'source'));
    const { primaryKey } = strapi.query('user', 'users-permissions');
    const finalQuery = { [`${primaryKey}_in`]: toRemove, _limit: 100 };

    const data = await strapi.plugins['users-permissions'].services.user.removeAll(finalQuery);

    ctx.send(data);
  },

  /**
   * Retrieve authenticated user.
   * @return {Object|Array}
   */
  async me(ctx) {
    const user = ctx.state.user;

    if (!user) {
      return ctx.badRequest(null, [{ messages: [{ id: 'No authorization header was found' }] }]);
    }
    const newUser = await strapi.query('user', 'users-permissions').findOne({
      id: user.id
    });

    ctx.body = sanitizeUser(newUser);
    // ctx.body = sanitizeUser(user);
  },

  /**
  * Update a/an user record.
  * @return {Object}
  */

  async updateMe(ctx) {
    const advancedConfigs = await strapi
      .store({
        environment: '',
        type: 'plugin',
        name: 'users-permissions',
        key: 'advanced',
      })
      .get();

    // Yoo.cash start
    // const { id } = ctx.params;
    if (!ctx.state.user || !ctx.state.user.id) {
      return ctx.badRequest(null, [{ messages: [{ id: 'No authorization header was found' }] }]);
    }
    const id = ctx.state.user.id;
    // Yoo.cash end

    const { email, username, password } = ctx.request.body;

    const user = await strapi.plugins['users-permissions'].services.user.fetch({
      id,
    });

    if (_.has(ctx.request.body, 'email') && !email) {
      return ctx.badRequest('email.notNull');
    }

    if (_.has(ctx.request.body, 'username') && !username) {
      return ctx.badRequest('username.notNull');
    }

    if (_.has(ctx.request.body, 'password') && !password && user.provider === 'local') {
      return ctx.badRequest('password.notNull');
    }

    if (_.has(ctx.request.body, 'username')) {
      const userWithSameUsername = await strapi
        .query('user', 'users-permissions')
        .findOne({ username });

      if (userWithSameUsername && userWithSameUsername.id != id) {
        return ctx.badRequest(
          null,
          formatError({
            id: 'Auth.form.error.username.taken',
            message: 'username.alreadyTaken.',
            field: ['username'],
          })
        );
      }
    }

    if (_.has(ctx.request.body, 'email') && advancedConfigs.unique_email) {
      const userWithSameEmail = await strapi.query('user', 'users-permissions').findOne({ email });

      if (userWithSameEmail && userWithSameEmail.id != id) {
        return ctx.badRequest(
          null,
          formatError({
            id: 'Auth.form.error.email.taken',
            message: 'Email already taken',
            field: ['email'],
          })
        );
      }
    }

    let updateData = {
      ...ctx.request.body,
    };

    if (_.has(ctx.request.body, 'password') && password === user.password) {
      delete updateData.password;
    }

    // Yoo.cash start: Don't update sensitive data
    delete updateData['id'];
    delete updateData['email'];
    delete updateData['username'];
    delete updateData['provider'];
    delete updateData['password'];
    delete updateData['resetPasswordToken'];
    delete updateData['confirmed'];
    delete updateData['blocked'];
    delete updateData['role'];
    delete updateData['providerAvatar'];
    delete updateData['providerUID'];
    delete updateData['created_by'];
    delete updateData['updated_by'];
    delete updateData['created_at'];
    delete updateData['updated_at'];
    delete updateData['confirmationToken'];
    // Yoo.cash end


    const data = await strapi.plugins['users-permissions'].services.user.edit({ id }, updateData);

    ctx.send(sanitizeUser(data));
  },
};
