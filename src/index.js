import Cookies from 'js-cookie';
import fetchIntercept from 'fetch-intercept';
import qs from 'qs';

import {
  ACCOUNT_UPDATE_ERROR,
  ACCOUNT_UPDATE_SUCCESS,
  DESTROY_ACCOUNT_ERROR,
  DESTROY_ACCOUNT_SUCCESS,
  EMAIL_SIGN_IN_ERROR,
  OAUTH_SIGN_IN_ERROR,
  OAUTH_SIGN_IN_SUCCESS,
  PASSWORD_UPDATE_ERROR,
  PASSWORD_UPDATE_SUCCESS,
  SIGN_IN_ERROR,
  SIGN_IN_SUCCESS,
  SIGN_OUT_ERROR,
  SIGN_OUT_SUCCESS
} from './constants/broadcast-message-types';
import {
  FIRST_TIME_LOGIN,
  INITIAL_CONFIG_KEY,
  MUST_RESET_PASSWORD,
  SAVED_CONFIG_KEY,
  SAVED_CREDS_KEY
} from './constants/storage-keys';

var root = window;
const AuthInstance = new Auth();
root.esTokerAuthInstance = AuthInstance;

// private util methods
var getFirstObjectKey = function(obj) {
  for (var key in obj) {
    return key;
  }
};

var unescapeQuotes = function(val) {
  return val && val.replace(/("|')/g, '');
};

var isApiRequest = function(url) {
  return url.match(AuthInstance.getApiUrl());
};

// simple string templating. stolen from:
// http://stackoverflow.com/questions/14879866/javascript-templating-function-replace-string-and-dont-take-care-of-whitespace
var tmpl = function(str, obj) {
  var replacer = function(wholeMatch, key) {
      return obj[key] === undefined ? wholeMatch : obj[key];
    },
    regexp = new RegExp('{{\\s*([a-z0-9-_]+)\\s*}}', 'ig');

  for (
    var beforeReplace = '';
    beforeReplace !== str;
    str = (beforeReplace = str).replace(regexp, replacer)
  ) {}
  return str;
};

// check if IE < 10
function isOldIE() {
  var oldIE = false,
    ua = root.navigator.userAgent.toLowerCase();

  if (ua && ua.indexOf('msie') !== -1) {
    var version = parseInt(ua.split('msie')[1]);
    if (version < 10) {
      oldIE = true;
    }
  }

  return oldIE;
}

// check if using IE
function isIE() {
  var ieLTE10 = isOldIE(),
    ie11 = !!root.navigator.userAgent.match(/Trident.*rv\:11\./);

  return ieLTE10 || ie11;
}

export class Auth {
  constructor() {
    // set flag so we know when plugin has been configured.
    this.configured = false;

    // create promise for configuration + verification
    this.configDfd = null;

    // configs hash allows for multiple configurations
    this.configs = {};

    // default config will be first named config or "default"
    this.defaultConfigKey = null;

    // flagged when users return from email confirmation
    this.firstTimeLogin = false;

    // flagged when users return from password change confirmation
    this.mustResetPassword = false;

    // save reference to user
    this.user = {};

    // oAuth promise is kept while visiting provider
    this.oAuthDfd = null;

    // timer is used to poll external auth window while authenticating via OAuth
    this.oAuthTimer = null;

    // base config from which other configs are extended
    this.configBase = {
      apiUrl: '/api',
      signOutPath: '/auth/sign_out',
      emailSignInPath: '/auth/sign_in',
      emailRegistrationPath: '/auth',
      accountUpdatePath: '/auth',
      accountDeletePath: '/auth',
      passwordResetPath: '/auth/password',
      passwordUpdatePath: '/auth/password',
      tokenValidationPath: '/auth/validate_token',
      proxyIf: function() {
        return false;
      },
      proxyUrl: '/proxy',
      forceHardRedirect: false,
      storage: 'cookies',
      cookieExpiry: 14,
      cookiePath: '/',
      initialCredentials: null,

      passwordResetSuccessUrl: function() {
        return root.location.href;
      },

      confirmationSuccessUrl: function() {
        return root.location.href;
      },

      tokenFormat: {
        'access-token': '{{ access-token }}',
        'token-type': 'Bearer',
        client: '{{ client }}',
        expiry: '{{ expiry }}',
        uid: '{{ uid }}'
      },

      parseExpiry: function(headers) {
        // convert from ruby time (seconds) to js time (millis)
        return parseInt(headers['expiry'], 10) * 1000 || null;
      },

      handleLoginResponse: function(resp) {
        return resp.data;
      },

      handleAccountUpdateResponse: function(resp) {
        return resp.data;
      },

      handleTokenValidationResponse: function(resp) {
        return resp.data;
      },

      authProviderPaths: {
        github: '/auth/github',
        facebook: '/auth/facebook',
        google: '/auth/google_oauth2'
      }
    };
  }

  // mostly for testing. reset all config values
  reset() {
    // clean up session without relying on `getConfig`
    this.destroySession();

    this.configs = {};
    this.defaultConfigKey = null;
    this.configured = false;
    this.configDfd = null;
    this.mustResetPassword = false;
    this.firstTimeLogin = false;
    this.oAuthDfd = null;
    this.willRedirect = false;

    if (this.oAuthTimer) {
      clearTimeout(this.oAuthTimer);
      this.oAuthTimer = null;
    }

    // clear user object
    for (var key in this.user) {
      delete this.user[key];
    }

    // remove event listeners
    root.removeEventListener('message', this.handlePostMessage);

    // remove global ajax "interceptors"
    if (typeof this.unregisterFetchIntercept === 'function') {
      this.unregisterFetchIntercept();
      delete this.unregisterFetchIntercept;
    }
  }

  invalidateTokens() {
    // clear user object, but don't destroy object in case of bindings
    for (var key in this.user) {
      delete this.user[key];
    }

    // clear auth session data
    this.deleteData(SAVED_CONFIG_KEY);
    this.deleteData(SAVED_CREDS_KEY);
  }

  // throw clear errors when dependencies are not met
  checkDependencies() {
    var errors = [],
      warnings = [];

    if (!$) {
      throw 'es-toker: jQuery not found. This module depends on jQuery.';
    }

    if (!root.localStorage && !Cookies) {
      errors.push(
        'This browser does not support localStorage. You must install ' +
          'jquery-cookie to use es-toker with this browser.'
      );
    }

    if (!qs.parse) {
      errors.push('Dependency not met: jquery-qs.parse.');
    }

    if (!root.PubSub) {
      warnings.push('PubSub not found. No auth events will be broadcast.');
    }

    if (errors.length) {
      var errMessage = errors.join(' ');
      throw 'es-toker: Please resolve the following errors: ' + errMessage;
    }

    if (warnings.length && console && console.warn) {
      var warnMessage = warnings.join(' ');
      console.warn('es-toker: Warning: ' + warnMessage);
    }
  }

  // need a way to destroy the current session without relying on `getConfig`.
  // otherwise we get into infinite loop territory.
  destroySession() {
    var sessionKeys = [SAVED_CREDS_KEY, SAVED_CONFIG_KEY];

    for (var key in sessionKeys) {
      key = sessionKeys[key];

      // kill all local storage keys
      if (root.localStorage) {
        root.localStorage.removeItem(key);
      }

      if (Cookies) {
        // each config may have different cookiePath settings
        for (var config in this.configs) {
          var cookiePath = this.configs[config].cookiePath;

          Cookies.remove(key, { path: cookiePath });
        }

        // remove from base path in case config is not specified
        Cookies.remove(key, { path: '/' });
      }
    }
  }

  configure(opts, reset) {
    // destroy all session data. useful for testing
    if (reset) {
      this.reset();
    }

    if (this.configured) {
      return this.configDfd;
    }

    // set flag so configure isn't called again (unless reset)
    this.configured = true;

    // normalize opts into object object
    if (!opts) {
      opts = {};
    }

    // normalize so opts is always an array of objects
    if (opts.constructor !== Array) {
      // single config will always be called 'default' unless set
      // by previous session
      this.defaultConfigKey = INITIAL_CONFIG_KEY;

      // config should look like {default: {...}}
      var defaultConfig = {};
      defaultConfig[this.defaultConfigKey] = opts;

      // opts should look like [{default: {...}}]
      opts = [defaultConfig];
    }

    // iterate over config items, extend each from defaults
    for (var i = 0; i < opts.length; i++) {
      var configName = getFirstObjectKey(opts[i]);

      // set first set as default config
      if (!this.defaultConfigKey) {
        this.defaultConfigKey = configName;
      }

      // save config to `configs` hash
      this.configs[configName] = {
        ...this.configBase,
        ...opts[i][configName]
      };
    }

    // ensure that setup requirements have been met
    // FIXME:
    this.checkDependencies();

    // TODO: add config option for these bindings
    if (true) {
      this.unregisterFetchIntercept = fetchIntercept.register({
        // intercept requests to the API, append auth headers
        request: this.appendAuthHeaders,
        // update auth creds after each request to the API
        response: this.updateAuthCredentials
      });
    }

    root.addEventListener('message', this.handlePostMessage, false);

    // pull creds from search bar if available
    // TODO: Extract this
    this.processSearchParams();

    // don't validate the token if we're just going to redirect anyway.
    // otherwise the page won't have time to process the response header and
    // the token may expire before the redirected page can validate.
    if (this.willRedirect) {
      return false;
    }

    // don't validate with the server if the credentials were provided. this is
    // a case where the validation happened on the server and is being used to
    // initialize the client.
    else if (this.getConfig().initialCredentials) {
      // skip initial headers check (i.e. check was already done server-side)
      var c = this.getConfig();
      this.persistData(SAVED_CREDS_KEY, c.initialCredentials.headers);
      this.persistData(
        MUST_RESET_PASSWORD,
        c.initialCredentials.mustResetPassword
      );
      this.persistData(FIRST_TIME_LOGIN, c.initialCredentials.firstTimeLogin);
      this.setCurrentUser(c.initialCredentials.user);

      return Promise.resolve(c.initialCredentials.user);
    }

    // otherwise check with server if any existing tokens are found
    else {
      // validate token if set
      this.configDfd = this.validateToken({
        config: this.getCurrentConfigName()
      });
      return this.configDfd;
    }
  }

  getApiUrl() {
    var config = this.getConfig();
    return config.proxyIf() ? config.proxyUrl : config.apiUrl;
  }

  // interpolate values of tokenFormat hash with ctx, return new hash
  buildAuthHeaders(ctx) {
    var headers = {},
      fmt = this.getConfig().tokenFormat;

    for (var key in fmt) {
      headers[key] = tmpl(fmt[key], ctx);
    }

    return headers;
  }

  setCurrentUser(user) {
    // clear user object of any existing attributes
    for (var key in this.user) {
      delete this.user[key];
    }

    // save user data, preserve bindings to original user object
    this.user = { ...this.user, ...user };

    this.user.signedIn = true;
    this.user.configName = this.getCurrentConfigName();

    return this.user;
  }

  handlePostMessage(ev) {
    var stopListening = false;

    if (ev.data.message === 'deliverCredentials') {
      delete ev.data.message;

      var initialHeaders = AuthInstance.normalizeTokenKeys(ev.data),
        authHeaders = AuthInstance.buildAuthHeaders(initialHeaders),
        user = AuthInstance.setCurrentUser(ev.data);

      AuthInstance.persistData(SAVED_CREDS_KEY, authHeaders);
      AuthInstance.resolvePromise(
        OAUTH_SIGN_IN_SUCCESS,
        AuthInstance.oAuthDfd,
        user
      );
      AuthInstance.broadcastEvent(SIGN_IN_SUCCESS, user);
      AuthInstance.broadcastEvent(VALIDATION_SUCCESS, user);

      stopListening = true;
    }

    if (ev.data.message === 'authFailure') {
      AuthInstance.rejectPromise(
        OAUTH_SIGN_IN_ERROR,
        AuthInstance.oAuthDfd,
        ev.data,
        'OAuth authentication failed.'
      );

      AuthInstance.broadcastEvent(SIGN_IN_ERROR, ev.data);

      stopListening = true;
    }

    if (stopListening) {
      clearTimeout(AuthInstance.oAuthTimer);
      AuthInstance.oAuthTimer = null;
    }
  }

  // compensate for poor naming decisions made early on
  // TODO: fix API so this isn't necessary
  normalizeTokenKeys(params) {
    // normalize keys
    if (params.token) {
      params['access-token'] = params.token;
      delete params.token;
    }
    if (params.auth_token) {
      params['access-token'] = params.auth_token;
      delete params.auth_token;
    }
    if (params.client_id) {
      params.client = params.client_id;
      delete params.client_id;
    }

    if (params.config) {
      this.persistData(SAVED_CONFIG_KEY, params.config, params.config);
      delete params.config;
    }

    return params;
  }

  processSearchParams() {
    var searchParams = this.getQs(),
      newHeaders = null;

    searchParams = this.normalizeTokenKeys(searchParams);

    // only bother with this if minimum search params are present
    if (searchParams['access-token'] && searchParams.uid) {
      newHeaders = this.buildAuthHeaders(searchParams);

      // save all token headers to session
      this.persistData(SAVED_CREDS_KEY, newHeaders);

      // check if user is returning from password reset link
      if (searchParams.reset_password) {
        this.persistData(MUST_RESET_PASSWORD, true);
      }

      // check if user is returning from confirmation email
      if (searchParams.account_confirmation_success) {
        this.persistData(FIRST_TIME_LOGIN, true);
      }

      // TODO: set uri flag on devise_token_auth for OAuth confirmation
      // when using hard page redirects.

      // set qs without auth keys/values
      var newLocation = this.getLocationWithoutParams([
        'access-token',
        'token',
        'auth_token',
        'config',
        'client',
        'client_id',
        'expiry',
        'uid',
        'reset_password',
        'account_confirmation_success'
      ]);

      this.willRedirect = true;
      this.setLocation(newLocation);
    }

    return newHeaders;
  }

  // this method is tricky. we want to reconstruct the current URL with the
  // following conditions:
  // 1. search contains none of the supplied keys
  // 2. anchor search (i.e. `#/?key=val`) contains none of the supplied keys
  // 3. all of the keys NOT supplied are presevered in their original form
  // 4. url protocol, host, and path are preserved
  getLocationWithoutParams(keys) {
    // strip all values from both actual and anchor search params
    var newSearch = qs.stringify(this.stripKeys(this.getSearchQs(), keys)),
      newAnchorQs = qs.stringify(this.stripKeys(this.getAnchorQs(), keys)),
      newAnchor = root.location.hash.split('?')[0];

    if (newSearch) {
      newSearch = '?' + newSearch;
    }

    if (newAnchorQs) {
      newAnchor += '?' + newAnchorQs;
    }

    if (newAnchor && !newAnchor.match(/^#/)) {
      newAnchor = '#/' + newAnchor;
    }

    // reconstruct location with stripped auth keys
    var newLocation =
      root.location.protocol +
      '//' +
      root.location.host +
      root.location.pathname +
      newSearch +
      newAnchor;

    return newLocation;
  }

  stripKeys(obj, keys) {
    for (var q in keys) {
      delete obj[keys[q]];
    }

    return obj;
  }

  // abstract publish method, only use if pubsub exists.
  // TODO: allow broadcast method to be configured
  // TODO: Extract this
  broadcastEvent(msg, data) {
    if (root.PubSub && typeof root.PubSub.publish === 'function') {
      root.PubSub.publish(msg, data);
    }
  }

  rejectPromise(evMsg, dfd, data, reason) {
    var self = this;

    data = JSON.parse((data && data.responseText) || '{}');

    // always reject after 0 timeout to ensure that ajaxComplete callback
    // has run before promise is rejected
    setTimeout(function() {
      self.broadcastEvent(evMsg, data);
      dfd.reject({
        reason: reason,
        data: data
      });
    }, 0);

    return dfd;
  }

  // TODO: document
  validateToken(options = {}) {
    if (!options.config) {
      options.config = this.getCurrentConfigName();
    }

    // if this check is already in progress, return existing promise
    if (this.configDfd) {
      return this.configDfd;
    }

    // no creds, reject promise without making API call
    if (!this.retrieveData(SAVED_CREDS_KEY)) {
      // clear any saved session data
      this.invalidateTokens();

      // reject promise, broadcast event
      return Promise.reject('Cannot validate token; no token found.');
    } else {
      const config = this.getConfig(options.config);
      const url = this.getApiUrl() + config.tokenValidationPath;

      return fetch(url)
        .then(response => {
          const user = config.handleTokenValidationResponse(response);
          this.setCurrentUser(user);

          if (this.retrieveData(FIRST_TIME_LOGIN)) {
            this.broadcastEvent(EMAIL_CONFIRMATION_SUCCESS, response);
            this.persistData(FIRST_TIME_LOGIN, false);
            this.firstTimeLogin = true;
          }

          if (this.retrieveData(MUST_RESET_PASSWORD)) {
            this.broadcastEvent(PASSWORD_RESET_CONFIRM_SUCCESS, response);
            this.persistData(MUST_RESET_PASSWORD, false);
            this.mustResetPassword = true;
          }

          this.resolvePromise(VALIDATION_SUCCESS, dfd, this.user);
        })
        .catch(error => {
          // clear any saved session data
          this.invalidateTokens();

          if (this.retrieveData(FIRST_TIME_LOGIN)) {
            this.broadcastEvent(EMAIL_CONFIRMATION_ERROR, resp);
            this.persistData(FIRST_TIME_LOGIN, false);
          }

          if (this.retrieveData(MUST_RESET_PASSWORD)) {
            this.broadcastEvent(PASSWORD_RESET_CONFIRM_ERROR, resp);
            this.persistData(MUST_RESET_PASSWORD, false);
          }

          this.rejectPromise(
            VALIDATION_ERROR,
            dfd,
            resp,
            'Cannot validate token; token rejected by server.'
          );

          return Promise.reject(error);
        });
    }
  }

  // TODO: document
  emailSignUp(options = {}) {
    var config = this.getConfig(options.config),
      url = this.getApiUrl() + config.emailRegistrationPath;

    options.config_name = options.config;
    delete options.config;

    options.confirm_success_url = config.confirmationSuccessUrl();

    return fetch(url, {
      method: 'POST',
      body: options
    })
      .then(response => {
        if (!response.ok) {
          throw response;
        }

        return response.json().then(data => {
          this.broadcastEvent(EMAIL_REGISTRATION_SUCCESS, data);
          return data;
        });
      })
      .catch(error => {
        this.broadcastEvent(EMAIL_REGISTRATION_ERROR, error);
        return Promise.reject(error);
      });
  }

  emailSignIn(options = {}) {
    const config = this.getConfig(opts.config);
    const url = this.getApiUrl() + config.emailSignInPath;

    // don't send config name to API
    delete options.config;

    return fetch(url, {
      method: 'POST',
      body: options
    })
      .then(response => {
        // return user attrs as directed by config
        var user = config.handleLoginResponse(response);

        // save user data, preserve bindings to original user object
        this.setCurrentUser(user);

        this.resolvePromise(EMAIL_SIGN_IN_SUCCESS, dfd, response);
        this.broadcastEvent(SIGN_IN_SUCCESS, user);
        this.broadcastEvent(VALIDATION_SUCCESS, this.user);
      })
      .catch(error => {
        this.rejectPromise(
          EMAIL_SIGN_IN_ERROR,
          dfd,
          error,
          'Invalid credentials.'
        );

        this.broadcastEvent(SIGN_IN_ERROR, resp);
      });
  }

  // ping auth window to see if user has completed authentication.
  // this method will be recursively called until:
  // 1. user completes authentication
  // 2. user fails authentication
  // 3. auth window is closed
  listenForCredentials(popup) {
    var self = this;
    if (popup.closed) {
      self.rejectPromise(
        OAUTH_SIGN_IN_ERROR,
        self.oAuthDfd,
        null,
        'OAuth window was closed bofore registration was completed.'
      );
    } else {
      popup.postMessage('requestCredentials', '*');
      self.oAuthTimer = setTimeout(function() {
        self.listenForCredentials(popup);
      }, 500);
    }
  }

  openAuthWindow(url) {
    if (this.getConfig().forceHardRedirect || isIE()) {
      // redirect to external auth provider. credentials should be
      // provided in location search hash upon return
      this.setLocation(url);
    } else {
      // open popup to external auth provider
      var popup = this.createPopup(url);

      // listen for postMessage response
      this.listenForCredentials(popup);
    }
  }

  buildOAuthUrl(configName, params, providerPath) {
    var oAuthUrl =
      this.getConfig().apiUrl +
      providerPath +
      '?auth_origin_url=' +
      encodeURIComponent(root.location.href) +
      '&config_name=' +
      encodeURIComponent(configName || this.getCurrentConfigName()) +
      '&omniauth_window_type=newWindow';

    if (params) {
      for (var key in params) {
        oAuthUrl += '&';
        oAuthUrl += encodeURIComponent(key);
        oAuthUrl += '=';
        oAuthUrl += encodeURIComponent(params[key]);
      }
    }

    return oAuthUrl;
  }

  oAuthSignIn(opts = {}) {
    if (!opts.provider) {
      throw 'es-toker: provider param undefined for `oAuthSignIn` method.';
    }

    const config = this.getConfig(opts.config);
    const providerPath = config.authProviderPaths[opts.provider];
    const oAuthUrl = this.buildOAuthUrl(opts.config, opts.params, providerPath);

    if (!providerPath) {
      throw 'es-toker: providerPath not found for provider: ' + opts.provider;
    }

    return this.openAuthWindow(oAuthUrl);
  }

  signOut(opts = {}) {
    const config = this.getConfig(opts.config);
    const url = this.getApiUrl() + config.signOutPath;

    return (
      fetch(url, {
        method: 'DELETE'
      })
        .then(response => response.json())
        .then(data => {
          this.resolvePromise(SIGN_OUT_SUCCESS, dfd, data);
        })
        .catch(error => {
          this.rejectPromise(SIGN_OUT_ERROR, dfd, resp, 'Failed to sign out.');
        })
        // finally
        .then(this.invalidateTokens)
    );
  }

  updateAccount(opts = {}) {
    const config = this.getConfig(opts.config);
    const url = this.getApiUrl() + config.accountUpdatePath;

    delete opts.config;

    return fetch(url, {
      method: 'PUT',
      body: opts
    })
      .then(response => response.json())
      .then(data => {
        const user = config.handleAccountUpdateResponse(data);
        this.setCurrentUser(user);
        this.resolvePromise(ACCOUNT_UPDATE_SUCCESS, dfd, data);
      })
      .catch(error => {
        this.rejectPromise(
          ACCOUNT_UPDATE_ERROR,
          dfd,
          error,
          'Failed to update user account'
        );
      });
  }

  destroyAccount(opts = {}) {
    const config = this.getConfig(opts.config);
    const url = this.getApiUrl() + config.accountDeletePath;

    return fetch(url, {
      method: 'DELETE'
    })
      .then(response => response.json())
      .then(data => {
        this.invalidateTokens();
        this.resolvePromise(DESTROY_ACCOUNT_SUCCESS, dfd, data);
      })
      .catch(error => {
        this.broadcastEvent(DESTROY_ACCOUNT_ERROR, error);
        return Promise.reject('Failed to destroy user account', error);
      });
  }

  // TODO: implement re-confirmable on devise_token_auth
  //resendConfirmation(email) {};

  requestPasswordReset(opts = {}) {
    if (opts.email === undefined) {
      throw 'es-toker: email param undefined for `requestPasswordReset` method.';
    }

    const config = this.getConfig(opts.config);
    const url = this.getApiUrl() + config.passwordResetPath;

    opts.config_name = opts.config;
    delete opts.config;

    opts.redirect_url = config.passwordResetSuccessUrl();

    return fetch(url, {
      method: 'POST',
      body: opts
    })
      .then(response => response.json())
      .then(data => {
        this.resolvePromise(PASSWORD_RESET_REQUEST_SUCCESS, dfd, data);
      })
      .catch(error => {
        this.rejectPromise(
          PASSWORD_RESET_REQUEST_ERROR,
          dfd,
          error,
          'Failed to submit email registration.'
        );
      });
  }

  updatePassword(opts = {}) {
    const config = this.getConfig(opts.config);
    const url = this.getApiUrl() + config.passwordUpdatePath;

    delete opts.config;

    return fetch(url, {
      method: 'PUT',
      body: opts
    })
      .then(response => response.json())
      .then(data => {
        this.resolvePromise(PASSWORD_UPDATE_SUCCESS, dfd, data);
      })
      .catch(error => {
        this.rejectPromise(
          PASSWORD_UPDATE_ERROR,
          dfd,
          error,
          'Failed to update password.'
        );
      });
  }

  // TODO: replace with more reliable abstraction using popular storage lib?
  // abstract storing of session data
  persistData(key, val, config) {
    val = JSON.stringify(val);

    switch (this.getConfig(config).storage) {
      case 'localStorage':
        root.localStorage.setItem(key, val);
        break;

      default:
        Cookies.set(key, val, {
          expires: this.getConfig(config).cookieExpiry,
          path: this.getConfig(config).cookiePath
        });
        break;
    }
  }

  // abstract reading of session data
  retrieveData(key) {
    var val = null;
    const storage = this.getConfig().storage;

    if (storage === 'localStorage') {
      val = root.localStorage.getItem(key);
    } else {
      val = Cookies.get(key);
    }

    try {
      return JSON.parse(val);
    } catch (err) {
      return unescapeQuotes(val);
    }
  }

  // this method cannot rely on `retrieveData` because `retrieveData` relies
  // on `getConfig` and we need to get the config name before `getConfig` can
  // be called. TL;DR prevent infinite loop by checking all forms of storage
  // and returning the first config name found
  getCurrentConfigName() {
    var configName = null;

    if (this.getQs().config) {
      configName = this.getQs().config;
    }

    if (Cookies && !configName) {
      configName = Cookies.get(SAVED_CONFIG_KEY);
    }

    if (root.localStorage && !configName) {
      configName = root.localStorage.getItem(SAVED_CONFIG_KEY);
    }

    configName = configName || this.defaultConfigKey || INITIAL_CONFIG_KEY;

    return unescapeQuotes(configName);
  }

  // abstract deletion of session data
  deleteData(key) {
    switch (this.getConfig().storage) {
      case 'cookies':
        Cookies.remove(key, {
          path: this.getConfig().cookiePath
        });
        break;

      default:
        root.localStorage.removeItem(key);
        break;
    }
  }

  // return the current config. config will take the following precedence:
  // 1. config by name saved in cookie / localstorage (current auth)
  // 2. first available configuration
  // 2. default config
  getConfig(key) {
    // configure if not configured
    if (!this.configured) {
      throw 'es-toker: `configure` must be run before using this plugin.';
    }

    // fall back to default unless config key is passed
    key = key || this.getCurrentConfigName();

    return this.configs[key];
  }

  // FIXME: rewrite for fetch
  // send auth credentials with all requests to the API
  appendAuthHeaders(xhr, settings) {
    // fetch current auth headers from storage
    var currentHeaders = AuthInstance.retrieveData(SAVED_CREDS_KEY);

    // check config apiUrl matches the current request url
    if (isApiRequest(settings.url) && currentHeaders) {
      // bust IE cache
      xhr.setRequestHeader(
        'If-Modified-Since',
        'Mon, 26 Jul 1997 05:00:00 GMT'
      );

      // set header for each key in `tokenFormat` config
      for (var key in AuthInstance.getConfig().tokenFormat) {
        xhr.setRequestHeader(key, currentHeaders[key]);
      }
    }
  }

  // FIXME: rewrite for fetch
  // update auth credentials after request is made to the API
  updateAuthCredentials(ev, xhr, settings) {
    // check config apiUrl matches the current response url
    if (isApiRequest(settings.url)) {
      // set header for each key in `tokenFormat` config
      var newHeaders = {};

      // set flag to ensure that we don't accidentally nuke the headers
      // if the response tokens aren't sent back from the API
      var blankHeaders = true;

      // set header key + val for each key in `tokenFormat` config
      for (var key in AuthInstance.getConfig().tokenFormat) {
        newHeaders[key] = xhr.getResponseHeader(key);

        if (newHeaders[key]) {
          blankHeaders = false;
        }
      }

      // persist headers for next request
      if (!blankHeaders) {
        AuthInstance.persistData(SAVED_CREDS_KEY, newHeaders);
      }
    }
  }

  // stub for mock overrides
  getRawSearch() {
    return root.location.search;
  }

  // stub for mock overrides
  getRawAnchor() {
    return root.location.hash;
  }

  setRawAnchor(a) {
    root.location.hash = a;
  }

  getAnchorSearch() {
    var arr = this.getRawAnchor().split('?');
    return arr.length > 1 ? arr[1] : null;
  }

  // stub for mock overrides
  setRawSearch(s) {
    root.location.search = s;
  }

  // stub for mock overrides
  setSearchQs(params) {
    this.setRawSearch(qs.stringify(params));
    return this.getSearchQs();
  }

  setAnchorQs(params) {
    this.setAnchorSearch(qs.stringify(params));
    return this.getAnchorQs();
  }

  // stub for mock overrides
  setLocation(url) {
    root.location.replace(url);
  }

  // stub for mock overrides
  createPopup(url) {
    return root.open(url);
  }

  getSearchQs() {
    var queryString = this.getRawSearch().replace('?', ''),
      qsObj = queryString ? qs.parse(queryString) : {};

    return qsObj;
  }

  getAnchorQs() {
    var anchorQs = this.getAnchorSearch(),
      anchorQsObj = anchorQs ? qs.parse(anchorQs) : {};

    return anchorQsObj;
  }

  // stub for mock overrides
  getQs() {
    return { ...this.getSearchQs(), ...this.getAnchorQs() };
  }
}

export default AuthInstance;
