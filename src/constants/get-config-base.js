const root = window;

export default () => ({
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
    uid: '{{ uid }}',
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
    google: '/auth/google_oauth2',
  },
});
