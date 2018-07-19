import sinon from 'sinon';
import deepEqual from 'deep-equal';

import Auth from '../src';
import getConfigBase from '../src/constants/get-config-base';

describe('Configuration', () => {
  let server;

  beforeEach(() => {
    server = sinon.fakeServer.create();
    sinon.spy(Auth, 'validateToken');
    sinon.spy(Auth, 'broadcastEvent');
    sinon.spy(Auth, 'configure');
  });

  afterEach(() => {
    server = sinon.fakeServer.restore();
    Auth.configure.restore();
    Auth.broadcastEvent.restore();
    Auth.validateToken.restore();
    Auth.reset();
  });

  it('should be ok: when no session, using no configuration', () => {
    // reset to zero config
    Auth.configure(null, true);

    const expected = getConfigBase();
    const actual = Auth.getConfig();

    expect(expected).toEqual(actual);

    // expect(expected.proxyIf()).toEqual(actual.proxyIf());
    // expect(expected.passwordResetSuccessUrl()).toEqual(
    //   actual.passwordResetSuccessUrl(),
    // );
    // expect(expected.confirmationSuccessUrl()).toEqual(
    //   actual.confirmationSuccessUrl(),
    // );
  });
});

// (
//   (function($) {
//     QUnit.test('scenario 1: ', function(assert) {});

//     QUnit.test('scenario 2a: no session, using custom configuration', function(
//       assert,
//     ) {
//       var apiUrl = '//api.cyclonopedia.dev';

//       Auth.configure({ apiUrl: apiUrl }, true);

//       expect().toEqual(
//         apiUrl,
//         Auth.getConfig().apiUrl,
//         'custom config overrides default settings',
//       );

//       expect().toEqual(
//         defaultConfig.signOutPath,
//         Auth.getConfig().signOutPath,
//         'config retains defalt where not overridden',
//       );

//       assert.ok(
//         Auth.configure.calledOnce,
//         '`configure` was only called once and only once',
//       );
//     });

//     QUnit.test('scenario 2b: no session, using multiple configs', function(
//       assert,
//     ) {
//       var defaultApiUrl = '//api.cyclonopedia.dev',
//         secondApiUrl = '//api.contra3.dev',
//         signOutPath = defaultConfig.signOutPath;

//       Auth.configure(
//         [
//           { first: { apiUrl: defaultApiUrl } },
//           { second: { apiUrl: secondApiUrl } },
//         ],
//         true,
//       );

//       assert.ok(
//         Auth.configure.calledOnce,
//         '`configure` was only called once and only once',
//       );

//       expect().toEqual(
//         defaultApiUrl,
//         Auth.getConfig('first').apiUrl,
//         'first config overrides default settings',
//       );

//       expect().toEqual(
//         secondApiUrl,
//         Auth.getConfig('second').apiUrl,
//         'second config overrides default settings',
//       );

//       expect().toEqual(
//         defaultApiUrl,
//         Auth.getConfig().apiUrl,
//         'first item in config array is used as the default config',
//       );

//       expect().toEqual(
//         signOutPath,
//         Auth.getConfig('first').signOutPath,
//         'first config retains defaults where not overriden',
//       );

//       expect().toEqual(
//         signOutPath,
//         Auth.getConfig('second').signOutPath,
//         'second config retains defaults where not overriden',
//       );
//     });

//     QUnit.test('scenario 3a: recovered session, using custom configs', function(
//       assert,
//     ) {
//       var defaultApiUrl = '//api.cyclonopedia.dev',
//         secondApiUrl = '//api.contra3.dev';

//       Auth.configure(
//         [
//           { first: { apiUrl: defaultApiUrl } },
//           { second: { apiUrl: secondApiUrl } },
//         ],
//         true,
//       );

//       $.cookie('currentConfigName', 'second', { path: '/' });

//       assert.ok(
//         Auth.configure.calledOnce,
//         '`configure` was only called once and only once',
//       );

//       expect().toEqual(
//         Auth.getConfig().apiUrl,
//         secondApiUrl,
//         'current config was recovered from session data',
//       );
//     });

//     QUnit.test('scenario 3a: recovered session, using default config', function(
//       assert,
//     ) {
//       var defaultApiUrl = '//api.cyclonopedia.dev';

//       $.cookie('currentConfigName', 'default', { path: '/' });

//       Auth.configure({ apiUrl: defaultApiUrl }, true);

//       assert.ok(
//         Auth.configure.calledOnce,
//         '`configure` was only called once and only once',
//       );

//       expect().toEqual(
//         Auth.getConfig().apiUrl,
//         defaultApiUrl,
//         'current config was recovered from session data',
//       );
//     });
//   })(jQuery),
// );
