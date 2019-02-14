const config = {
  framework: 'qunit',
  test_page: 'tests/index.html?hidepassed',
  tap_quiet_logs: true,
  disable_watching: true,
  timeout: 60,
  launchers: {
    bs_chrome: {
      exe: 'node_modules/.bin/browserstack-launch',
      args: ['--os', 'Windows', '--osv', '10', '--b', 'chrome', '--bv', 'latest', '-t', '600', '--u'],
      protocol: 'browser',
    },
  },
  launch_in_ci: ['bs_chrome'],
  on_exit:
    '[ -e ../../vault-ui-integration-server.pid ] && node ../../scripts/start-vault.js `cat ../../vault-ui-integration-server.pid`; [ -e ../../vault-ui-integration-server.pid ] && rm ../../vault-ui-integration-server.pid',
  proxies: {
    '/v1': {
      target: 'http://localhost:9200',
    },
  },
};

if (process.env.CI) {
  config.reporter = 'xunit';
  config.report_file = 'test-reports/ember.xml';
  config.xunit_intermediate_output = true;
}

module.exports = config;
