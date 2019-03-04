#!/usr/bin/env node

const execa = require('execa');
const chalk = require('chalk');

function run(command, args = []) {
  console.log(chalk.dim('$ ' + command + ' ' + args.join(' ')));

  let p = execa(command, args);
  p.stdout.pipe(process.stdout);
  p.stderr.pipe(process.stderr);

  return p;
}

(async function() {
  await run('ember', ['browserstack:connect']);

  try {
    try {
      await run('ember', ['test', '-f=permissions', '--c', 'testem.browserstack.js']);

      console.log('success');
      process.exit(0);
    } finally {
      // this needs to be updated to show results in our CI system
      if (process.env.TRAVIS_JOB_NUMBER) {
        await run('ember', ['browserstack:results']);
      }
      await run('ember', ['browserstack:disconnect']);
    }
  } catch (error) {
    console.log('error');
    console.log(error);
    process.exit(1);
  }
})();
