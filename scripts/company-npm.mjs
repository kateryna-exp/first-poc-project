import { spawn } from 'node:child_process';
import { reportLockfile } from './report-lockfile.mjs';

const argumentsToNpm = process.argv.slice(2);
if (argumentsToNpm.length === 0) {
  // console.error('Usage: npm run company-npm -- install');
  process.exit(1);
}

const npmExecutable = process.platform === 'win32' ? 'npm.cmd' : 'npm';
const child = spawn(npmExecutable, argumentsToNpm, {
  cwd: process.cwd(),
  env: process.env,
  stdio: 'inherit',
  shell: false,
});

child.on('error', (error) => {
  // console.error(`Unable to start npm: ${error.message}`);
  process.exit(1);
});

child.on('exit', async (code, signal) => {
  if (signal) {
    // console.error(`npm stopped by signal ${signal}`);
    process.exit(1);
  }
  if (code !== 0) process.exit(code ?? 1);

  try {
    await reportLockfile();
  } catch (error) {
    // console.error(`npm succeeded, but dependency reporting failed: ${error.message}`);
    const reportRequired = !['0', 'false', 'no'].includes(
      String(process.env.COMPANY_NPM_REPORT_REQUIRED ?? 'true').toLowerCase(),
    );
    process.exit(reportRequired ? 2 : 0);
  }
});
