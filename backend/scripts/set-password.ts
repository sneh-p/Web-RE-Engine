import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { hashPassword } from '../src/services/password.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

function promptSecret(promptText: string): Promise<string> {
  return new Promise((resolve) => {
    process.stdout.write(promptText);
    const stdin = process.stdin;

    if (!stdin.isTTY) {
      let data = '';
      stdin.setEncoding('utf8');
      const onData = (chunk: string) => {
        data += chunk;
        const nl = data.indexOf('\n');
        if (nl !== -1) {
          stdin.removeListener('data', onData);
          resolve(data.substring(0, nl).replace(/\r$/, ''));
        }
      };
      stdin.on('data', onData);
      return;
    }

    const wasRaw = stdin.isRaw;
    stdin.setRawMode(true);
    stdin.resume();
    stdin.setEncoding('utf8');
    let input = '';

    const onData = (ch: string) => {
      for (const char of ch) {
        if (char === '\n' || char === '\r' || char === '\u0004') {
          process.stdout.write('\n');
          stdin.removeListener('data', onData);
          stdin.setRawMode(wasRaw ?? false);
          stdin.pause();
          resolve(input);
          return;
        } else if (char === '\u0003') {
          process.stdout.write('\n');
          process.exit(1);
        } else if (char === '\u0008' || char === '\x7f') {
          if (input.length > 0) {
            input = input.slice(0, -1);
          }
        } else {
          input += char;
        }
      }
    };

    stdin.on('data', onData);
  });
}

async function main() {
  let password = process.env.WEB_RE_NEW_PASSWORD;

  if (!password) {
    password = await promptSecret('Enter new password: ');
    const confirm = await promptSecret('Confirm new password: ');

    if (password !== confirm) {
      console.error('Error: Passwords do not match.');
      process.exit(1);
    }
  }

  if (password.length < 12) {
    console.error('Error: Password must be at least 12 characters.');
    process.exit(1);
  }

  const hash = hashPassword(password);
  const envPath = path.resolve(__dirname, '../.env');

  let content = '';
  if (fs.existsSync(envPath)) {
    content = fs.readFileSync(envPath, 'utf-8');
  }

  const lines = content.length > 0 ? content.split('\n') : [];
  let found = false;
  for (let i = 0; i < lines.length; i++) {
    if (lines[i].startsWith('WEB_RE_ADMIN_PASSWORD_HASH=')) {
      lines[i] = `WEB_RE_ADMIN_PASSWORD_HASH=${hash}`;
      found = true;
      break;
    }
  }

  if (!found) {
    if (lines.length > 0 && lines[lines.length - 1] === '') {
      lines[lines.length - 1] = `WEB_RE_ADMIN_PASSWORD_HASH=${hash}`;
      lines.push('');
    } else {
      lines.push(`WEB_RE_ADMIN_PASSWORD_HASH=${hash}`);
      lines.push('');
    }
  }

  const newContent = lines.join('\n');
  fs.writeFileSync(envPath, newContent, { mode: 0o600 });
  try {
    fs.chmodSync(envPath, 0o600);
  } catch {
    // ignore
  }

  console.log('Admin password updated successfully in backend/.env');
}

main().catch((err) => {
  console.error('Failed to set password:', err);
  process.exit(1);
});
