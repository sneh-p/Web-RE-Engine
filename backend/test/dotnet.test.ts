import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import { execFileSync } from 'child_process';
import { runDotNetAnalysis } from '../src/services/dotnet.js';
import { detectFileType } from '../src/services/detector.js';
import { fixtureDir, hasTool } from './fixtures.js';

test('dotnet: ILSpy lists types with their kinds and decompiles a browsable C# project', { timeout: 300_000 }, async (t) => {
  if (!hasTool('dotnet') || !hasTool('ilspycmd')) return t.skip('dotnet SDK or ilspycmd not installed');

  const dir = fixtureDir('dotnet');
  const env = { ...process.env, DOTNET_CLI_TELEMETRY_OPTOUT: '1', DOTNET_NOLOGO: '1', HOME: dir };
  execFileSync('dotnet', ['new', 'classlib', '-n', 'Sample', '-o', path.join(dir, 'src')], { env, stdio: 'ignore' });
  fs.writeFileSync(
    path.join(dir, 'src/Class1.cs'),
    'namespace Demo.Lib { public interface IChannel { string Send(string d); } public class Gate : IChannel { public string Send(string d) => "http://203.0.113.7/gate" + d; } public enum Mode { Idle, Exfil } }'
  );
  execFileSync('dotnet', ['build', path.join(dir, 'src'), '-c', 'Release', '-o', path.join(dir, 'out')], { env, stdio: 'ignore' });

  const dll = path.join(dir, 'out/Sample.dll');
  assert.equal(detectFileType(dll, 'Sample.dll'), 'dotnet');

  const { result, extractedPath } = await runDotNetAnalysis({ type: 'dotnet', fileName: 'Sample.dll', fileSize: 0, filePath: dll }, () => {});
  const demo = result.namespaces.find((n) => n.name === 'Demo.Lib');
  assert.deepEqual(
    Object.fromEntries((demo?.types ?? []).map((t) => [t.name, t.kind])),
    { IChannel: 'interface', Gate: 'class', Mode: 'enum' }
  );
  assert.ok(extractedPath && fs.readFileSync(path.join(extractedPath, 'Demo.Lib/Gate.cs'), 'utf8').includes('http://203.0.113.7/gate'));
  assert.deepEqual(result.limitations, []);
});
