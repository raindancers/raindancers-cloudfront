import * as crypto from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

/**
 * Compute a deterministic content hash for a Lambda@Edge asset bundle.
 *
 * Why this exists: `cloudfront.experimental.EdgeFunction` publishes a new
 * `AWS::Lambda::Version` whenever the asset hash changes. Passing a stable
 * `assetHash` with `assetHashType: AssetHashType.CUSTOM` pins the SOURCE
 * identity so unchanged inputs yield an unchanged hash and no new version.
 *
 * NOTE: a CUSTOM assetHash alone is not sufficient for determinism — CDK also
 * folds `JSON.stringify(bundling)` into the final hash (see aws-cdk-lib
 * `AssetStaging.calculateHash`), so any non-deterministic value inside the
 * `bundling` options (e.g. a random `volumes[].hostPath`) still churns the
 * hash. See {@link deterministicConfigDir}, which keeps that path stable.
 *
 * This helper produces a hash from the actual INPUTS — the source directory
 * contents, the generated config, and the optional pre-bundled deps directory —
 * so an unchanged input yields an unchanged hash and no new version. Pass the
 * result as `assetHash` with `assetHashType: AssetHashType.CUSTOM`.
 *
 * Files are hashed in sorted order for determinism. `requirements.txt` is
 * excluded because it is not shipped in the bundle (the bundler skips it).
 */
export function computeEdgeAssetHash(
  sourceDir: string,
  generatedConfig: string,
  bundledDepsDir?: string,
): string {
  const hash = crypto.createHash('sha256');
  hash.update('config\0');
  hash.update(generatedConfig);

  hashDir(hash, sourceDir, 'src', (file) => file === 'requirements.txt');

  if (bundledDepsDir && fs.existsSync(bundledDepsDir)) {
    hashDir(hash, bundledDepsDir, 'dep');
  }

  return hash.digest('hex');
}

/**
 * Create a DETERMINISTIC temp directory holding the generated `config_generated.py`,
 * and return its path. Used as the `hostPath` of the Docker-fallback bundling
 * volume for a Lambda@Edge function.
 *
 * Why this must be deterministic: CDK derives an asset's final hash even under
 * `assetHashType: CUSTOM` by folding `JSON.stringify(bundling)` into the custom
 * hash (see aws-cdk-lib `AssetStaging.calculateHash`). `bundling.volumes[].hostPath`
 * is therefore part of the hash. A random `fs.mkdtempSync(...)` path changes on
 * every synth, so the asset hash — and thus the published S3 key — changes every
 * synth for byte-identical code, publishing a fresh `AWS::Lambda::Version` and
 * forcing a global CloudFront distribution update on EVERY deploy (and orphaning
 * the prior replicated edge version, which cannot be deleted for hours).
 *
 * Keying the directory on `key` (a per-function id) plus the config content keeps
 * it stable for unchanged inputs while staying unique per function.
 */
export function deterministicConfigDir(key: string, configPy: string): string {
  const digest = crypto
    .createHash('sha256')
    .update(`${key}\0`)
    .update(configPy)
    .digest('hex')
    .slice(0, 16);
  const dir = path.join(os.tmpdir(), `raindancers-edge-config-${digest}`);
  fs.mkdirSync(dir, { recursive: true });
  const configPyPath = path.join(dir, 'config_generated.py');
  fs.writeFileSync(configPyPath, configPy);
  return configPyPath;
}

/**
 * Fold every regular file under `dir` (recursively, sorted) into `hash`. Each
 * file contributes its relative path and its bytes under a namespace prefix so
 * that two directories cannot collide and file moves change the hash.
 */
function hashDir(
  hash: crypto.Hash,
  dir: string,
  namespace: string,
  skip?: (relPath: string) => boolean,
): void {
  const walk = (current: string, rel: string): void => {
    const entries = fs.readdirSync(current).sort();
    for (const name of entries) {
      const abs = path.join(current, name);
      const relPath = rel ? `${rel}/${name}` : name;
      const stat = fs.statSync(abs);
      if (stat.isDirectory()) {
        walk(abs, relPath);
      } else if (stat.isFile()) {
        if (skip && skip(relPath)) continue;
        hash.update(`${namespace}\0${relPath}\0`);
        hash.update(fs.readFileSync(abs));
      }
    }
  };
  walk(dir, '');
}
