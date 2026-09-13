import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';

/**
 * Compute a deterministic content hash for a Lambda@Edge asset bundle.
 *
 * Why this exists: `cloudfront.experimental.EdgeFunction` publishes a new
 * `AWS::Lambda::Version` whenever the asset hash changes. When the asset is
 * created via `lambda.Code.fromAsset(dir, { bundling })` WITHOUT an explicit
 * `assetHash`, CDK falls back to hashing the bundling OUTPUT — and the local
 * bundler here copies files with `fs.cpSync`, which does not reproduce a
 * byte-identical tree across synths (mtimes/ordering drift). The result is a
 * fresh edge-Lambda version on EVERY deploy even when the code is unchanged,
 * each of which forces a global CloudFront re-association + propagation and
 * locks the prior version from deletion (it also slowly fills the regional
 * Lambda storage quota).
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
