import * as fs from 'fs';
import * as path from 'path';
import { FunctionComposer, minifyFunctionCode } from '../../src/cloudfront/cloudfront-functions/function-composer';
import { Extension } from '../../src/cloudfront/patterns/securedCloudFront';

/**
 * CloudFront Functions have a hard 10KB (10240-byte) code-size limit. Exceeding
 * it fails the deploy with a 413. Both function-generation paths must stay under
 * it, minified:
 *   - the composed multi-module path (FunctionComposer.compose)
 *   - the standalone whole-file auth-check path (loadAndReplaceAuthCheckCode)
 *
 * The standalone path had no test and shipped UN-minified, reaching ~11KB and
 * 413'ing at deploy. These assertions guard against that regressing.
 */
const CLOUDFRONT_FUNCTION_LIMIT = 10240;

describe('CloudFront Function size limit', () => {
  it('composed REQUIRE_AUTH function with header injection stays under 10KB', () => {
    const composer = new FunctionComposer();
    const code = composer.compose([Extension.REQUIRE_AUTH], undefined, {
      tenantId: 'de413a9b-e275-4ae5-8845-21535a89f25c',
      clientId: '872b262d-64c8-449a-91c8-38e13afa3c03',
      redirectUri: 'https://example.com/oauth2/callback',
      cookieDomain: '.example.com',
      enableHeaderInjection: true,
      headerInjectionClaims: {
        'x-oidc-email': 'email',
        'x-oidc-name': 'name',
        'x-oidc-oid': 'oid',
        'x-oidc-preferred-username': 'preferred_username',
      },
    });
    expect(Buffer.byteLength(code, 'utf-8')).toBeLessThan(CLOUDFRONT_FUNCTION_LIMIT);
  });

  it('standalone auth-check.js minified stays well under 10KB', () => {
    // Mirror loadAndReplaceAuthCheckCode's substitutions + minify, so this test
    // covers the exact bytes that path emits without reaching into a private method.
    const authCheckPath = path.join(
      __dirname, '../../src/cloudfront/cloudfront-functions/auth-check.js',
    );
    let code = fs.readFileSync(authCheckPath, 'utf-8');
    const claims = {
      'x-oidc-email': 'email',
      'x-oidc-name': 'name',
      'x-oidc-oid': 'oid',
      'x-oidc-preferred-username': 'preferred_username',
    };
    code = code
      .replace('TENANT_ID_PLACEHOLDER', 'de413a9b-e275-4ae5-8845-21535a89f25c')
      .replace('CLIENT_ID_PLACEHOLDER', '872b262d-64c8-449a-91c8-38e13afa3c03')
      .replace('REDIRECT_URI_PLACEHOLDER', 'https://example.com/oauth2/callback')
      .replace('COOKIE_DOMAIN_PLACEHOLDER', '.example.com')
      .replace(/ENABLE_HEADER_INJECTION_PLACEHOLDER/g, 'true')
      .replace(/HEADER_INJECTION_MAP_PLACEHOLDER/g, JSON.stringify(claims))
      .replace(/HEADER_INJECTION_KEYS_PLACEHOLDER/g, JSON.stringify(Object.keys(claims)))
      .replace(/ENABLE_REFRESH_PLACEHOLDER/g, 'false');
    const body = code
      .replace(/import cf from 'cloudfront';\s*/g, '')
      .replace(/var crypto = require\('crypto'\);\s*/g, '')
      .replace(/const kvsHandle = cf\.kvs\(\);\s*/g, '');
    const minified = "import cf from 'cloudfront';\nvar crypto = require('crypto');\nconst kvsHandle = cf.kvs();\n"
      + minifyFunctionCode(body);
    expect(Buffer.byteLength(minified, 'utf-8')).toBeLessThan(CLOUDFRONT_FUNCTION_LIMIT);
  });

  it('minifyFunctionCode fails loud (throws) on invalid input rather than passing it through', () => {
    // Guards against the old `minified.code || assembled` silent fallback: a
    // minify failure must surface as a build error, never a passed-through
    // oversized blob. terser throws on a parse error; the `result.code`
    // guard covers the return-based failure mode. Either way it must throw.
    expect(() => minifyFunctionCode('const x = ;;; @@@ }{')).toThrow();
  });
});
