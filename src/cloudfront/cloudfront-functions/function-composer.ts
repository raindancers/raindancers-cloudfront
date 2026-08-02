import * as fs from 'fs';
import * as path from 'path';
import { minify_sync } from 'terser';
import { Extension, ExtensionConfig, RoleMatchMode } from '../patterns/securedCloudFront';

export interface ComposerConfig {
  readonly tenantId?: string;
  readonly cognitoDomain?: string;
  readonly clientId?: string;
  readonly redirectUri?: string;
  readonly cookieDomain?: string;
  readonly requireMfa?: boolean;
  /** Enable header stripping and injection from JWT claims. @default false */
  readonly enableHeaderInjection?: boolean;
  /** Map of header name → JWT claim key. e.g. { 'x-customer-id': 'customer_id' } */
  readonly headerInjectionClaims?: Record<string, string>;
  /** Enable refresh redirect for expired-but-valid tokens. @default false */
  readonly enableRefresh?: boolean;
}

/**
 * Generates a combined CloudFront Function from modular check functions
 * based on requested extensions
 */
export class FunctionComposer {
  private readonly modulesDir: string;

  constructor() {
    this.modulesDir = path.join(__dirname, 'modules');
  }

  /**
   * Generate combined function code based on requested extensions
   */
  public compose(extensions: Extension[], config?: ExtensionConfig, composerConfig?: ComposerConfig): string {
    const parts: string[] = [];

    // Always include shared utilities
    parts.push(this.loadModule('shared-utils.js'));

    // Include required check modules
    const checks: string[] = [];

    if (extensions.includes(Extension.REWRITE_TO_INDEX_HTML)) {
      parts.push(this.loadModule('url-rewrite.js'));
      checks.push('rewrite');
    }

    if (extensions.includes(Extension.REQUIRE_TLS_13)) {
      parts.push(this.loadModule('tls-check.js'));
      checks.push('tls');
    }

    if (extensions.includes(Extension.REQUIRE_AUTH)) {
      const isCognito = composerConfig?.cognitoDomain !== undefined;
      let authModule = this.loadModule(isCognito ? 'cognito-auth-check.js' : 'auth-check.js');
      if (composerConfig) {
        if (composerConfig.cognitoDomain) {
          authModule = authModule.replace(/COGNITO_DOMAIN_PLACEHOLDER/g, composerConfig.cognitoDomain);
        }
        if (composerConfig.tenantId) {
          authModule = authModule.replace(/TENANT_ID_PLACEHOLDER/g, composerConfig.tenantId);
        }
        if (composerConfig.clientId) {
          authModule = authModule.replace(/CLIENT_ID_PLACEHOLDER/g, composerConfig.clientId);
        }
        if (composerConfig.redirectUri) {
          authModule = authModule.replace(/REDIRECT_URI_PLACEHOLDER/g, composerConfig.redirectUri);
        }
        if (composerConfig.cookieDomain !== undefined) {
          authModule = authModule.replace(/COOKIE_DOMAIN_PLACEHOLDER/g, composerConfig.cookieDomain);
        }

        // Header injection placeholders
        const enableHeaderInjection = composerConfig.enableHeaderInjection ?? false;
        authModule = authModule.replace(/ENABLE_HEADER_INJECTION_PLACEHOLDER/g, String(enableHeaderInjection));

        if (enableHeaderInjection && composerConfig.headerInjectionClaims) {
          const map = composerConfig.headerInjectionClaims;
          authModule = authModule.replace(/HEADER_INJECTION_MAP_PLACEHOLDER/g, JSON.stringify(map));
          authModule = authModule.replace(/HEADER_INJECTION_KEYS_PLACEHOLDER/g, JSON.stringify(Object.keys(map)));
        } else {
          authModule = authModule.replace(/HEADER_INJECTION_MAP_PLACEHOLDER/g, '{}');
          authModule = authModule.replace(/HEADER_INJECTION_KEYS_PLACEHOLDER/g, '[]');
        }

        // Refresh redirect placeholder
        const enableRefresh = composerConfig.enableRefresh ?? false;
        authModule = authModule.replace(/ENABLE_REFRESH_PLACEHOLDER/g, String(enableRefresh));
      }
      parts.push(authModule);
      checks.push('auth');
    }

    // Generate handler function
    parts.push(this.generateHandler(checks, config, composerConfig));

    let assembled = parts.join('\n\n');

    // Extract the CloudFront-specific import (terser can't parse ES module imports in script mode).
    // We'll prepend it back after minification.
    const cfImport = "import cf from 'cloudfront';\n";
    assembled = assembled.replace(/import cf from 'cloudfront';\s*/g, '');

    // Also extract `var crypto = require('crypto');` — terser handles it fine but
    // CloudFront Functions need it at the top level.
    const cryptoRequire = "var crypto = require('crypto');\n";
    assembled = assembled.replace(/var crypto = require\('crypto'\);\s*/g, '');

    // Extract KVS handle declaration (depends on cf import)
    const kvsDecl = 'const kvsHandle = cf.kvs();\n';
    assembled = assembled.replace(/const kvsHandle = cf\.kvs\(\);\s*/g, '');

    // Minify with terser to stay well under the 10KB CloudFront Function limit.
    const minified = minify_sync(assembled, {
      compress: {
        dead_code: true,
        drop_console: false,
        passes: 2,
      },
      mangle: {
        reserved: ['handler', 'event', 'kvsHandle'],
      },
      format: {
        comments: false,
      },
    });

    // Prepend the CloudFront-specific preamble back
    const code = cfImport + cryptoRequire + kvsDecl + (minified.code || assembled);
    const sizeKB = Buffer.byteLength(code, 'utf-8') / 1024;

    if (sizeKB > 10) {
      throw new Error(`CloudFront Function exceeds 10KB limit: ${sizeKB.toFixed(2)}KB (extensions: ${extensions.join(', ')})`);
    }

    return code;
  }

  private loadModule(filename: string): string {
    const filePath = path.join(this.modulesDir, filename);
    const content = fs.readFileSync(filePath, 'utf-8');

    return content
      .replace(/\/\*[\s\S]*?\*\//g, '') // block comments
      .replace(/^\s*\/\/.*$/gm, '') // line comments (whole-line only)
      .replace(/^\s*\n/gm, '') // blank lines
      .replace(/function handler\(event\) \{[\s\S]*?\n\}/g, '')
      .replace(/async function handler\(event\) \{[\s\S]*?\n\}/g, '');
  }

  private generateHandler(checks: string[], config?: ExtensionConfig, composerConfig?: ComposerConfig): string {
    const hasAuth = checks.includes('auth');
    const requireMfa = composerConfig?.requireMfa ?? false;
    const lines: string[] = [
      '// Generated handler function',
      hasAuth ? 'async function handler(event) {' : 'function handler(event) {',
      '  var decodedPayload = null;',
      '',
    ];

    // Add TLS check
    if (checks.includes('tls')) {
      lines.push(
        '  // TLS 1.3 enforcement',
        '  var tlsResult = checkTLS(event);',
        '  if (tlsResult) return tlsResult;',
        '',
      );
    }

    // Add auth check (with optional role checking built-in)
    if (hasAuth) {
      const requiredRoles = config?.requiredRoles ? config.requiredRoles : [];
      const matchMode = config?.roleMatchMode || RoleMatchMode.OR;
      const rolesJson = JSON.stringify(requiredRoles);

      lines.push(
        '  // Authentication check',
        `  var requiredRoles = ${rolesJson};`,
        `  var matchMode = '${matchMode}';`,
        '  var authResult = await checkAuth(event, decodedPayload, requiredRoles, matchMode);',
        '  if (!authResult.pass) return authResult.response;',
        '  decodedPayload = authResult.payload;',
        '',
        '  // Inject Azure AD JWT for AssumeRoleWithWebIdentity (Azure only)',
        '  if (typeof injectAzureToken === \'function\') {',
        '    event.request = injectAzureToken(event.request, event.request.cookies);',
        '  }',
        '',
        '  // Inject identity claims as headers for origin (when enabled)',
        '  if (typeof injectClaimsHeaders === \'function\') {',
        '    event.request = injectClaimsHeaders(event.request, decodedPayload);',
        '  }',
        '',
      );

      // MFA enforcement (defence in depth)
      if (requireMfa) {
        lines.push(
          '  // MFA enforcement',
          '  if (decodedPayload) {',
          '    var amr = decodedPayload.amr || [];',
          '    if (amr.indexOf(\'mfa\') === -1) {',
          '      return {',
          '        statusCode: 403,',
          '        statusDescription: \'Forbidden\',',
          '        body: \'Access denied: MFA required\'',
          '      };',
          '    }',
          '  }',
          '',
        );
      }
    }

    // Add URL rewrite after auth so originalPath is saved correctly
    if (checks.includes('rewrite')) {
      lines.push(
        '  rewriteToIndex(event);',
        '',
      );
    }

    lines.push(
      '  // All checks passed',
      '  return event.request;',
      '}',
    );

    return lines.join('\n');
  }
}
