import * as fs from 'fs';
import * as path from 'path';
import { Extension, ExtensionConfig, RoleMatchMode } from '../patterns/securedCloudFront';

export interface ComposerConfig {
  readonly tenantId?: string;
  readonly cognitoDomain?: string;
  readonly clientId?: string;
  readonly redirectUri?: string;
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
      }
      parts.push(authModule);
      checks.push('auth');
    }

    // Generate handler function
    parts.push(this.generateHandler(checks, config));

    const code = parts.join('\n\n');
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
      .replace(/\/\*[\s\S]*?\*\//g, '')        // block comments
      .replace(/^\s*\/\/.*$/gm, '')             // line comments (whole-line only)
      .replace(/^\s*\n/gm, '')                 // blank lines
      .replace(/function handler\(event\) \{[\s\S]*?\n\}/g, '')
      .replace(/async function handler\(event\) \{[\s\S]*?\n\}/g, '');
  }

  private generateHandler(checks: string[], config?: ExtensionConfig): string {
    const hasAuth = checks.includes('auth');
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
      );
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
