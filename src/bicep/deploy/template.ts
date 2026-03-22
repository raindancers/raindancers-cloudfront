/**
 * Lightweight Bicep synthesizer for generating Bicep templates from TypeScript.
 * Provides type-safe Bicep generation without requiring external dependencies.
 */

import { ResourceAppId, MicrosoftGraphPermission } from '../resources/graph/types';

export enum BicepParameterType {
  STRING = 'string',
  INT = 'int',
  BOOL = 'bool',
  OBJECT = 'object',
  ARRAY = 'array',
}

export enum BicepExtension {
  MICROSOFT_GRAPH_STABLE = 'br:mcr.microsoft.com/bicep/extensions/microsoftgraph/v1.0:1.0.0',
  KUBERNETES_STABLE = 'Microsoft.KubernetesConfiguration/stable',
}

export interface BicepParameter {
  type: BicepParameterType;
  description?: string;
  defaultValue?: any;
  allowedValues?: any[];
}

export interface BicepResource {
  type: string;
  apiVersion: string;
  name?: string;
  kind?: string;
  location?: string;
  properties?: Record<string, any>;
  dependsOn?: string[];
  comment?: string;
  linterSuppressions?: string[]; // Bicep linter rule codes to suppress for the resource declaration
  propertySuppressions?: Record<string, string[]>; // Property name -> linter codes to suppress
  [key: string]: any;
}

export interface BicepOutput {
  type: BicepParameterType;
  value: string;
}

export interface BicepMetadata {
  name?: string;
  description?: string;
  version?: string;
  cloudformation?: {
    stackArn?: string;
  };
}

export class BicepTemplate {
  private parameters: Map<string, BicepParameter> = new Map();
  private resources: Map<string, BicepResource> = new Map();
  private outputs: Map<string, BicepOutput> = new Map();
  private extensions: Map<string, string> = new Map();
  private metadata: BicepMetadata = {};

  addStringParameter(name: string, description?: string, defaultValue?: string): void {
    this.parameters.set(name, { type: BicepParameterType.STRING, description: description, defaultValue: defaultValue });
  }

  addIntParameter(name: string, description?: string, defaultValue?: number): void {
    this.parameters.set(name, { type: BicepParameterType.INT, description: description, defaultValue: defaultValue });
  }

  addBoolParameter(name: string, description?: string, defaultValue?: boolean): void {
    this.parameters.set(name, { type: BicepParameterType.BOOL, description: description, defaultValue: defaultValue });
  }

  addObjectParameter(name: string, description?: string, defaultValue?: Record<string, any>): void {
    this.parameters.set(name, { type: BicepParameterType.OBJECT, description: description, defaultValue: defaultValue });
  }

  addArrayParameter(name: string, description?: string, defaultValue?: any[]): void {
    this.parameters.set(name, { type: BicepParameterType.ARRAY, description: description, defaultValue: defaultValue });
  }

  addExtension(extension: BicepExtension): void {
    this.extensions.set(extension, extension);
  }

  setMetadata(metadata: BicepMetadata): void {
    this.metadata = metadata;
  }

  addResource(name: string, resource: BicepResource): void {
    const pascalCaseName = this.toPascalCase(name);
    this.resources.set(pascalCaseName, resource);
  }

  addStringOutput(name: string, value: string): void {
    this.outputs.set(name, { type: BicepParameterType.STRING, value: value });
  }

  addIntOutput(name: string, value: string): void {
    this.outputs.set(name, { type: BicepParameterType.INT, value: value });
  }

  addBoolOutput(name: string, value: string): void {
    this.outputs.set(name, { type: BicepParameterType.BOOL, value: value });
  }

  addObjectOutput(name: string, value: string): void {
    this.outputs.set(name, { type: BicepParameterType.OBJECT, value: value });
  }

  addArrayOutput(name: string, value: string): void {
    this.outputs.set(name, { type: BicepParameterType.ARRAY, value: value });
  }

  synthesize(): string {
    const lines: string[] = [];

    // Add header comment
    lines.push('// This template has been automatically synthesized by bicep-cdk');
    lines.push('');

    // Metadata
    lines.push('metadata generator = {');
    lines.push('  name: \'bicep-cdk\'');
    lines.push('  version: \'1.0.0\'');
    lines.push('}');
    lines.push('');

    if (this.metadata.name || this.metadata.description) {
      lines.push('metadata template = {');
      if (this.metadata.name) {
        lines.push(`  name: '${this.metadata.name}'`);
      }
      if (this.metadata.description) {
        lines.push(`  description: '${this.metadata.description}'`);
      }
      lines.push('}');
      lines.push('');
    }

    if (this.metadata.cloudformation?.stackArn) {
      lines.push('metadata cloudformation = {');
      lines.push(`  stackArn: '${this.metadata.cloudformation.stackArn}'`);
      lines.push('}');
      lines.push('');
    }

    // Extensions
    for (const [name] of this.extensions) {
      lines.push(`extension '${name}'`);
    }
    if (this.extensions.size > 0) {
      lines.push('');
    }

    // Parameters
    for (const [name, param] of this.parameters) {
      if (param.description) {
        lines.push(`@description('${param.description}')`);
      }
      if (param.allowedValues) {
        lines.push('@allowed([');
        param.allowedValues.forEach(v => lines.push(`  '${v}'`));
        lines.push('])');
      }
      const defaultVal = param.defaultValue !== undefined
        ? ` = ${this.formatValue(param.defaultValue)}`
        : '';
      lines.push(`param ${name} ${param.type}${defaultVal}`);
      lines.push('');
    }

    // Resources grouped by section
    const resourcesBySection = new Map<string, Array<[string, BicepResource]>>();

    for (const [name, resource] of this.resources) {
      const section = this.getResourceSection(resource.type);
      if (!resourcesBySection.has(section)) {
        resourcesBySection.set(section, []);
      }
      resourcesBySection.get(section)!.push([name, resource]);
    }

    // Output resources grouped by section
    for (const [section, resources] of resourcesBySection) {
      lines.push(...this.formatSectionHeader(section));
      lines.push('');

      for (const [name, resource] of resources) {
        if (resource.linterSuppressions && resource.linterSuppressions.length > 0) {
          resource.linterSuppressions.forEach(code => {
            lines.push(`#disable-next-line ${code}`);
          });
        }
        if (resource.comment) {
          lines.push(`// ${resource.comment}`);
        }

        const resourceType = resource.type.includes('@') ? resource.type : `${resource.type}@${resource.apiVersion}`;
        const resourceDeclaration = resource.existing ? `resource ${name} '${resourceType}' existing = {` : `resource ${name} '${resourceType}' = {`;
        lines.push(resourceDeclaration);

        const knownProps = ['type', 'apiVersion', 'dependsOn', 'comment', 'linterSuppressions', 'propertySuppressions', 'existing'];
        for (const [key, value] of Object.entries(resource)) {
          if (knownProps.includes(key)) continue;
          if (value === undefined) continue;
          if (this.isEmptyValue(value)) continue;

          const camelKey = this.toCamelCase(key);

          // Add property-level linter suppressions
          if (resource.propertySuppressions && resource.propertySuppressions[key]) {
            resource.propertySuppressions[key].forEach(code => {
              lines.push(`  #disable-next-line ${code}`);
            });
          }

          if (key === 'properties' && value) {
            lines.push(`  ${camelKey}: ${this.formatValue(value, 2)}`);
          } else if (key === 'kind') {
            lines.push(`  ${camelKey}: '${value}'`);
          } else if (key === 'location') {
            lines.push(`  ${camelKey}: ${value}`);
          } else {
            lines.push(`  ${camelKey}: ${this.formatValue(value, 2)}`);
          }
        }

        if (resource.dependsOn && resource.dependsOn.length > 0) {
          lines.push('  dependsOn: [');
          resource.dependsOn.forEach(dep => lines.push(`    ${dep}`));
          lines.push('  ]');
        }
        lines.push('}');
        lines.push('');
      }

      lines.push('');
    }

    // Outputs
    if (this.outputs.size > 0) {
      lines.push(...this.formatSectionHeader('Outputs'));
      lines.push('');
    }
    for (const [name, output] of this.outputs) {
      lines.push(`output ${name} ${output.type} = ${output.value}`);
    }

    return lines.join('\n');
  }

  private formatValue(value: any, indent: number = 0): string {
    if (typeof value === 'string') {
      // Check if it's already a quoted Bicep expression with interpolation
      if (value.startsWith("'") && value.endsWith("'")) {
        return value;
      }
      // Check if it's a multi-line script (contains newlines)
      if (value.includes('\n')) {
        // Multi-line string literal
        return `'''\n${value}\n'''`;
      }
      // Check if it's a Bicep function call (e.g., guid(...), tenant(), resourceGroup().location)
      if (/^[a-zA-Z][a-zA-Z0-9]*\(.*\)/.test(value)) {
        return value;
      }
      // Check if it's a nested resource name pattern (e.g., ResourceName.uniqueName/childName)
      if (/^[a-zA-Z][a-zA-Z0-9]*\.[a-zA-Z][a-zA-Z0-9]*\/[^']+$/.test(value)) {
        const [parentRef, childName] = value.split('/');
        return `'\${${parentRef}}/${childName}'`;
      }
      // Check if it's a Bicep property reference (e.g., resourceName.property, resourceName.properties.subProperty)
      if (/^[a-zA-Z][a-zA-Z0-9]*(?:\.[a-zA-Z][a-zA-Z0-9]*)+$/.test(value)) {
        return value;
      }
      // Check if it's a Bicep parameter or simple identifier (e.g., parameterName, location)
      if (/^[a-zA-Z][a-zA-Z0-9]*$/.test(value) && this.parameters.has(value)) {
        return value;
      }
      // Check if it's a known Bicep expression
      if (['location', 'utcValue', 'appName', 'redirectUri', 'signInAudience'].includes(value)) {
        return value;
      }
      // Check if it contains unresolved CDK tokens
      if (value.includes('Token[')) {
        return `'${value}'`;
      }
      // Check if it's a GUID and add comment if known
      if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value)) {
        const comment = this.getGuidComment(value);
        return comment ? `'${value}' // ${comment}` : `'${value}'`;
      }
      // Check if string contains single quotes AND looks like a shell script - use multi-line string
      if (value.includes("'") && (value.includes('az ') || value.includes('echo ') || value.length > 100)) {
        return `'''${value}'''`;
      }
      return `'${value}'`;
    }
    if (typeof value === 'number' || typeof value === 'boolean') {
      return String(value);
    }
    if (Array.isArray(value)) {
      if (value.length === 0) {
        return '[]';
      }
      const itemIndent = ' '.repeat(indent + 2);
      const closeIndent = ' '.repeat(indent);
      const items = value.map(v => `${itemIndent}${this.formatValue(v, indent + 2)}`).join('\n');
      return `[\n${items}\n${closeIndent}]`;
    }
    if (typeof value === 'object') {
      return this.formatObject(value, indent);
    }
    return String(value);
  }

  private formatObject(obj: Record<string, any>, indent: number): string {
    const propIndent = ' '.repeat(indent + 2);
    const closeIndent = ' '.repeat(indent);
    const lines = ['{'];
    for (const [key, value] of Object.entries(obj)) {
      // Special handling for Bicep interpolated keys (e.g., '${Managedidentity.id}' or ${Managedidentity.id})
      if ((key.startsWith("'${") && key.endsWith("}'"))) {
        lines.push(`${propIndent}${key}: ${this.formatValue(value, indent + 2)}`);
        continue;
      }
      if (key.startsWith('${') && key.endsWith('}')) {
        lines.push(`${propIndent}'${key}': ${this.formatValue(value, indent + 2)}`);
        continue;
      }
      if (this.isEmptyValue(value)) continue;
      const camelKey = (key.includes('_') || key.charAt(0) === key.charAt(0).toUpperCase()) ? key : this.toCamelCase(key);
      lines.push(`${propIndent}${camelKey}: ${this.formatValue(value, indent + 2)}`);
    }
    lines.push(`${closeIndent}}`);
    return lines.join('\n');
  }

  private isEmptyValue(value: any): boolean {
    if (value === null || value === undefined) return true;
    if (value === '') return true;
    if (Array.isArray(value) && value.length === 0) return true;
    if (typeof value === 'object' && !Array.isArray(value) && Object.keys(value).length === 0) return true;
    return false;
  }

  private toCamelCase(str: string): string {
    return str.charAt(0).toLowerCase() + str.slice(1);
  }

  private toPascalCase(str: string): string {
    return str
      .split(/[-_\s]+/)
      .map(word => word.charAt(0).toUpperCase() + word.slice(1).toLowerCase())
      .join('')
      .replace(/[^a-zA-Z0-9]/g, '')
      .replace(/^[0-9]/, '_$&');
  }

  private getGuidComment(guid: string): string | null {
    const lowerGuid = guid.toLowerCase();

    if (lowerGuid === ResourceAppId.MICROSOFT_GRAPH.toLowerCase()) {
      return 'Microsoft Graph';
    }

    const permissionMap: Record<string, string> = {
      [MicrosoftGraphPermission.USER_READ]: 'User.Read',
      [MicrosoftGraphPermission.USER_READ_WRITE]: 'User.ReadWrite',
      [MicrosoftGraphPermission.USER_READ_ALL]: 'User.Read.All',
      [MicrosoftGraphPermission.USER_READ_WRITE_ALL]: 'User.ReadWrite.All',
      [MicrosoftGraphPermission.DIRECTORY_READ_ALL]: 'Directory.Read.All',
      [MicrosoftGraphPermission.DIRECTORY_READ_WRITE_ALL]: 'Directory.ReadWrite.All',
      [MicrosoftGraphPermission.GROUP_READ_ALL]: 'Group.Read.All',
      [MicrosoftGraphPermission.GROUP_READ_WRITE_ALL]: 'Group.ReadWrite.All',
      [MicrosoftGraphPermission.MAIL_READ]: 'Mail.Read',
      [MicrosoftGraphPermission.MAIL_READ_WRITE]: 'Mail.ReadWrite',
      [MicrosoftGraphPermission.MAIL_SEND]: 'Mail.Send',
      [MicrosoftGraphPermission.CALENDARS_READ]: 'Calendars.Read',
      [MicrosoftGraphPermission.CALENDARS_READ_WRITE]: 'Calendars.ReadWrite',
      [MicrosoftGraphPermission.FILES_READ]: 'Files.Read',
      [MicrosoftGraphPermission.FILES_READ_WRITE]: 'Files.ReadWrite',
      [MicrosoftGraphPermission.FILES_READ_ALL]: 'Files.Read.All',
      [MicrosoftGraphPermission.FILES_READ_WRITE_ALL]: 'Files.ReadWrite.All',
    };

    for (const [permGuid, name] of Object.entries(permissionMap)) {
      if (permGuid.toLowerCase() === lowerGuid) {
        return name;
      }
    }

    return null;
  }

  private getResourceSection(resourceType: string): string {
    if (resourceType.includes('Microsoft.Graph/groups')) return 'Azure AD Groups';
    if (resourceType.includes('Microsoft.Graph/appRoleAssignedTo')) return 'Group Role Assignments';
    if (resourceType.includes('Microsoft.Graph/applications/federatedIdentityCredentials')) return 'Federated Identity Credentials';
    if (resourceType.includes('Microsoft.Graph/applications')) return 'Azure AD Application';
    if (resourceType.includes('Microsoft.Graph/servicePrincipals')) return 'Service Principal';
    if (resourceType.includes('Microsoft.Compute')) return 'Compute Resources';
    if (resourceType.includes('Microsoft.Network')) return 'Network Resources';
    if (resourceType.includes('Microsoft.Storage')) return 'Storage Resources';
    return 'Resources';
  }

  private formatSectionHeader(title: string): string[] {
    const border = '// ========================================================================';
    const totalWidth = border.length;
    const contentWidth = totalWidth - 5;
    const padding = contentWidth - title.length;
    const leftPad = Math.floor(padding / 2);
    const rightPad = padding - leftPad;
    const centeredTitle = `// =${' '.repeat(leftPad)}${title}${' '.repeat(rightPad)}=`;
    return [border, centeredTitle, border];
  }
}
