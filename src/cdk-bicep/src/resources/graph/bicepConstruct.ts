import { BicepTemplate } from '../../deploy/template';

/**
 * Base class for Bicep constructs - provides CDK-like experience for Bicep resources
 */
export abstract class BicepConstruct {
  protected template: BicepTemplate;
  protected resourceName: string;
  protected explicitDependencies: string[] = [];

  constructor(template: BicepTemplate, resourceName: string) {
    this.template = template;
    this.resourceName = resourceName;
  }

  public getResourceName(): string {
    return this.toPascalCase(this.resourceName);
  }

  public addDependency(resource: BicepConstruct): void {
    this.explicitDependencies.push(resource.getResourceName());
  }

  protected toPascalCase(str: string): string {
    return str
      .split(/[-_\s]+/)
      .map(word => word.charAt(0).toUpperCase() + word.slice(1).toLowerCase())
      .join('')
      .replace(/[^a-zA-Z0-9]/g, '')
      .replace(/^[0-9]/, '_$&');
  }

  abstract synthesize(): void;
}
