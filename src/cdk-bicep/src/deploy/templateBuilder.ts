import { BicepTemplate, BicepExtension, BicepMetadata } from './template';

/**
 * Fluent builder for creating Bicep templates with a CDK-idiomatic approach
 */
export class BicepTemplateBuilder {
  private template = new BicepTemplate();
  private outputKeys: string[] = [];

  withMetadata(metadata: BicepMetadata): this {
    this.template.setMetadata(metadata);
    return this;
  }

  withExtensions(...extensions: BicepExtension[]): this {
    extensions.forEach(ext => this.template.addExtension(ext));
    return this;
  }

  withResources(buildFn: (template: BicepTemplate) => void): this {
    buildFn(this.template);
    return this;
  }

  withOutputs(outputs: Record<string, string>): this {
    this.outputKeys = Object.keys(outputs);
    Object.entries(outputs).forEach(([name, value]) =>
      this.template.addStringOutput(name, value),
    );
    return this;
  }

  build(): { template: BicepTemplate; outputKeys: string[] } {
    return { template: this.template, outputKeys: this.outputKeys };
  }
}
