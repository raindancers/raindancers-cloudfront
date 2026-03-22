import { typescript } from 'projen';
const project = new typescript.TypeScriptProject({
  authorName: 'Andrew Frazer',
  authorEmail: 'mrpackethead@users.noreply.github.com',
  defaultReleaseBranch: 'main',
  name: 'raindancers-cloudfront',
  projenrcTs: true,
  repository: 'https://github.com/raindancers/raindancers-cloudfront',
  releaseToNpm: true,
  sampleCode: false,
  peerDeps: [
    'aws-cdk-lib@^2.244.0',
    'constructs@^10.5.0',
  ],
  devDeps: [
    'aws-cdk-lib@2.244.0',
    'constructs@10.5.0',
  ],
});

project.addPackageIgnore('.amazonq/');
project.addPackageIgnore('.devcontainer/');

project.synth();