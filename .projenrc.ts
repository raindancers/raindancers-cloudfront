import { typescript } from 'projen';
const project = new typescript.TypeScriptProject({
  authorName: 'Andrew Frazer',
  authorEmail: 'mrpackethead@users.noreply.github.com',
  defaultReleaseBranch: 'main',
  name: 'raindancers-cloudfront',
  projenrcTs: true,
  repository: 'https://github.com/raindancers/raindancers-cloudfront',
  releaseToNpm: true,
  npmProvenance: false,
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

// Copy non-TypeScript assets (Lambda code, CloudFront functions, scripts) to lib/ after compile
project.compileTask.exec(
  'rsync -av --include="*/" --include="*.py" --include="*.js" --include="requirements.txt" --include="Dockerfile" --include="host.json" --include="*.sh" --exclude="*.ts" --exclude="*.d.ts" --exclude="*.js.map" src/ lib/',
);

// Allow non-JS/DTS asset files in the npm package
project.addPackageIgnore('!/lib/**/*.py');
project.addPackageIgnore('!/lib/**/*.sh');
project.addPackageIgnore('!/lib/**/requirements.txt');
project.addPackageIgnore('!/lib/**/Dockerfile');
project.addPackageIgnore('!/lib/**/host.json');

project.synth();