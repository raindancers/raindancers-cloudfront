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

// Pre-bundle Python Lambda dependencies for Linux x86_64 (Lambda target).
// This eliminates Docker from cdk synth for consumers of this library.
const lambdaBundles = [
  { name: 'edge-auth', path: 'src/cloudfront/lambda/edge-auth/requirements.txt' },
  { name: 'cognito-auth', path: 'src/cloudfront/lambda/cognito-auth/requirements.txt' },
  { name: 'hmacSecret', path: 'src/cloudfront/lambda/hmacSecret/requirements.txt' },
];

for (const bundle of lambdaBundles) {
  project.compileTask.exec(
    `pip install -r ${bundle.path} --target lib/cloudfront/lambda-bundled/${bundle.name} --upgrade --platform manylinux2014_x86_64 --only-binary=:all: --python-version 3.12 --implementation cp --quiet`,
  );
}

// Allow non-JS/DTS asset files in the npm package
project.addPackageIgnore('!/lib/**/*.py');
project.addPackageIgnore('!/lib/**/*.sh');
project.addPackageIgnore('!/lib/**/requirements.txt');
project.addPackageIgnore('!/lib/**/Dockerfile');
project.addPackageIgnore('!/lib/**/host.json');
// Include pre-bundled Lambda dependencies
project.addPackageIgnore('!/lib/**/lambda-bundled/**');

project.synth();