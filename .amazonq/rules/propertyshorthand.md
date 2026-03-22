Do not use typescript property shorthand and be explict about the property keys and values. 

For example;

Do not do this;

const albWithAuth = new local.patterns.AlbWithEntraAuth(this, 'ALB', {
      vpc,
      azureCredentials,
    });

Do this, even if the property and value are the same

const albWithAuth = new local.patterns.AlbWithEntraAuth(this, 'ALB', {
    vpc: vpc,
    azureCredentials: azureCredentials,
});



