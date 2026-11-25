# Hook relay

A way for the session-issuance Lambda@Edge to reach an identity-linking hook that is **not on the internet**.

Lambda@Edge cannot join a VPC, so by default it calls the hook at a public URL (`identityLinkingHookUrl`, with a shared Bearer secret). `HookRelay` is an optional regular Lambda that runs in a VPC. The edge function invokes it with `lambda:Invoke`, and it calls the hook on a private address.

```
Lambda@Edge (session issuance)
   │  lambda:Invoke (IAM)               no public path to the hook
   ▼
HookRelay (Lambda in your VPC)
   │  POST, Authorization: Bearer <web identity token from AWS STS>
   ▼
the hook (private URL)
```

Nothing changes for a stack that does not use it. `identityLinkingHookUrl` and `identityLinkingHookSecretArn` work as before.

## Use it

```ts
const relay = new HookRelay(stack, 'HookRelay', {
  vpc,
  hookUrl: 'http://medusa-api.hermes.internal:9000/hooks/identity-link',
  audience: 'medusa-identity-hook',
  provisionedConcurrency: isProd ? 1 : undefined,   // keep one instance warm in production
  invokeTargetArnSsmParameter: '/hook-relay/prod/invokeTargetArn', // for the edge stack in another region
});

// In the edge stack (us-east-1). The ARN is a string so it can come from SSM, not a stack reference.
new CognitoCustomUiAuth(edgeStack, 'Auth', {
  // ...
  identityLinkingHookRelayArn: ssm.StringParameter.valueForStringParameter(edgeStack, '/hook-relay/prod/invokeTargetArn'),
  identityLinkingHookRelayRegion: 'eu-west-2',
  // identityLinkingHookUrl and identityLinkingHookSecretArn are NOT set.
});
```

Set `identityLinkingHookUrl` **or** `identityLinkingHookRelayArn`, not both. With a relay, `identityLinkingHookSecretArn` is refused.

`relay.invokeTargetArn` is the alias ARN when `provisionedConcurrency` is set, else the function ARN. The issuance role is granted `lambda:InvokeFunction` on exactly the ARN you pass, and nothing else.

## How the hook knows the caller

The relay asks AWS STS for a short-lived token with `GetWebIdentityToken` (IAM outbound identity federation), 5 minutes, `ES384`, for the audience you set. It sends it as the Bearer token. The hook should:

1. fetch the public keys at `<issuer>/.well-known/jwks.json` (cache them; the issuer URL is the one `aws iam enable-outbound-web-identity-federation` returns for the account),
2. check the signature, `iss`, `aud` and `exp`,
3. check the claim `principal_id` under the namespace `https://sts.amazonaws.com/` equals `relay.role.roleArn`.

There is no shared secret. The relay's role may request tokens only for its own audience and for 300 seconds or less.

## Needs

- **Outbound identity federation turned on in the account**, once: `aws iam enable-outbound-web-identity-federation`. `GetWebIdentityToken` is not on the global STS endpoint; the relay uses the regional one (`stsRegion`).
- **A route from the relay's subnets to STS**: NAT, or an STS VPC endpoint. The default subnets are the private subnets with egress.
- **The hook's security group allows the relay's security group** in (`relay.securityGroup`, or the group you pass in).
- **A `boto3` that has `get_web_identity_token`** in the Lambda Python runtime. If the runtime's is older, the relay answers 503 and logs why. This was not checked against the runtime's current boto3 version.

## Latency

A Lambda in a VPC starts more slowly when cold. Set `provisionedConcurrency` to keep instances warm (billed per hour while set; the Lambda free tier does not apply to it). The edge function waits `identityLinkingHookRelayTimeoutSeconds` (default 3) for the relay, and the relay waits `hookTimeoutSeconds` (default 2.5) for the hook. Keep the function `timeout` above the hook timeout. If the relay fails, times out or the hook answers 5xx, no session is issued and the endpoint answers 503 `identity_unavailable`, as for a failing hook today.

The relay keeps its token in memory until it has under a minute left, so a warm instance makes no STS call on a login.

## What it does not do

It does not create the hook, the VPC or the security group rule on the hook's side. It opens no inbound path: no function URL, no API.
