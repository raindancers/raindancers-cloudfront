/**
 * Factory functions for creating CloudFront viewer-request event objects
 * used in auth-check.js unit tests.
 *
 * These fixtures mirror the CloudFront Functions event structure documented at:
 * https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/functions-event-structure.html
 */

export interface CloudFrontCookie {
  readonly value: string;
  readonly attributes?: string;
}

export interface CloudFrontHeader {
  readonly value: string;
}

export interface CloudFrontQueryParam {
  readonly value: string;
  readonly multiValue?: Array<{ value: string }>;
}

export interface CloudFrontRequest {
  readonly method: string;
  readonly uri: string;
  readonly querystring: Record<string, CloudFrontQueryParam>;
  readonly headers: Record<string, CloudFrontHeader>;
  readonly cookies: Record<string, CloudFrontCookie>;
}

export interface CloudFrontEvent {
  readonly context: {
    readonly requestId: string;
  };
  readonly request: CloudFrontRequest;
}

export interface CreateEventOptions {
  /** Request URI path. @default '/' */
  readonly uri?: string;
  /** HTTP method. @default 'GET' */
  readonly method?: string;
  /** Headers to include. @default { host: { value: 'example.com' } } */
  readonly headers?: Record<string, CloudFrontHeader>;
  /** Cookies to include. @default {} */
  readonly cookies?: Record<string, CloudFrontCookie>;
  /** Query string parameters. @default {} */
  readonly querystring?: Record<string, CloudFrontQueryParam>;
  /** CloudFront request ID. @default 'test-request-id' */
  readonly requestId?: string;
}

/**
 * Create a CloudFront viewer-request event with sensible defaults.
 *
 * @param options - Override specific fields of the event
 * @returns A complete CloudFront event object suitable for passing to handler()
 *
 * @example
 * const event = createCloudFrontEvent({ uri: '/account', cookies: { '__Secure-auth_session': { value: token } } });
 */
export function createCloudFrontEvent(options: CreateEventOptions = {}): CloudFrontEvent {
  return {
    context: {
      requestId: options.requestId ?? 'test-request-id',
    },
    request: {
      method: options.method ?? 'GET',
      uri: options.uri ?? '/',
      querystring: options.querystring ?? {},
      headers: options.headers ?? { host: { value: 'example.com' } },
      cookies: options.cookies ?? {},
    },
  };
}

/**
 * Create a CloudFront event with a valid session cookie.
 *
 * @param token - The signed JWT string to include in the session cookie
 * @param options - Additional event options to merge
 * @returns A CloudFront event with the session cookie set
 */
export function createAuthenticatedEvent(token: string, options: CreateEventOptions = {}): CloudFrontEvent {
  return createCloudFrontEvent({
    ...options,
    cookies: {
      '__Secure-auth_session': { value: token },
      ...options.cookies,
    },
  });
}

/**
 * Create a CloudFront event targeting the OAuth2 callback path.
 *
 * @param code - The authorization code from Entra
 * @param state - The state parameter
 * @param cookies - Additional cookies (e.g., oauth_state, code_verifier)
 * @returns A CloudFront event mimicking the Entra redirect back
 */
export function createCallbackEvent(code: string, state: string, cookies: Record<string, CloudFrontCookie> = {}): CloudFrontEvent {
  return createCloudFrontEvent({
    uri: '/oauth2/callback',
    querystring: {
      code: { value: code },
      state: { value: state },
    },
    cookies: cookies,
  });
}
