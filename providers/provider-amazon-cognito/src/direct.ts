import {
  AuthError,
  isRecord,
  type AuthChallengeKind,
  type AuthFlowResult,
  type AuthPlugin,
  type AuthPluginContext,
  type AuthUser,
  type ExternalIdentity,
  type PublicChallenge
} from '@ngriffin_uk/auth-core'
import { createRemoteJwksResolver, verifyJwt, type JwtClaims, type JwtKeyResolver } from '@ngriffin_uk/auth-jwt'

import { CognitoClient, CognitoServiceError } from './cognito-client.js'
import {
  hasRequiredTokenTimes,
  MAX_PARAMETER_COUNT,
  MAX_PARAMETER_LENGTH,
  optionalAuthenticationResult,
  optionalString,
  optionalStringArray,
  optionalStringMap,
  payloadString,
  requiredString,
  validateCognitoStringMap,
  validateCode,
  validateConfig,
  validateMfaSetupLabel,
  validatePassword,
  validateResponse,
  validateToken,
  validateUsername
} from './direct-validation.js'
import type {
  AmazonCognitoDirectOptions,
  CognitoAuthResponse,
  CognitoAuthenticationResult,
  CognitoChoice,
  CognitoDirectOperations,
  CognitoSignUpInput,
  CognitoTokenSet
} from './direct-types.js'

const PROVIDER = 'amazon-cognito'
interface DirectRuntime<User extends AuthUser> {
  readonly context: AuthPluginContext<User>
  readonly config: AmazonCognitoDirectOptions<User>
  readonly client: CognitoClient
  readonly issuer: string
  readonly key: JwtKeyResolver
}

interface StoredChallenge {
  readonly username: string
  readonly session: string
  readonly challengeName: string
}

export function createAmazonCognitoDirectAuth<User extends AuthUser>(
  config: AmazonCognitoDirectOptions<User>
): AuthPlugin<'amazon-cognito', CognitoDirectOperations<User>, User> {
  validateConfig(config)
  return {
    name: PROVIDER,
    install(context) {
      const client = new CognitoClient(config)
      const issuer = `https://cognito-idp.${config.region}.amazonaws.com/${config.userPoolId}`
      const key = createRemoteJwksResolver({
        url: `${issuer}/.well-known/jwks.json`,
        ...(config.fetch ? { fetch: config.fetch } : {}),
        clock: context.now
      })
      const runtime: DirectRuntime<User> = {
        context,
        config,
        client,
        issuer,
        key
      }
      return {
        signUp: (input) => signUp(runtime, input),
        confirmSignUp: (input) => confirmSignUp(runtime, input.token, input.code),
        resendConfirmationCode: (username) => resendConfirmationCode(runtime, username),
        signInPassword: (input) => signInPassword(runtime, input),
        startSignIn: (input) => startSignIn(runtime, input),
        respondToCode: (input) => respondToCode(runtime, input.token, input.code),
        respondToPassword: (input) => respondToPassword(runtime, input.token, input.password),
        respondToNewPassword: (input) => respondToNewPassword(runtime, input),
        selectChallenge: (input) => selectChallenge(runtime, input),
        respondToCustomChallenge: (input) => respondToCustomChallenge(runtime, input.token, input.answer),
        respondToWebAuthn: (input) => respondToWebAuthn(runtime, input.token, input.credential),
        startMfaSetup: (input) => startMfaSetup(runtime, input),
        verifyMfaSetup: (input) => verifyMfaSetup(runtime, input.token, input.code),
        forgotPassword: (username) => forgotPassword(runtime, username),
        confirmForgotPassword: (input) => confirmForgotPassword(runtime, input),
        changePassword: (input) => changePassword(runtime, input),
        refresh: (input) => refresh(runtime, input),
        revokeRefreshToken: (refreshToken) => revokeRefreshToken(runtime, refreshToken),
        signOut: (accessToken) => signOut(runtime, accessToken)
      }
    }
  }
}

async function signUp<User extends AuthUser>(
  runtime: DirectRuntime<User>,
  input: CognitoSignUpInput
): Promise<AuthFlowResult<User>> {
  validateUsername(input.username)
  validatePassword(input.password)
  validateCognitoStringMap(input.attributes)
  validateCognitoStringMap(input.clientMetadata)
  const secretHash = await runtime.client.secretHash(input.username)
  let value: Readonly<Record<string, unknown>>
  try {
    value = await runtime.client.request('SignUp', {
      ClientId: runtime.client.clientId,
      Username: input.username,
      Password: input.password,
      UserAttributes: Object.entries(input.attributes ?? {}).map(([Name, Value]) => ({ Name, Value })),
      ...withOptional('SecretHash', secretHash),
      ...withMetadata(runtime.config.clientMetadata, input.clientMetadata)
    })
  } catch (cause) {
    throw mapServiceError(cause)
  }
  const providerSubject = requiredString(value, 'UserSub')
  const confirmed = value['UserConfirmed'] === true
  await runtime.config.onSignUp?.({
    providerSubject,
    username: input.username,
    confirmed
  })
  if (confirmed) {
    return signInPassword(runtime, {
      username: input.username,
      password: input.password
    })
  }
  return issueEmailVerification(runtime, input.username, value)
}

async function confirmSignUp<User extends AuthUser>(
  runtime: DirectRuntime<User>,
  token: string,
  code: string
): Promise<void> {
  validateCode(code)
  const challenge = await runtime.context.readChallenge(token, PROVIDER, ['email_verification'])
  const username = payloadString(challenge.payload, 'username')
  try {
    await runtime.client.request('ConfirmSignUp', {
      ClientId: runtime.client.clientId,
      Username: username,
      ConfirmationCode: code,
      ...withOptional('SecretHash', await runtime.client.secretHash(username)),
      ...withMetadata(runtime.config.clientMetadata)
    })
    await runtime.context.consumeChallenge(token, PROVIDER, ['email_verification'])
  } catch (cause) {
    throw mapServiceError(cause)
  }
}

async function resendConfirmationCode<User extends AuthUser>(
  runtime: DirectRuntime<User>,
  username: string
): Promise<void> {
  validateUsername(username)
  try {
    await runtime.client.request('ResendConfirmationCode', {
      ClientId: runtime.client.clientId,
      Username: username,
      ...withOptional('SecretHash', await runtime.client.secretHash(username)),
      ...withMetadata(runtime.config.clientMetadata)
    })
  } catch (cause) {
    if (cause instanceof CognitoServiceError && cause.type === 'UserNotFoundException') {
      return
    }
    throw mapServiceError(cause)
  }
}

async function signInPassword<User extends AuthUser>(
  runtime: DirectRuntime<User>,
  input: { readonly username: string; readonly password: string }
): Promise<AuthFlowResult<User>> {
  validateUsername(input.username)
  validatePassword(input.password)
  return initiateAuth(runtime, input.username, 'USER_PASSWORD_AUTH', {
    USERNAME: input.username,
    PASSWORD: input.password
  })
}

async function startSignIn<User extends AuthUser>(
  runtime: DirectRuntime<User>,
  input: {
    readonly username: string
    readonly preferredChallenge?: CognitoChoice
  }
): Promise<AuthFlowResult<User>> {
  validateUsername(input.username)
  return initiateAuth(runtime, input.username, 'USER_AUTH', {
    USERNAME: input.username,
    ...(input.preferredChallenge ? { PREFERRED_CHALLENGE: input.preferredChallenge } : {})
  })
}

async function initiateAuth<User extends AuthUser>(
  runtime: DirectRuntime<User>,
  username: string,
  authFlow: 'USER_AUTH' | 'USER_PASSWORD_AUTH',
  parameters: Readonly<Record<string, string>>
): Promise<AuthFlowResult<User>> {
  const secretHash = await runtime.client.secretHash(username)
  try {
    const value = await runtime.client.request('InitiateAuth', {
      AuthFlow: authFlow,
      ClientId: runtime.client.clientId,
      AuthParameters: {
        ...parameters,
        ...withOptional('SECRET_HASH', secretHash)
      },
      ...withMetadata(runtime.config.clientMetadata)
    })
    return handleAuthResponse(runtime, username, parseAuthResponse(value))
  } catch (cause) {
    if (cause instanceof CognitoServiceError && cause.type === 'UserNotConfirmedException') {
      return issueEmailVerification(runtime, username, {})
    }
    if (cause instanceof CognitoServiceError && cause.type === 'PasswordResetRequiredException') {
      return issuePasswordReset(runtime, username, {})
    }
    throw mapServiceError(cause)
  }
}

async function respondToCode<User extends AuthUser>(
  runtime: DirectRuntime<User>,
  token: string,
  code: string
): Promise<AuthFlowResult<User>> {
  validateCode(code)
  return respond(runtime, token, (challenge) => {
    const fields: Readonly<Record<string, string>> = {
      EMAIL_OTP: 'EMAIL_OTP_CODE',
      EMAIL_MFA: 'EMAIL_MFA_CODE',
      SMS_MFA: 'SMS_MFA_CODE',
      SMS_OTP: 'SMS_OTP_CODE',
      SOFTWARE_TOKEN_MFA: 'SOFTWARE_TOKEN_MFA_CODE'
    }
    const field = fields[challenge.challengeName]
    if (!field) throw new AuthError('challenge_mismatch')
    return { [field]: code }
  })
}

async function respondToPassword<User extends AuthUser>(
  runtime: DirectRuntime<User>,
  token: string,
  password: string
): Promise<AuthFlowResult<User>> {
  validatePassword(password)
  return respond(runtime, token, (challenge) => {
    if (challenge.challengeName !== 'PASSWORD') {
      throw new AuthError('challenge_mismatch')
    }
    return { PASSWORD: password }
  })
}

async function respondToNewPassword<User extends AuthUser>(
  runtime: DirectRuntime<User>,
  input: {
    readonly token: string
    readonly newPassword: string
    readonly attributes?: Readonly<Record<string, string>>
  }
): Promise<AuthFlowResult<User>> {
  validatePassword(input.newPassword)
  validateCognitoStringMap(input.attributes)
  return respond(runtime, input.token, (challenge) => {
    if (challenge.challengeName !== 'NEW_PASSWORD_REQUIRED') {
      throw new AuthError('challenge_mismatch')
    }
    return {
      NEW_PASSWORD: input.newPassword,
      ...Object.fromEntries(
        Object.entries(input.attributes ?? {}).map(([name, value]) => [`userAttributes.${name}`, value])
      )
    }
  })
}

async function selectChallenge<User extends AuthUser>(
  runtime: DirectRuntime<User>,
  input: {
    readonly token: string
    readonly challenge: CognitoChoice | 'SOFTWARE_TOKEN_MFA'
  }
): Promise<AuthFlowResult<User>> {
  return respond(runtime, input.token, (challenge) => {
    if (!['SELECT_CHALLENGE', 'SELECT_MFA_TYPE'].includes(challenge.challengeName)) {
      throw new AuthError('challenge_mismatch')
    }
    return { ANSWER: input.challenge }
  })
}

async function respondToCustomChallenge<User extends AuthUser>(
  runtime: DirectRuntime<User>,
  token: string,
  answer: string
): Promise<AuthFlowResult<User>> {
  validateResponse(answer)
  return respond(runtime, token, (challenge) => {
    if (challenge.challengeName !== 'CUSTOM_CHALLENGE') {
      throw new AuthError('challenge_mismatch')
    }
    return { ANSWER: answer }
  })
}

async function respondToWebAuthn<User extends AuthUser>(
  runtime: DirectRuntime<User>,
  token: string,
  credential: string
): Promise<AuthFlowResult<User>> {
  validateResponse(credential)
  return respond(runtime, token, (challenge) => {
    if (challenge.challengeName !== 'WEB_AUTHN') {
      throw new AuthError('challenge_mismatch')
    }
    return { CREDENTIAL: credential }
  })
}

async function respond<User extends AuthUser>(
  runtime: DirectRuntime<User>,
  token: string,
  response: (challenge: StoredChallenge) => Readonly<Record<string, string>>
): Promise<AuthFlowResult<User>> {
  const record = await runtime.context.readChallenge(token, PROVIDER)
  const challenge = storedChallenge(record.payload)
  const secretHash = await runtime.client.secretHash(challenge.username)
  try {
    const value = await runtime.client.request('RespondToAuthChallenge', {
      ChallengeName: challenge.challengeName,
      ClientId: runtime.client.clientId,
      Session: challenge.session,
      ChallengeResponses: {
        USERNAME: challenge.username,
        ...response(challenge),
        ...withOptional('SECRET_HASH', secretHash)
      },
      ...withMetadata(runtime.config.clientMetadata)
    })
    await runtime.context.consumeChallenge(token, PROVIDER)
    return handleAuthResponse(runtime, challenge.username, parseAuthResponse(value))
  } catch (cause) {
    throw mapServiceError(cause)
  }
}

async function startMfaSetup<User extends AuthUser>(
  runtime: DirectRuntime<User>,
  input: {
    readonly token: string
    readonly accountName: string
    readonly issuer: string
  }
): Promise<AuthFlowResult<User>> {
  validateMfaSetupLabel(input.issuer)
  validateMfaSetupLabel(input.accountName)
  const record = await runtime.context.readChallenge(input.token, PROVIDER, ['mfa_setup'])
  const challenge = storedChallenge(record.payload)
  if (challenge.challengeName !== 'MFA_SETUP') {
    throw new AuthError('challenge_mismatch')
  }
  let value: Readonly<Record<string, unknown>>
  try {
    value = await runtime.client.request('AssociateSoftwareToken', {
      Session: challenge.session
    })
  } catch (cause) {
    throw mapServiceError(cause)
  }
  await runtime.context.consumeChallenge(input.token, PROVIDER, ['mfa_setup'])
  const secret = requiredString(value, 'SecretCode')
  const session = optionalString(value, 'Session') ?? challenge.session
  const issued = await runtime.context.issueChallenge(PROVIDER, 'mfa_setup', {
    username: challenge.username,
    session,
    challengeName: 'MFA_SETUP_VERIFY'
  })
  return {
    status: 'mfa_setup_required',
    challenge: {
      kind: 'mfa_setup',
      continuationToken: issued.token,
      expiresAt: issued.expiresAt,
      parameters: {
        secret,
        uri: totpUri(input.issuer, input.accountName, secret)
      }
    }
  }
}

async function verifyMfaSetup<User extends AuthUser>(
  runtime: DirectRuntime<User>,
  token: string,
  code: string
): Promise<AuthFlowResult<User>> {
  validateCode(code)
  const record = await runtime.context.readChallenge(token, PROVIDER, ['mfa_setup'])
  const challenge = storedChallenge(record.payload)
  if (challenge.challengeName !== 'MFA_SETUP_VERIFY') {
    throw new AuthError('challenge_mismatch')
  }
  try {
    const verified = await runtime.client.request('VerifySoftwareToken', {
      Session: challenge.session,
      UserCode: code
    })
    const session = optionalString(verified, 'Session') ?? challenge.session
    const secretHash = await runtime.client.secretHash(challenge.username)
    const value = await runtime.client.request('RespondToAuthChallenge', {
      ChallengeName: 'MFA_SETUP',
      ClientId: runtime.client.clientId,
      Session: session,
      ChallengeResponses: {
        USERNAME: challenge.username,
        ...withOptional('SECRET_HASH', secretHash)
      },
      ...withMetadata(runtime.config.clientMetadata)
    })
    await runtime.context.consumeChallenge(token, PROVIDER, ['mfa_setup'])
    return handleAuthResponse(runtime, challenge.username, parseAuthResponse(value))
  } catch (cause) {
    throw mapServiceError(cause)
  }
}

async function forgotPassword<User extends AuthUser>(
  runtime: DirectRuntime<User>,
  username: string
): Promise<AuthFlowResult<User>> {
  validateUsername(username)
  let value: Readonly<Record<string, unknown>> = {}
  try {
    value = await runtime.client.request('ForgotPassword', {
      ClientId: runtime.client.clientId,
      Username: username,
      ...withOptional('SecretHash', await runtime.client.secretHash(username)),
      ...withMetadata(runtime.config.clientMetadata)
    })
  } catch (cause) {
    if (!(cause instanceof CognitoServiceError && cause.type === 'UserNotFoundException')) {
      throw mapServiceError(cause)
    }
  }
  return issuePasswordReset(runtime, username, value)
}

async function confirmForgotPassword<User extends AuthUser>(
  runtime: DirectRuntime<User>,
  input: {
    readonly token: string
    readonly code: string
    readonly newPassword: string
  }
): Promise<void> {
  validateCode(input.code)
  validatePassword(input.newPassword)
  const record = await runtime.context.readChallenge(input.token, PROVIDER, ['password_reset'])
  const username = payloadString(record.payload, 'username')
  try {
    await runtime.client.request('ConfirmForgotPassword', {
      ClientId: runtime.client.clientId,
      Username: username,
      ConfirmationCode: input.code,
      Password: input.newPassword,
      ...withOptional('SecretHash', await runtime.client.secretHash(username)),
      ...withMetadata(runtime.config.clientMetadata)
    })
    await runtime.context.consumeChallenge(input.token, PROVIDER, ['password_reset'])
  } catch (cause) {
    throw mapServiceError(cause)
  }
}

async function changePassword<User extends AuthUser>(
  runtime: DirectRuntime<User>,
  input: {
    readonly accessToken: string
    readonly currentPassword: string
    readonly newPassword: string
  }
): Promise<void> {
  validateToken(input.accessToken)
  validatePassword(input.currentPassword)
  validatePassword(input.newPassword)
  try {
    await runtime.client.request('ChangePassword', {
      AccessToken: input.accessToken,
      PreviousPassword: input.currentPassword,
      ProposedPassword: input.newPassword
    })
  } catch (cause) {
    throw mapServiceError(cause)
  }
}

async function refresh<User extends AuthUser>(
  runtime: DirectRuntime<User>,
  input: { readonly username: string; readonly refreshToken: string }
): Promise<AuthFlowResult<User>> {
  validateUsername(input.username)
  validateToken(input.refreshToken)
  const secretHash = await runtime.client.secretHash(input.username)
  try {
    const value = await runtime.client.request('InitiateAuth', {
      AuthFlow: 'REFRESH_TOKEN_AUTH',
      ClientId: runtime.client.clientId,
      AuthParameters: {
        REFRESH_TOKEN: input.refreshToken,
        ...withOptional('SECRET_HASH', secretHash)
      },
      ...withMetadata(runtime.config.clientMetadata)
    })
    const response = parseAuthResponse(value)
    if (!response.AuthenticationResult) throw new AuthError('provider_error')
    return authenticate(runtime, response.AuthenticationResult, input.refreshToken)
  } catch (cause) {
    throw mapServiceError(cause)
  }
}

async function revokeRefreshToken<User extends AuthUser>(
  runtime: DirectRuntime<User>,
  refreshToken: string
): Promise<void> {
  validateToken(refreshToken)
  try {
    await runtime.client.request('RevokeToken', {
      ClientId: runtime.client.clientId,
      Token: refreshToken,
      ...withOptional('ClientSecret', runtime.client.clientSecret())
    })
  } catch (cause) {
    throw mapServiceError(cause)
  }
}

async function signOut<User extends AuthUser>(runtime: DirectRuntime<User>, accessToken: string): Promise<void> {
  validateToken(accessToken)
  try {
    await runtime.client.request('GlobalSignOut', {
      AccessToken: accessToken
    })
  } catch (cause) {
    throw mapServiceError(cause)
  }
}

async function handleAuthResponse<User extends AuthUser>(
  runtime: DirectRuntime<User>,
  username: string,
  response: CognitoAuthResponse
): Promise<AuthFlowResult<User>> {
  if (response.AuthenticationResult) {
    return authenticate(runtime, response.AuthenticationResult)
  }
  if (!response.ChallengeName || !response.Session) {
    throw new AuthError('provider_error')
  }
  const challengeName = response.ChallengeName
  const issued = await runtime.context.issueChallenge(PROVIDER, challengeKind(challengeName), {
    username,
    session: response.Session,
    challengeName,
    parameters: response.ChallengeParameters ?? {},
    availableChallenges: response.AvailableChallenges ?? []
  })
  const parameters = publicParameters(challengeName, response)

  switch (challengeName) {
    case 'EMAIL_MFA':
    case 'EMAIL_OTP':
      return {
        status: 'mfa_challenge_required',
        challenge: makeChallenge('email_otp', issued, parameters)
      }
    case 'SMS_MFA':
      return {
        status: 'mfa_challenge_required',
        challenge: makeChallenge('sms_mfa', issued, parameters)
      }
    case 'SMS_OTP':
      return {
        status: 'mfa_challenge_required',
        challenge: makeChallenge('sms_otp', issued, parameters)
      }
    case 'SOFTWARE_TOKEN_MFA':
      return {
        status: 'mfa_challenge_required',
        challenge: makeChallenge('software_token_mfa', issued, parameters)
      }
    case 'MFA_SETUP':
    case 'SOFTWARE_TOKEN_SETUP':
      return {
        status: 'mfa_setup_required',
        challenge: makeChallenge('mfa_setup', issued, parameters)
      }
    case 'NEW_PASSWORD_REQUIRED':
      return {
        status: 'new_password_required',
        challenge: makeChallenge('new_password', issued, parameters)
      }
    case 'SELECT_CHALLENGE':
    case 'SELECT_MFA_TYPE':
      return {
        status: 'challenge_selection_required',
        challenge: makeChallenge('mfa_selection', issued, parameters)
      }
    case 'CUSTOM_CHALLENGE':
      return {
        status: 'custom_challenge_required',
        challenge: makeChallenge('custom', issued, parameters)
      }
    case 'PASSWORD':
      return {
        status: 'custom_challenge_required',
        challenge: makeChallenge('password', issued, parameters)
      }
    case 'WEB_AUTHN':
      return {
        status: 'webauthn_challenge_required',
        challenge: makeChallenge('webauthn', issued, parameters)
      }
    default:
      return {
        status: 'unsupported_challenge',
        challenge: makeChallenge('unsupported', issued, { challengeName })
      }
  }
}

async function authenticate<User extends AuthUser>(
  runtime: DirectRuntime<User>,
  result: CognitoAuthenticationResult,
  fallbackRefreshToken?: string
): Promise<AuthFlowResult<User>> {
  const accessToken = result.AccessToken
  if (!accessToken || (result.TokenType !== undefined && result.TokenType.toLowerCase() !== 'bearer')) {
    throw new AuthError('provider_error')
  }
  let accessClaims: JwtClaims
  let idClaims: JwtClaims | undefined
  try {
    accessClaims = await verifyJwt(accessToken, {
      algorithms: ['RS256'],
      key: runtime.key,
      issuer: runtime.issuer,
      clock: runtime.context.now
    })
    if (
      accessClaims['token_use'] !== 'access' ||
      accessClaims['client_id'] !== runtime.config.clientId ||
      typeof accessClaims.sub !== 'string' ||
      accessClaims.sub.length === 0 ||
      !hasRequiredTokenTimes(accessClaims)
    ) {
      throw new Error('Access-token claims are invalid.')
    }
    if (result.IdToken) {
      idClaims = await verifyJwt(result.IdToken, {
        algorithms: ['RS256'],
        key: runtime.key,
        issuer: runtime.issuer,
        audience: runtime.config.clientId,
        subject: accessClaims.sub,
        clock: runtime.context.now
      })
      if (idClaims['token_use'] !== 'id' || !hasRequiredTokenTimes(idClaims)) {
        throw new Error('ID-token claims are invalid.')
      }
    }
  } catch (cause) {
    throw new AuthError('provider_error', 'Amazon Cognito returned invalid tokens.', {
      cause
    })
  }
  if (!runtime.context.identities) {
    throw new AuthError('unsupported_operation', 'An identity store is required for Amazon Cognito authentication.')
  }
  const identity: ExternalIdentity = {
    provider: PROVIDER,
    providerSubject: accessClaims.sub,
    ...(typeof idClaims?.['email'] === 'string' ? { email: idClaims['email'] } : {}),
    ...(typeof idClaims?.['email_verified'] === 'boolean' ? { emailVerified: idClaims['email_verified'] } : {}),
    claims: {
      access: accessClaims,
      ...(idClaims ? { id: idClaims } : {})
    }
  }
  const user = await runtime.context.identities.resolve(identity)
  const expiresIn = result.ExpiresIn ?? 3600
  if (!Number.isSafeInteger(expiresIn) || expiresIn <= 0 || expiresIn > 7 * 24 * 60 * 60) {
    throw new AuthError('provider_error')
  }
  const refreshToken = result.RefreshToken ?? fallbackRefreshToken
  const tokens: CognitoTokenSet = {
    accessToken,
    ...(result.IdToken ? { idToken: result.IdToken } : {}),
    ...(refreshToken ? { refreshToken } : {}),
    expiresAt: new Date(runtime.context.now().getTime() + expiresIn * 1000),
    tokenType: result.TokenType ?? 'Bearer'
  }
  await runtime.config.onTokens?.({ user, tokens, identity })
  const session = await runtime.context.issueSession(user.id)
  return {
    status: 'authenticated',
    session: {
      user,
      token: session.token,
      expiresAt: session.expiresAt
    }
  }
}

async function issueEmailVerification<User extends AuthUser>(
  runtime: DirectRuntime<User>,
  username: string,
  response: Readonly<Record<string, unknown>>
): Promise<AuthFlowResult<User>> {
  const issued = await runtime.context.issueChallenge(PROVIDER, 'email_verification', { username })
  return {
    status: 'email_verification_required',
    challenge: {
      kind: 'email_verification',
      continuationToken: issued.token,
      expiresAt: issued.expiresAt,
      parameters: {
        username,
        ...deliveryParameters(response)
      }
    }
  }
}

async function issuePasswordReset<User extends AuthUser>(
  runtime: DirectRuntime<User>,
  username: string,
  response: Readonly<Record<string, unknown>>
): Promise<AuthFlowResult<User>> {
  const issued = await runtime.context.issueChallenge(PROVIDER, 'password_reset', { username })
  return {
    status: 'password_reset_required',
    challenge: {
      kind: 'password_reset',
      continuationToken: issued.token,
      expiresAt: issued.expiresAt,
      parameters: {
        username,
        ...deliveryParameters(response)
      }
    }
  }
}

function challengeKind(
  name: string
):
  | 'custom'
  | 'email_otp'
  | 'mfa_selection'
  | 'mfa_setup'
  | 'new_password'
  | 'password'
  | 'sms_mfa'
  | 'sms_otp'
  | 'software_token_mfa'
  | 'unsupported'
  | 'webauthn' {
  switch (name) {
    case 'EMAIL_MFA':
    case 'EMAIL_OTP':
      return 'email_otp'
    case 'SMS_MFA':
      return 'sms_mfa'
    case 'SMS_OTP':
      return 'sms_otp'
    case 'SOFTWARE_TOKEN_MFA':
      return 'software_token_mfa'
    case 'MFA_SETUP':
    case 'SOFTWARE_TOKEN_SETUP':
      return 'mfa_setup'
    case 'NEW_PASSWORD_REQUIRED':
      return 'new_password'
    case 'SELECT_CHALLENGE':
    case 'SELECT_MFA_TYPE':
      return 'mfa_selection'
    case 'CUSTOM_CHALLENGE':
      return 'custom'
    case 'PASSWORD':
      return 'password'
    case 'WEB_AUTHN':
      return 'webauthn'
    default:
      return 'unsupported'
  }
}

function parseAuthResponse(value: Readonly<Record<string, unknown>>): CognitoAuthResponse {
  const parameters = optionalStringMap(value['ChallengeParameters'])
  const available = optionalStringArray(value['AvailableChallenges'])
  const authentication = optionalAuthenticationResult(value['AuthenticationResult'])
  return {
    ...withOptional('ChallengeName', optionalString(value, 'ChallengeName')),
    ...withOptional('Session', optionalString(value, 'Session')),
    ...(parameters ? { ChallengeParameters: parameters } : {}),
    ...(available ? { AvailableChallenges: available } : {}),
    ...(authentication ? { AuthenticationResult: authentication } : {})
  }
}

function publicParameters(
  challengeName: string,
  response: CognitoAuthResponse
): Readonly<Record<string, string | readonly string[]>> {
  const entries = Object.entries(response.ChallengeParameters ?? {}).filter(([key]) =>
    isPublicChallengeParameter(challengeName, key)
  )
  if (
    entries.length > MAX_PARAMETER_COUNT ||
    entries.some(([key, value]) => key.length > 256 || value.length > MAX_PARAMETER_LENGTH)
  ) {
    throw new AuthError('provider_error')
  }
  return {
    ...Object.fromEntries(entries),
    ...(response.AvailableChallenges ? { availableChallenges: response.AvailableChallenges } : {})
  }
}

function isPublicChallengeParameter(challengeName: string, key: string): boolean {
  switch (challengeName) {
    case 'CUSTOM_CHALLENGE':
      return !/(?:SECRET|SESSION|TOKEN|SRP|SALT)/iu.test(key)
    case 'EMAIL_MFA':
    case 'EMAIL_OTP':
    case 'SMS_MFA':
    case 'SMS_OTP':
    case 'SOFTWARE_TOKEN_MFA':
      return ['CODE_DELIVERY_DELIVERY_MEDIUM', 'CODE_DELIVERY_DESTINATION'].includes(key)
    case 'MFA_SETUP':
    case 'SOFTWARE_TOKEN_SETUP':
      return key === 'MFAS_CAN_SETUP'
    case 'NEW_PASSWORD_REQUIRED':
      return ['requiredAttributes', 'userAttributes'].includes(key)
    case 'SELECT_CHALLENGE':
    case 'SELECT_MFA_TYPE':
      return key === 'MFAS_CAN_SETUP'
    case 'WEB_AUTHN':
      return key === 'CREDENTIAL_REQUEST_OPTIONS'
    default:
      return false
  }
}

function deliveryParameters(value: Readonly<Record<string, unknown>>): Readonly<Record<string, string>> {
  const details = value['CodeDeliveryDetails']
  if (!isRecord(details)) return {}
  return Object.fromEntries(
    ['AttributeName', 'DeliveryMedium', 'Destination'].flatMap((field) => {
      const item = details[field]
      return typeof item === 'string' && item.length <= MAX_PARAMETER_LENGTH
        ? [[field[0]!.toLowerCase() + field.slice(1), item]]
        : []
    })
  )
}

function storedChallenge(payload: Readonly<Record<string, unknown>>): StoredChallenge {
  return {
    username: payloadString(payload, 'username'),
    session: payloadString(payload, 'session'),
    challengeName: payloadString(payload, 'challengeName')
  }
}

function totpUri(issuer: string, accountName: string, secret: string): string {
  if (!/^[A-Z2-7]+=*$/iu.test(secret)) {
    throw new AuthError('provider_error')
  }
  const url = new URL(`otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(accountName)}`)
  url.searchParams.set('secret', secret)
  url.searchParams.set('issuer', issuer)
  return url.href
}

function withMetadata(
  base?: Readonly<Record<string, string>>,
  override?: Readonly<Record<string, string>>
): Readonly<Record<string, unknown>> {
  validateCognitoStringMap(base)
  validateCognitoStringMap(override)
  const metadata = { ...base, ...override }
  return Object.keys(metadata).length > 0 ? { ClientMetadata: metadata } : {}
}

function withOptional<Key extends string, Value>(key: Key, value: Value | undefined): Readonly<Record<string, Value>> {
  return value === undefined ? {} : { [key]: value }
}

function makeChallenge<Kind extends AuthChallengeKind>(
  kind: Kind,
  issued: { readonly token: string; readonly expiresAt: Date },
  parameters: Readonly<Record<string, string | readonly string[]>>
): PublicChallenge<Kind> {
  return {
    kind,
    continuationToken: issued.token,
    expiresAt: issued.expiresAt,
    parameters
  }
}

function mapServiceError(cause: unknown): AuthError {
  if (cause instanceof AuthError) return cause
  if (!(cause instanceof CognitoServiceError)) {
    return new AuthError('provider_error', undefined, {
      cause,
      retryable: true
    })
  }
  switch (cause.type) {
    case 'CodeMismatchException':
    case 'ExpiredCodeException':
    case 'NotAuthorizedException':
    case 'UserNotFoundException':
      return new AuthError('invalid_credentials', undefined, { cause })
    case 'UsernameExistsException':
      return new AuthError('email_in_use', undefined, { cause })
    case 'InvalidParameterException':
    case 'InvalidPasswordException':
      return new AuthError('invalid_input', undefined, { cause })
    case 'LimitExceededException':
    case 'TooManyRequestsException':
      return new AuthError('rate_limited', undefined, {
        cause,
        retryable: true
      })
    default:
      return new AuthError('provider_error', undefined, {
        cause,
        retryable: true
      })
  }
}
