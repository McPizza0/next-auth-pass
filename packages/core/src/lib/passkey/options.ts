import type { Authenticator } from "../../types"
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
} from "@simplewebauthn/server"
import type {
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
} from "@simplewebauthn/server/script/deps"
import {
  assertAdapterImplementsMethods,
  type Adapter,
  type AdapterUser,
} from "../../adapters"
import type { Options } from "./types"
import { randomString } from "../web"
import { MissingAdapter } from "../../errors"

async function getUserAndAuthenticators(
  options: Options,
  email?: string
): Promise<[Authenticator[] | undefined, AdapterUser | null]> {
  const { adapter: _adapter, provider } = options
  const adapter: Adapter | undefined = _adapter

  // Validate that the adapter is defined and implements the required methods
  if (!adapter)
    throw new MissingAdapter(
      "WebaAuthn getUserAndAuthenticators requires an adapter."
    )
  assertAdapterImplementsMethods(
    "WebaAuthn getUserAndAuthenticators requires an adapter that implements",
    adapter,
    ["getUserByEmail", "listLinkedAccounts", "listAuthenticatorsByAccountId"]
  )

  // Get the full user from the email
  const user = email ? await adapter.getUserByEmail(email) : null

  // Find the user's account associated with the provider
  const accounts = user ? (await adapter.listLinkedAccounts(user.id)) ?? [] : []
  const account = accounts.find((a) => a.provider === provider.id)

  // Find the account's authenticators
  const authenticators = account
    ? (await adapter.listAuthenticatorsByAccountId(
      account.providerAccountId
    )) ?? undefined
    : undefined

  return [authenticators, user]
}

/**
 * Generate passkey authentication options.
 * If a user is provided, their credentials will be used to generate the options.
 * Otherwise, allow any credentials.
 *
 * @param options
 * @param email Optional user email to use to generate the options.
 * @returns The options prepared for the client.
 */
export async function authenticationOptions(
  options: Options,
  email?: string
): Promise<PublicKeyCredentialRequestOptionsJSON> {
  const { provider } = options

  // Get the user's authenticators
  const [authenticators] = await getUserAndAuthenticators(options, email)

  // Generate authentication options
  const authOptions = await generateAuthenticationOptions({
    rpID: provider.relayingParty.id,
    allowCredentials: authenticators?.map((a) => ({
      id: a.credentialID,
      type: "public-key",
      transports: a.transports,
    })),
    userVerification: "preferred",
  })

  return authOptions
}

/**
 * Generate passkey registration options.
 * If a user is provided, their credentials will be used to generate the options.
 * Otherwise, their email will be used to generate the options.
 *
 * @param options
 * @param email The user's email to use to generate the options.
 * @returns The options prepared for the client.
 */
export async function registrationOptions(
  options: Options,
  email: string
): Promise<PublicKeyCredentialCreationOptionsJSON> {
  const { provider } = options

  // Get the user authenticators and user object
  const [authenticators, user] = await getUserAndAuthenticators(options, email)

  // Generate a random user ID and name if the user does not exist
  const userID = user?.id ?? randomString(32)
  const userName = user?.name ?? user?.email ?? email
  const userDisplayName = user?.name ?? userName

  // Generate registration options
  const regOptions = await generateRegistrationOptions({
    userID,
    userName,
    userDisplayName,
    rpID: provider.relayingParty.id,
    rpName: provider.relayingParty.name,
    excludeCredentials: authenticators?.map((a) => ({
      id: a.credentialID,
      type: "public-key",
      transports: a.transports,
    })),
    authenticatorSelection: {
      residentKey: "preferred",
      userVerification: "preferred",
      requireResidentKey: true,
    },
  })

  return regOptions
}
