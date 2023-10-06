import { PasskeyProviderType } from "src/providers/passkey"
import type { InternalOptions, ResponseInternal } from "../../types"
import { SessionStore, signCookie } from "../cookie"
import { session as routesSession } from "./session"
import { authenticationOptions, registrationOptions } from "../passkey/options"
import type {
  PasskeyOptionsCookieData,
  PasskeyOptionsReturn,
} from "../passkey/types"

/**
 * Handle passkey options requests by generating authentication or registration options
 * based on the query parameters and the user's credentials.
 *
 * @param request The incoming request.
 * @param options
 * @returns A response with the options and a signed challenge cookie.
 */
export async function passkeyOptions(
  options: InternalOptions<PasskeyProviderType>,
  sessionStore: SessionStore,
  action?: string,
  queryEmail?: string
): Promise<ResponseInternal<PasskeyOptionsReturn> | ResponseInternal<string>> {
  const { adapter } = options

  let selectedAction = action

  // Get the current session, if it exists
  // NOTE: this is a bit hacky, but routes.session seems to be
  // the only place that implements a full session/user check.
  const { body: currentSession } = await routesSession({
    options,
    sessionStore,
  })
  const sessionUserEmail = currentSession?.user?.email ?? undefined

  // Ignore the email parameter if the user is logged in
  const email = sessionUserEmail ?? queryEmail

  // If the user did not provide an explicit action,
  // we need to figure out what they want to do.
  if (!selectedAction) {
    if (!sessionUserEmail) {
      if (queryEmail) {
        // The user is not logged in and provided an email
        // Let's check if the email is registered
        const user = await adapter?.getUserByEmail(queryEmail)
        if (user) {
          // If the user exists, they want to authenticate
          selectedAction = "authenticate"
        } else {
          // if the user doesn't exist they want to register
          selectedAction = "register"
        }
      } else {
        // The user is not logged in and did not provide an email
        // There is nothing we can do
        return { status: 400, body: "email is required to register" }
      }
    } else {
      if (queryEmail) {
        // The user is logged in and provided an email
        // They probably want to register a new passkey
        selectedAction = "register"
      } else {
        // The user is logged in and did not provide an email
        // This is probably a bad request
        return { status: 400, body: "email is required to register a new passkey" }
      }
    }
  }

  switch (selectedAction) {
    case "authenticate": {
      // Get auth options
      const authOptions = await authenticationOptions(options, email)

      // Set the cookie
      const cookieData: PasskeyOptionsCookieData = {
        challenge: authOptions.challenge,
      }
      const [cookie] = await signCookie("challenge", cookieData, options)

      // Return the options and set the challenge cookie
      return {
        status: 200,
        body: { options: authOptions, action: "authenticate" },
        cookies: [cookie],
      }
    }
    case "register": {
      if (!email) {
        return { status: 400, body: "email is required for registration" }
      }

      const regOptions = await registrationOptions(options, email)

      // Set the cookie
      const cookieData: PasskeyOptionsCookieData = {
        providerAccountId: regOptions.user.id,
        challenge: regOptions.challenge,
      }
      const [cookie] = await signCookie("challenge", cookieData, options)

      // Return the options and set the challenge cookie
      return {
        status: 200,
        body: { options: regOptions, action: "register" },
        cookies: [cookie],
      }
    }
    default: {
      return { status: 400, body: "invalid action" }
    }
  }
}
