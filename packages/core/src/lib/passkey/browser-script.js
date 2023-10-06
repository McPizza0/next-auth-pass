//@ts-check

// This will be available in the browser
/** @type {import("@simplewebauthn/browser")} */
let SimpleWebAuthnBrowser

/** @typedef {import("./types").PasskeyOptionsAction} PasskeyOptionsAction */
/**
 * @template {PasskeyOptionsAction} T
 * @typedef {import("./types").PasskeyOptionsReturn<T>} PasskeyOptionsReturn
 */

/**
 * passkeyScript is the client-side script that handles the passkey form
 * 
 * @param {string} baseURL is the base URL of the auth API
 */
export async function passkeyScript(baseURL) {
  const startAuthentication = SimpleWebAuthnBrowser.startAuthentication
  const startRegistration = SimpleWebAuthnBrowser.startRegistration

  /**
   * Display an error on the page by redirecting to the same page with an error query parameter
   * 
   * @param {string | Error} message error or error message
   */
  function displayError(message) {
    const url = new URL(window.location.href)
    url.searchParams.set("error", typeof message === "string" ? message : message.message)
    // window.location.search = url.search
  }

  /**
   * Fetch passkey options from the server
   * 
   * @template {PasskeyOptionsAction} T
   * @param {T | undefined} action action to fetch options for
   * @param {string | undefined} email optional user email to fetch options for
   * @returns {Promise<PasskeyOptionsReturn<T> | undefined>}
   */
  async function fetchOptions(action, email) {
    // Create the options URL with the action and email query parameters
    const url = new URL(`${baseURL}/options`)

    if (action) url.searchParams.append("action", action)
    if (email) url.searchParams.append("email", email)

    const res = await fetch(url)
    if (!res.ok) {
      displayError(await res.text() || res.statusText)
      return
    }

    return res.json()
  }

  /**
   * Get the passkey form from the page
   * 
   * @returns {HTMLFormElement}
   */
  function getForm() {
    /** @type {HTMLFormElement | null} */
    const form = document.querySelector("#passkey-form")
    if (!form) throw new Error("Form not found")

    return form
  }

  /**
   * Passkey form submission handler.
   * Takes the input from the form and a few other parameters and submits it to the server.
   * 
   * @param {"GET" | "POST"} method http method to use
   * @param {PasskeyOptionsAction} action action to submit
   * @param {unknown | undefined} data optional data to submit
   * @returns {Promise<Response>}
   */
  function submitForm(method, action, data) {
    const form = getForm()

    // Create a FormData object from the form and
    // append the action
    const formData = new FormData(form)
    const url = new URL(form.action)
    formData.append("action", action)
    
    if (method === "GET") {
      // Add form data to URL
      for (const [key, value] of formData.entries()) {
        if (typeof value !== "string") continue
        url.searchParams.append(key, value)
      }

      if (data) {
        // Add data to URL
        url.searchParams.append("data", JSON.stringify(data))
      }

      return fetch(url)
    }

    // Create a JSON object from the form data
    const bodyJSON = Object.fromEntries(formData.entries())


    // Create the payload and add the data if provided
    /** @type {Record<string, unknown>} */
    const payload = { ...bodyJSON }
    if (data) payload.data = data

    return fetch(url, {
      method,
      body: JSON.stringify(payload),
      headers: {
        "Content-Type": "application/json"
      }
    })
  }

  /**
   * Executes the authentication flow by fetching options from the server,
   * starting the authentication, and submitting the response to the server.
   * 
   * @param {PasskeyOptionsReturn<"authenticate">['options']} options
   * @param {boolean} autofill Whether or not to use the browser's autofill
   * @returns {Promise<void>}
   */
  async function authenticationFlow(options, autofill) {
    // Get email from form
    const form = getForm()
    /** @type {string | undefined} */
    const email = form.email ? form.email.value : undefined

    // Start authentication
    const authResp = await startAuthentication(options, autofill)

    // Submit authentication response to server
    const res = await submitForm("POST", "authenticate", authResp)
    if (!res.ok) {
      throw new Error(`Failed to submit authentication response. email: "${email}", autofill: "${autofill}", status: "${res.status}", error: "${await res.text()}"`)
    }
    
    return
  }

  /**
   * @param {PasskeyOptionsReturn<"register">['options']} options
   */
  async function registrationFlow(options) {
    // Get email from form
    const form = getForm()
    /** @type {string | undefined} */
    const email = form.email ? form.email.value : undefined
    if (!email) throw new Error("Register email not provided")

    // Start registration
    const regResp = await startRegistration(options)

    // Submit registration response to server
    const res = await submitForm("POST", "register", regResp)
    if (!res.ok) {
      throw new Error(`Failed to submit registration response. email: "${email}", status: "${res.status}", error: "${await res.text()}"`)
    }

    return
  }

  /**
   * Attempts to authenticate the user when the page loads
   * using the browser's autofill popup.
   * 
   * @returns {Promise<void>}
   */
  async function autofillAuthentication() {
    const res = await fetchOptions("authenticate", undefined)
    if (!res) {
      console.error("Failed to fetch option for autofill authentication")

      return
    }

    try {
      await authenticationFlow(res.options, true)
    } catch (/** @type {any} */ e) {
      console.error(e)
      displayError(e)
    }
  }

  /**
   * Sets up the passkey form by overriding the form submission handler
   * so that it attempts to authenticate the user when the form is submitted.
   * If the user is not registered, it will attempt to register them.
   */
  async function setupForm() {
    const form = getForm()

    if (form) {
      form.addEventListener("submit", async (e) => {
        e.preventDefault()

        // Fetch options from the server without assuming that
        // the user is registered
        const res = await fetchOptions(undefined, form.email.value)
        if (!res) {
          console.error("Failed to fetch options for form submission")

          return
        }

        // Then execute the appropriate flow
        if (res.action === "authenticate") {
          try {
            await authenticationFlow(res.options, false)
          } catch (/** @type {any} */ e) {
            console.error(e)
            displayError(e)
          }
        } else if (res.action === "register") {
          try {
            await registrationFlow(res.options)
          } catch (/** @type {any} */ e) {
            console.error(e)
            displayError(e)
          }
        }
      })
    }
  }

  // On page load, setup the form and attempt to authenticate the user.
  setupForm()
  autofillAuthentication()
}
