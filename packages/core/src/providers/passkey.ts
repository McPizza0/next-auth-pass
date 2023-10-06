import type { CommonProviderOptions } from "./index.js"

export type PasskeyProviderType = "passkey"

type RelayingPartyConfig = {
  name: string
  id: string
  origin: string
}

export interface PasskeyConfig extends CommonProviderOptions {
  type: PasskeyProviderType

  /** Relaying party (RP) configuration. */
  relayingParty: RelayingPartyConfig
}

/** The Passkey Provider needs to be configured. */
export type PasskeyInputConfig = Pick<PasskeyConfig, "relayingParty"> &
  Partial<PasskeyConfig>

export default function Passkey(config: PasskeyInputConfig): PasskeyConfig {
  return {
    id: "passkey",
    name: "Passkey",
    ...config,
    type: "passkey",
  }
}
