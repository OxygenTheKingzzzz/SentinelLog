/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** Public http(s) API origin. Not a secret. Empty uses the same origin. */
  readonly VITE_API_BASE_URL?: string;
}
