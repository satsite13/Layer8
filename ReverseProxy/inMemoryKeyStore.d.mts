/**
 * Calling this functions initializes the server's private keys.
 */
export function initServerKeys(): void;
/**
 * Creates the server's key pair for signing all future JWTs
 * @returns {null}
 */
export function initServerSigningKeyPair(): null;
/**
 * Simple utility to limit the scope of the 'keyStore_server' to the nodeCryptoModule. Stores JWKs for later use. KeyId is always the b64 sha256Hash of the stingified JWK.
 * @param {string} identifier (e.g., userId)
 * @param {string} pubJWK
 * @returns null
 */
export function storeJWKs(identifier: string, pubJWK: string): Promise<null>;
export let JWTEncryptionKey_s: any;
export let HMACKey_s: any;
export let signingKeyPair_s: any;
export const pubSJWKFromClients: Map<any, any>;
export const keyStore_server: Map<any, any>;
