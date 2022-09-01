/**
 * createUserId
 * Uses the username to create a b64, sha256 hash to uniquely identify each user.
 * @param {string} username
 * @returns {string} b64UserId
 */
export function createUserId(citizenName: any): string;
/**
 * storeCryptoAsset
 * @param {string} userId
 * @param {string} type
 * @param {JsonWebKey | CryptoKey | CryptoKeyPair} JWK
 * @return {Promise<boolean>} successFlag
 */
export function storeCryptoAsset(userId: string, type: string, JWK: JsonWebKey | CryptoKey | CryptoKeyPair): Promise<boolean>;
/**
 * getCryptoAsset
 * Used to retrieve from the keyStore_module. Prevents direct accessing of crypto assets.
 * @param {string} userId
 * @param {string} type
 * @return {Promise<CryptoKeyPair | JsonWebKey | CryptoKey | boolean>} Requested asset
 */
export function getCryptoAsset(userId: string, type: string): Promise<CryptoKeyPair | JsonWebKey | CryptoKey | boolean>;
/**
 * getPubSJWK
 * Creates a key pair for signing all messages to the single page application(spa) and stores them by the spa's B64 userId. The pubSJWK_m2spa is then returned for return send to the spa.
* @param {string} userId
* @returns {Promise<JsonWebKey>} pubSJWK_m2spa
*/
export function getPubSJWK(userId: string): Promise<JsonWebKey>;
/**
 * getPubDHJWK
 * Creates a key pair for completing an ECDH with the single page application (spa) and stores them by the spa's B64 userId. The pubDHJWK_m2spa is then returned for return send to the spa.
* @param {string} userId
* @returns {Promise<JsonWebKey>} pubDHJWK_m2spa
*/
export function getPubDHJWK(userId: string): Promise<JsonWebKey>;
/**
 * getSharedSalt
 * Needed for encryption / decryption. Important that it both return it as well as store it for later use attached to the client's id.
 * @param {string} userId
 * @returns {Promise<string>} sharedSalt_b64
 */
export function getSharedSalt(userId: string): Promise<string>;
/**
 * doubleDerivedSharedSecret
 * Preps the module to encrypt / decrype messages.
 * @param {string} userId
 * @returns null
 */
export function doubleDerivedSharedSecret(userId: string): Promise<null>;
/**
 * Used to encrypt plain text strings.
 * @param {string} userId
 * @param {string} plaintext
 * @returns {string} ciphertext_b64
 */
export function symmetricEncrypt(userId: string, plaintext: string): string;
/**
 * symmetricDecrypt
 * Used to decrypt ciphertext strings encoded as base64
 * @param {string} userId
 * @param {string} ciphertext_b64
 * @returns {string} plaintext
 */
export function symmetricDecrypt(userId: string, ciphertext_b64: string): string;
/**
 * signString
 * Generic function for signing any string.
 * @param {string} citizenId
 * @param {string} str (the object you want signed)
 * @returns {string} authSignature_b64
 */
export function signString(citizenId: string, string: any): string;
/**
 * verifySignedString
* Used to verify an encrypted string prior to decryption.
* @param {string} userId
* @param {string} signedString_b64
* @param {string} signature_b64
* @returns {Promise<boolean>} verification
*/
export function verifySignedString(userId: string, signedString_b64: string, signature_b64: string): Promise<boolean>;
/**
* verifySignedObject
* Used to verify an encrypted string prior to decryption.
* @param {string} userId
* @param {string} type (e.g., 'pubSJWK_c2p')
* @param {Object} signedObj
* @param {string} signature_b64
* @returns {Promise<boolean>} verification
*/
export function verifySignedObject(userId: string, keyType: any, signedObj: Object, signature_b64: string): Promise<boolean>;
