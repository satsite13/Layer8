/**
 * getPubSJWK_s
 * Returns the servers pubSJWK for all future signatures so that the client can verify the same.
 * @returns {Promise<JWK>} the proxy's pubSJWK
 */
export function getPubSJWK_s(): Promise<JWK>;
/**
 * User schema: {userId, username, hashedPassword_b64, userSalt_b64, identities}
 * @param {IUser} user
 * @returns {IHalfJWT} halfJWT
 */
export function createHalfJWT(user: IUser): IHalfJWT;
/**
 * signObject
 * Generic function for signing any object.
 * @param {object} object (the object you want signed)
 * @returns {string} authSignature_b64
 */
export function signObject(object: object): string;
/**
 * verifySignature
 * Use to authenticate the signature of an object.
 * @param {object} object
 * @param {JsonWebKey} pubSJWK
 * @param {string} signature_b64 <b64>
 * @return {Promise<boolean>}
 */
export function verifySignedObject(object: object, pubSJWK: JsonWebKey, signature_b64: string): Promise<boolean>;
/**
 * verifyMac
 * Use to verify the MAC of the Half JWT coming from the client.
 * @param {string} MAC <b64>
 * @param {string} cipherTextToVerify_b64
 * @return {boolean} result
 */
export function verifyMAC(MAC: string, cipherTextToVerify_b64: string): boolean;
/**
 * The final check before accepting the client's JWT, internal message must decrypt appropriately using the servers AES key.
 * @param {string} cipherText: b64string
 * @returns {Promise<IPayload>} plaintext_JSON_obj
 */
export function verifyAndDecryptCipherText(cipherText: string): Promise<IPayload>;
/**
 * buildFullJWT
 * If the Half JWT passes all three tests, the next step is to return a full JWT to the client so that they can store it and know who they are and verify all future transactions.
 * @param {IUser} storedUserObject
 * @param {string} chosenIdentity
 * @return {object} fullJWT
 */
export function buildFullJWT(storedUserObject: IUser, chosenIdentity: string): object;
