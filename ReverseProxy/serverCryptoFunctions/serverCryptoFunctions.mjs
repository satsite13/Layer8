// This file houses all of the server's crypto functionality.
import { webcrypto } from "crypto";
import { b64ToUint8Arr, uInt8ArrToB64} from "./b64_utils.mjs";
import { JWTEncryptionKey_s, HMACKey_s, signingKeyPair_s } from "../inMemoryKeyStore.mjs";


/**
 * getPubSJWK_s
 * Returns the servers pubSJWK for all future signatures so that the client can verify the same.
 * @returns {Promise<JWK>} the proxy's pubSJWK
 */

export async function getPubSJWK_s(){
  const pubSJWK_s = await webcrypto.subtle.exportKey("jwk", signingKeyPair_s.publicKey);
  return pubSJWK_s;
}

/**
 * User schema: {userId, username, hashedPassword_b64, userSalt_b64, identities}
 * @param {IUser} user
 * @returns {IHalfJWT} halfJWT
 */
 export async function createHalfJWT(user){
  const JWTHeader = {
    "typ": "halfJWT",
    "sig": "HMAC-SHA256"
  }

  // Create and encrypt the JWT payload
  const halfJWTpayload = {
    "username": user.username,
    "userId": user.userId,
    "expiry": 100000,
    "data": null
  }

  const iv = new Uint8Array(16);

  webcrypto.getRandomValues(iv);

  const payload_cipher = await webcrypto.subtle.encrypt(
    {name: "AES-CBC", iv: iv},
    JWTEncryptionKey_s,
    JSON.stringify(halfJWTpayload)
  );

  const ivedPayload_cipher_uInt8 = new Uint8Array([ // ([Uint8Array, Uint8Array])
    ...iv,
    ...new Uint8Array(payload_cipher)
  ]);

  const HMAC = await webcrypto.subtle.sign(
    {
      name: "HMAC",
      hash: "SHA-256",
      length: 256
    },
    HMACKey_s,
    ivedPayload_cipher_uInt8
  );

  const ivedPayload_cipher_b64 = uInt8ArrToB64(new Uint8Array(ivedPayload_cipher_uInt8));

  const HMAC_b64 = uInt8ArrToB64(new Uint8Array(HMAC));

  // Assemble the final halfJWT
  // A halfJWT is missing the user's chosen identity.
  const halfJWT = {
    JWTHeader,
    ivedPayload_cipher_b64,
    HMAC_b64
  }

  return halfJWT;
}

/**
 * signObject
 * Generic function for signing any object.
 * @param {object} object (the object you want signed)
 * @returns {string} authSignature_b64
 */
 export async function signObject(object){
  const object_uInt8 = new TextEncoder().encode(JSON.stringify(object));

  const authSignature_s = await webcrypto.subtle.sign(
    {
      name: "ECDSA",
      hash: "SHA-256"
    },
    signingKeyPair_s.privateKey, // imported from "../inMemoryKeyStore.mjs"
    object_uInt8
  );

  const authSignature_b64 = uInt8ArrToB64(new Uint8Array(authSignature_s));

  return authSignature_b64;
}

/**
 * verifySignature
 * Use to authenticate the signature of an object.
 * @param {object} object
 * @param {JsonWebKey} pubSJWK
 * @param {string} signature_b64 <b64>
 * @return {Promise<boolean>}
 */

export async function verifySignedObject(object, pubSJWK, signature_b64){
  const stringifiedObject = JSON.stringify(object);
  const signature_uInt8 = b64ToUint8Arr(signature_b64, 0);
  const pubSKey_s = await webcrypto.subtle.importKey(
    "jwk",
    pubSJWK,
    {
    name: "ECDSA",
    namedCurve: "P-256",
    },
    false,
    ['verify']
  );
  const textToVerify = new TextEncoder().encode(stringifiedObject);
  const verification = await webcrypto.subtle.verify(
    {
      name: "ECDSA",
      hash: "SHA-256"
    },
    pubSKey_s, // Server's public ECDSA key
    signature_uInt8, // Server's signature
    textToVerify // Encrypted object
  )
  return verification;
}

/**
 * verifyMac
 * Use to verify the MAC of the Half JWT coming from the client.
 * @param {string} MAC <b64>
 * @param {string} cipherTextToVerify_b64
 * @return {boolean} result
 */
 export async function verifyMAC(MAC, cipherTextToVerify_b64){
  const tag = b64ToUint8Arr(MAC);
  const ivedPayload_cipher_uInt8 = b64ToUint8Arr(cipherTextToVerify_b64);

  const result = await webcrypto.subtle.verify(
    {
      name: "HMAC",
    },
    HMACKey_s,
    tag,
    ivedPayload_cipher_uInt8
  );

  return result;
}

/**
 * The final check before accepting the client's JWT, internal message must decrypt appropriately using the servers AES key.
 * @param {string} cipherText: b64string
 * @returns {Promise<IPayload>} plaintext_JSON_obj
 */
 export async function verifyAndDecryptCipherText(cipherText){
  const ivedPayload_cipher_uInt8 = b64ToUint8Arr(cipherText);
  const iv = ivedPayload_cipher_uInt8.slice(0, 16);
  const cipherText_uInt8 = ivedPayload_cipher_uInt8.slice(16);

  try{
    const decryptedBuffer = await webcrypto.subtle.decrypt(
      {
        name: "AES-CBC",
        iv: iv
      },
      JWTEncryptionKey_s,
      cipherText_uInt8
    );

    const decryptedString = new TextDecoder().decode(decryptedBuffer);

    return JSON.parse(decryptedString);
  } catch(err){
    throw new Error("The extracted cipher text failed to decrypt while verifying the client's hafl JWT.");
  }
}


/**
 * buildFullJWT
 * If the Half JWT passes all three tests, the next step is to return a full JWT to the client so that they can store it and know who they are and verify all future transactions.
 * @param {IUser} storedUserObject
 * @param {string} chosenIdentity
 * @return {IFullJWT} fullJWT
 */
 export async function buildFullJWT(storedUserObject, chosenIdentity){

  const JWTHeader = {
    "typ": "fullJWT",
    "sig": "HMAC-SHA256"
  }

  const fullPayload = {
    "userId": storedUserObject.userId,
    "username": storedUserObject.username,
    "chosenIdentity": chosenIdentity
  }

  const iv = new Uint8Array(16);
  webcrypto.getRandomValues(iv);

  const payload_cipher = await webcrypto.subtle.encrypt(
    {name: "AES-CBC", iv: iv},
    JWTEncryptionKey_s,
    JSON.stringify(fullPayload)
  );

  const ivedPayload_cipher_uInt8 = new Uint8Array([
    ...iv,
    ...new Uint8Array(payload_cipher)
  ]);

  const HMAC = await webcrypto.subtle.sign(
    {
      name: "HMAC",
      hash: "SHA-256",
      length: 256
    },
    HMACKey_s,
    ivedPayload_cipher_uInt8
  );

  const ivedPayload_cipher_b64 = uInt8ArrToB64(ivedPayload_cipher_uInt8);

  const HMAC_b64 = uInt8ArrToB64(new Uint8Array(HMAC));

  const fullJWT = {
    JWTHeader: JWTHeader,
    ivedPayload_encrypted_b64: ivedPayload_cipher_b64,
    HMAC_b64
  }

  return fullJWT;
}