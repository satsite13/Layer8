//This files is meant to simulate what happens when the server initializes will all the other L8 servers to get the day's (hour's?) JWTEncryptionKey_s or the HMACKey_s. It should be a dynamic file that is updating.

import { webcrypto } from "crypto";

// GLOBAL VARIABLES
export let JWTEncryptionKey_s;
export let HMACKey_s;
export let signingKeyPair_s;
export const pubSJWKFromClients = new Map();
export const keyStore_server = new Map(); // Stores the client / server key pairs for an ECDH

// INIT FUNCTION
/**
 * Calling this functions initializes the server's private keys.
 */
export function initServerKeys(){
  try{
    initServerAESKey();
    initServerHMACKey();
    initServerSigningKeyPair();
  } catch (err){
    console.log("Server failed to initialize the in memory private key store.", err);
  }
};

// PRIVATE FUNCTIONS WITH SIDE EFFECTS IN THIS MODULE
/**
 *In order to decrypt the innermost payload of each JWT, the proxy needs an AES key synchronized across all proxy instances. This allows clients to interact with any instance of the proxy. It is referred to as the "JWTEncryptionKey_s."
 * @returns void
*/
async function initServerAESKey(){
  JWTEncryptionKey_s = await webcrypto.subtle.generateKey(
    {
      name: "AES-CBC",
      length: 256
    },
    false,
    ['encrypt', 'decrypt']
  );
  return null;
};

/**
 * The Triple Check algorithm depends on the JWTs encrypted payload being verifiable by the proxy. The HMACKey_s is also intended to be synchronized across all proxy instances.
 * @returns {null}
*/
async function initServerHMACKey(){
  HMACKey_s = await webcrypto.subtle.generateKey(
    {
      name: "HMAC",
      hash: "SHA-256",
      length: 256
    },
    true,
    ['sign', 'verify']
  );
  return null;
};

/**
 * Creates the server's key pair for signing all future JWTs
 * @returns {null}
 */
 export async function initServerSigningKeyPair(){ // And create/store a private key
  signingKeyPair_s = await webcrypto.subtle.generateKey(
      {
         name: "ECDSA",
         namedCurve: "P-256"
      },
      true,
      ['sign',"verify"]
  );
  return null;
}












/**
 * Simple utility to limit the scope of the 'keyStore_server' to the nodeCryptoModule. Stores JWKs for later use. KeyId is always the b64 sha256Hash of the stingified JWK.
 * @param {string} identifier (e.g., userId)
 * @param {string} pubJWK
 * @returns null
 */
 export async function storeJWKs(identifier, pubJWK){
  //console.log("pubJWK: ", pubJWK);
  const pubJWK_uInt8 = new TextEncoder().encode(pubJWK);
  const pubJWK_id_uInt8 = new Uint8Array(await webcrypto.subtle.digest("SHA-256", pubJWK_uInt8));
  const pubJWK_id_b64 = uInt8ArrToB64(pubJWK_id_uInt8);
  keyStore_server.set(identifier, {pubJWK_id_b64, pubJWK});
  console.log("keyStore_server: ", keyStore_server);
  return null;
}