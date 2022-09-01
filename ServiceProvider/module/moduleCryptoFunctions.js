import { webcrypto } from "crypto";
import { setCitizenId } from "../database/MockedDatabase.mjs";
import { uInt8ArrToB64, b64ToUint8Arr } from "./b64_utils.js";


const keyStore_module = new Map();

/**
 * createUserId
 * Uses the username to create a b64, sha256 hash to uniquely identify each user.
 * @param {string} username
 * @returns {string} b64UserId
 */
 export async function createUserId(citizenName){
  const citizenName_uInt8 = new TextEncoder().encode(citizenName);
  const hash_uInt8 = await webcrypto.subtle.digest("SHA-256", citizenName_uInt8);
  const citizenId = uInt8ArrToB64(new Uint8Array(hash_uInt8)).slice(0,5);

  await setCitizenId(citizenName, citizenId);
  //console.log("\n\nkeyStore_module", keyStore_module);
  return citizenId;
};

/**
 * storeCryptoAsset
 * @param {string} userId
 * @param {string} type
 * @param {JsonWebKey | CryptoKey | CryptoKeyPair} JWK
 * @return {Promise<boolean>} successFlag
 */
export async function storeCryptoAsset(userId, type, JWK){
  try{
    if(!keyStore_module.get(userId)){
      keyStore_module.set(userId, new Map());
    };
    keyStore_module.get(userId).set(type, JWK);
    return true;
  } catch(err){
    console.log(err);
    return false;
  }
}

/**
 * getCryptoAsset
 * Used to retrieve from the keyStore_module. Prevents direct accessing of crypto assets.
 * @param {string} userId
 * @param {string} type
 * @return {Promise<CryptoKeyPair | JsonWebKey | CryptoKey | boolean>} Requested asset
 */
 export async function getCryptoAsset(userId, type){
  try{
    return keyStore_module.get(userId).get(type);
  }catch(err){
    console.log(err);
    return false
  }
}


/**
 * getPubSJWK
 * Creates a key pair for signing all messages to the single page application(spa) and stores them by the spa's B64 userId. The pubSJWK_m2spa is then returned for return send to the spa.
* @param {string} userId
* @returns {Promise<JsonWebKey>} pubSJWK_m2spa
*/
export async function getPubSJWK(userId){
  const keyPairS_m2spa = await webcrypto.subtle.generateKey(
     {
        name: "ECDSA",
        namedCurve: "P-256"
     },
     true,
     ["sign", "verify"]
  );

  storeCryptoAsset(userId, "keyPairS_m2spa", keyPairS_m2spa);

  const pubJWK_m2spa = await webcrypto.subtle.exportKey(
     "jwk",
     keyPairS_m2spa.publicKey
  );

  return pubJWK_m2spa;
};


/**
 * getPubDHJWK
 * Creates a key pair for completing an ECDH with the single page application (spa) and stores them by the spa's B64 userId. The pubDHJWK_m2spa is then returned for return send to the spa.
* @param {string} userId
* @returns {Promise<JsonWebKey>} pubDHJWK_m2spa
*/
export async function getPubDHJWK(userId){
  const keyPairDH_m2spa = await webcrypto.subtle.generateKey(
     {
        name: "ECDH",
        namedCurve: "P-256"
     },
     true,
     ["deriveKey", "deriveBits"]
  );

  storeCryptoAsset(userId, "keyPairDH_m2spa", keyPairDH_m2spa);

  const pubDHJWK_m2spa = await webcrypto.subtle.exportKey(
     "jwk",
     keyPairDH_m2spa.publicKey
  );

  return pubDHJWK_m2spa;
};

/**
 * getSharedSalt
 * Needed for encryption / decryption. Important that it both return it as well as store it for later use attached to the client's id.
 * @param {string} userId
 * @returns {Promise<string>} sharedSalt_b64
 */
 export async function getSharedSalt(userId){
  const sharedSalt_uInt8 = webcrypto.getRandomValues(new Uint8Array(16));
  const sharedSalt_b64 = uInt8ArrToB64(sharedSalt_uInt8);
  storeCryptoAsset(userId, "sharedSalt_b64", sharedSalt_b64);
  return sharedSalt_b64;
}

/**
 * doubleDerivedSharedSecret
 * Preps the module to encrypt / decrype messages.
 * @param {string} userId
 * @returns null
 */
 export async function doubleDerivedSharedSecret(userId){
  const pubDHJWK_spa2m = await getCryptoAsset(userId, "pubDHJWK_spa2m");
  const keyPairDH_m2spa = await getCryptoAsset(userId, "keyPairDH_m2spa");
  const sharedSalt_b64 = await getCryptoAsset(userId, 'sharedSalt_b64');
  //console.log("sharedsalt_b64: ", sharedSalt_b64);
  const sharedSalt_uInt8 = b64ToUint8Arr(sharedSalt_b64);

  const pubDHKey_spa2m = await webcrypto.subtle.importKey(
     "jwk",
     pubDHJWK_spa2m,
     {
        name: "ECDH",
        namedCurve: "P-256"
     },
     true,
     []
  );

  const ecdhResult = await webcrypto.subtle.deriveBits(
     {
        name: "ECDH",
        public: pubDHKey_spa2m
     },
     keyPairDH_m2spa.privateKey,
     256
  );

  const sharedKeyMaterial = await webcrypto.subtle.importKey(
     "raw",
     ecdhResult,
     {
        name: "PBKDF2"
     },
     false,
     ["deriveBits"]
  );

  const sharedDerivedBits = await webcrypto.subtle.deriveBits(
     {
        name: "PBKDF2",
        salt: sharedSalt_uInt8,
        iterations: 10000,
        hash: 'SHA-256'
     },
     sharedKeyMaterial,
     256
  );

  const sharedSecret = await webcrypto.subtle.importKey(
     'raw',
     sharedDerivedBits,
     {
        name: "AES-GCM",
     },
     true,
     ['encrypt', 'decrypt']
  );

  storeCryptoAsset(userId, 'sharedSecret', sharedSecret);

  console.log("****", await webcrypto.subtle.exportKey("jwk", sharedSecret));

  //viewKeyStore("L190");

  return null;
};

/**
 * Used to encrypt plain text strings.
 * @param {string} userId
 * @param {string} plaintext
 * @returns {string} ciphertext_b64
 */
 export async function symmetricEncrypt(userId, plaintext){
  const sharedSecret = await getCryptoAsset(userId, "sharedSecret")

  const plaintext_uInt8 = new TextEncoder().encode(plaintext);

  const iv = new Uint8Array(16);
  webcrypto.getRandomValues(iv);

  const encrypted = await webcrypto.subtle.encrypt(
     {name: "AES-GCM", iv: iv},
     sharedSecret,
     plaintext_uInt8
  )

  const ciphertext_uInt8 = new Uint8Array([
     ...iv,
     ...new Uint8Array(encrypted)
  ]);

  const ciphertext_b64 = uInt8ArrToB64(ciphertext_uInt8);

  return ciphertext_b64;
}

/**
 * symmetricDecrypt
 * Used to decrypt ciphertext strings encoded as base64
 * @param {string} userId 
 * @param {string} ciphertext_b64 
 * @returns {string} plaintext
 */
 export async function symmetricDecrypt(userId, ciphertext_b64) {
   const ciphertext = b64ToUint8Arr(ciphertext_b64, 0);
   const iv = ciphertext.slice(0, 16);
   const encrypted = ciphertext.slice(16);

   const sharedSecret = await getCryptoAsset(userId, "sharedSecret");
   
   const plaintext_uInt8 = await webcrypto.subtle.decrypt(
      {name: 'AES-GCM', iv: iv},
      sharedSecret,
      encrypted
   )

   const plaintext = new TextDecoder().decode(plaintext_uInt8);

   return plaintext;
}


/**
 * signString
 * Generic function for signing any string.
 * @param {string} citizenId
 * @param {string} str (the object you want signed)
 * @returns {string} authSignature_b64
 */
 export async function signString(citizenId, string){
   const string_uInt8 = new TextEncoder().encode(string);

   const keyPair_m2spa = await getCryptoAsset(citizenId, "keyPairS_m2spa")
 
   const authSignature_uInt8 = await webcrypto.subtle.sign(
     {
       name: "ECDSA",
       hash: "SHA-256"
     },
     keyPair_m2spa.privateKey,
     string_uInt8
   );
   const authSignature_b64 = uInt8ArrToB64(new Uint8Array(authSignature_uInt8));
   return authSignature_b64;
 }


 /**
  * verifySignedString
 * Used to verify an encrypted string prior to decryption.
 * @param {string} userId 
 * @param {string} signedString_b64 
 * @param {string} signature_b64 
 * @returns {Promise<boolean>} verification
 */
export async function verifySignedString(userId, signedString_b64, signature_b64){
const signature_uInt8 = b64ToUint8Arr(signature_b64, 0);
const pubSJWK = await getCryptoAsset(userId, "pubSJWK_spa2m");
const pubSKey = await webcrypto.subtle.importKey(
   "jwk",
   pubSJWK,
   {
      name: "ECDSA",
      namedCurve: 'P-256'
   },
   true,
   ["verify"]
);

const textToVerify = new TextEncoder().encode(signedString_b64);

const verification = await webcrypto.subtle.verify(
   {
      name: 'ECDSA',
      hash: "SHA-256"
   },
   pubSKey,
   signature_uInt8,
   textToVerify
)

return verification? true: false;
}

  /**
  * verifySignedObject
 * Used to verify an encrypted string prior to decryption.
 * @param {string} userId 
 * @param {string} type (e.g., 'pubSJWK_c2p')
 * @param {Object} signedObj 
 * @param {string} signature_b64 
 * @returns {Promise<boolean>} verification
 */
export async function verifySignedObject(userId, keyType, signedObj, signature_b64){
   const signedObj_str = JSON.stringify(signedObj);
   const signature_uInt8 = b64ToUint8Arr(signature_b64, 0);
   const pubSJWK = await getCryptoAsset(userId, keyType);
   const pubSKey = await webcrypto.subtle.importKey(
      "jwk",
      pubSJWK,
      {
         name: "ECDSA",
         namedCurve: 'P-256'
      },
      true,
      ["verify"]
   );

   const textToVerify = new TextEncoder().encode(signedObj_str);

   const verification = await webcrypto.subtle.verify(
      {
         name: 'ECDSA',
         hash: "SHA-256"
      },
      pubSKey,
      signature_uInt8,
      textToVerify
   )

   return verification? true: false;
   }