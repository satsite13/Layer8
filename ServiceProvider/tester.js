const fullJWT_spa_str = sessionStorage.getItem("fullJWT");

const citizen = sessionStorage.getItem("citizen");
if ( !fullJWT_spa_str || !citizen ) throw new Error("fullJWT or citizen not properly initialized.");


const fullJWT_spa_obj = JSON.parse(fullJWT_spa_str);
const privSJWK_spa_str = sessionStorage.getItem("privSJWK_c"); //note conversion from 'client'(c) to 'single page application' (spa).

if ( !privSJWK_spa_str ) throw new Error("Signing key was not initialized.");

const privSJWK_spa = JSON.parse(privSJWK_spa_str);


const privSKey_spa = await crypto.subtle.importKey(
  "jwk",
  privSJWK_spa,
  {
    name: "ECDSA",
    namedCurve: "P-256",
  },
  false,
  ["sign"]
);
const authSignature_b64 = await signObject(fullJWT_spa_obj, privSKey_spa); // TODO: Sign obj or str?

const signedFullJWT_spa2p = {
  fullJWT_spa_obj,
  authSignature_b64
};