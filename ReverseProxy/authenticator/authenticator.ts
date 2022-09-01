import { Request, Response, NextFunction } from "express";
import { getIdByCitizenship, getUser } from "../database/users.mjs";
import { pubSJWKFromClients } from "../inMemoryKeyStore.mjs";
import {
  verifySignedObject,
  verifyMAC,
  verifyAndDecryptCipherText
} from "../serverCryptoFunctions/serverCryptoFunctions.mjs";


// INTERFACES
export interface IPayload {
  username: string,
  userId: string,
  expiry: number,
  chosenIdentity: string | null;
}

interface IJWTHeader {
  typ: string,
  sig: string
}

interface IFullJWT {
  JWTHeader: IJWTHeader,
  ivedPayload_encrypted_b64: string,
  HMAC_b64: string
}

interface ISignedFullJWT {
  fullJWT: IFullJWT,
  signature_b64: string
}

interface IUser {
  username: string,
  hashedPassword_b64: string,
  userSalt_b64: string,
  identities: string[],
}

// AUTHENTICATOR MIDDLEWARE
export async function authenticator(req_c: Request, res_rp: Response, next: NextFunction): Promise<void> {
  const headers = req_c.headers;
  const citizen = req_c.header("x-citizen");
  try{
    if(!citizen) throw new Error("'x-citizen' http header was null or undefined");
    const userId = await getIdByCitizenship(citizen);
    const x_signedFullJWT_spa = JSON.parse(<string>headers["x-signedfulljwt-spa"]);
    const { fullJWT, signature_b64 } = <ISignedFullJWT>x_signedFullJWT_spa;
    const pubSJWK_spa2p = pubSJWKFromClients.get(userId);
    if(!pubSJWK_spa2p) throw new Error("Citizen does not have associated pubSJWK_spa2p?");
    const fullJWT_verification = await verifySignedObject(fullJWT, pubSJWK_spa2p, signature_b64);
    if( fullJWT_verification === false ){
      console.log("[L138] fullJWT failed verification");
    } else { // Move on to check the MAC...
      const HMAC_b64 = fullJWT['HMAC_b64'];
      const ivedPayload_encrypted_b64 = fullJWT['ivedPayload_encrypted_b64'];
      const MAC_verification = await verifyMAC( HMAC_b64, ivedPayload_encrypted_b64 );
      if(MAC_verification === false ){
        console.log("[Proxy] MAC failed verification");
      } else { // Move on to verify the encrypted body...
        const plaintext_JSON: IPayload = await verifyAndDecryptCipherText(ivedPayload_encrypted_b64);
        const { userId: decryptedUserId } = plaintext_JSON;

        if(!plaintext_JSON){ // Final test of the full JWT
          console.log("Error while, or unable to, decrypt the FullJWTs payload.");
        } else {
          const chosenIdentity = citizen;
          const identifiedUser = <IUser>await getUser(userId);
          if(userId != decryptedUserId){
            throw new Error("Supplied userId does not equal the decryptedUserId");
          } else if (!identifiedUser.identities.includes(chosenIdentity)){
            throw new Error("Chosen identity not available on this user.")
          } else {
            //Full JWT has passwed all checks.
            next();
          }
        }
      }
    }
  } catch (err){
    console.log("Error unknown while authenticating the FullJWT.");
    res_rp.end("FYI: Error unknown while authenticating the FullJWT.");
  }
}

//EXPORT DEFAULT
export default authenticator;
