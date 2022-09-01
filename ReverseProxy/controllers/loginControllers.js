import { checkUserExistence, getUser } from "../database/users.mjs";
import { pubSJWKFromClients } from "../inMemoryKeyStore.mjs";
import {
  createHalfJWT,
  signObject,
  getPubSJWK_s,
  verifySignedObject,
  verifyMAC,
  verifyAndDecryptCipherText,
  buildFullJWT
} from "../serverCryptoFunctions/serverCryptoFunctions.mjs";


// LOGIN ENDPOINTS
export function getLogin(req, res, next){
  res.render("login");
}


/**
 * loginPrecheck route
 * If the user exists, the stored salt is sent back so that a hash can be computed locally.
 * @param {*} req 
 * @param {IStdRes<PreCheckData>} res 
 * @param {*} next 
 */
export async function loginPrecheck( req, res, next){
  const {trialUserId, pubSJWK_c} = req.body;
  const userExists = await checkUserExistence(trialUserId);
  if(userExists === false){ // User does not exist
    res.status(400);
    res.end(JSON.stringify({
      msg: "Response from '/login/salt': User does not exist",
      errorFlag: true,
      data: null,
    }));
  } else { // User does exist
    const { userSalt_b64 } = await getUser(trialUserId);

    pubSJWKFromClients.set(trialUserId, pubSJWK_c)

    const pubSJWK_s = await getPubSJWK_s()

    res.writeHead(200, {
      "Content-type": "application/json"
    })

    res.end(JSON.stringify({
      msg: "user exists. Salt at response.data.userSalt_b64",
      errorFlag: "false",
      data: {
        userSalt_b64,
        pubSJWK_s: JSON.stringify(pubSJWK_s)
      },
    }));
  }
}

/**
 * 
 * @param {*} req 
 * @param {IStdRes<LoginData>} res 
 * @param {*} next 
 */
export async function postLogin(req, res, next){
  const { trialUserId, trialPassword } = req.body;
  const userExists = await checkUserExistence(trialUserId);
  if(userExists === false){
    res.status(400);
    res.end(JSON.stringify({
      msg: "Response from '/login': User does not exist",
      errorFlag: true,
      data: null,
    }));
  } else {
    const userObj = await getUser(trialUserId);
    const passwordMatch = (trialPassword === userObj.hashedPassword_b64);
    if(passwordMatch === false){
      res.status(400);
      res.end(JSON.stringify({
        msg: "Response from '/login': Incorrect password",
        errorFlag: true,
        data: null,
      }));
    } else {
      const halfJWT = await createHalfJWT(userObj);
      const authSignature_b64 = await signObject(halfJWT);
      const signedHalfJWT = { halfJWT, authSignature_b64 };
      res.status(200);
      res.end(JSON.stringify({
        msg: "You should get a halfJWT on the data field.",
        errorFlag: false,
        data: {
          "userId": trialUserId,
          "signedHalfJWT": signedHalfJWT,
          "availableIdentities": userObj.identities
        },
      }));
    }
  }
}

export async function chooseIdentity(req, res, next){
  // Client should now have signed the halfJWT and returned it with an identity selection. Verify that it came from the correct client and that the chosen identity is available. Next, create and return a full JWT with this information.
  const x_signedhalfjwt_c = req.header("x-signedhalfjwt-c");
  const { halfJWT: halfJWT_c, authSignature_c_b64 } = JSON.parse(x_signedhalfjwt_c);
  const { userId, chosenIdentity } = req.body;
  const pubSJWK_c2p = pubSJWKFromClients.get(userId);

  //The following try/catch block is where the halfJWT verification occurs.
  try{
    const halfJWT_verification = await verifySignedObject(halfJWT_c, pubSJWK_c2p, authSignature_c_b64);
    if( halfJWT_verification === false ){
      console.log("halfJWT failed to verify @ signature step.");
      res.writeHead(401, {
        "content-type": "application/json"
      });
      res.end(JSON.stringify({
        msg: "Failed signature of halfJWT_c",
        errorFlag: true,
        data: null
      }))
    } else {
      const extractedHMAC = halfJWT_c['HMAC_b64'];
      const extractedCipherText = halfJWT_c['ivedPayload_cipher_b64'];
      const MAC_verification = verifyMAC(extractedHMAC, extractedCipherText) // Side Effects*;
      if( MAC_verification === false ){
        console.log("MAC from halfJWT failed to verify @ HMAC step.");
        res.writeHead(401, {
          "content-type": "application/json"
        });
        res.end(JSON.stringify({
          msg: "MAC from halfJWT failed to verify.",
          errorFlag: true,
          data: null
        }))
      } else {
        const encryptedPayload = halfJWT_c['ivedPayload_cipher_b64']
        const decryptedPayload = await verifyAndDecryptCipherText(encryptedPayload);
        const storedUserObject = await getUser(userId);
        const storedIdentities = storedUserObject.identities;
        const storedUsername = storedUserObject.username;
        if( storedIdentities.includes(chosenIdentity) === false ||
            storedUsername != decryptedPayload.username ){
              console.log("halfJWT failed to verify @ decryption step.");
              res.writeHead(401, {
                "content-type": "application/json"
              });
              res.end(JSON.stringify({
                msg: "Failed decryption of the halfJWT payload.",
                errorFlag: true,
                data: null
              }))
        } else {
          //At this point, the user has logged in and authenticated.
          const fullJWT = await buildFullJWT(storedUserObject, chosenIdentity);
          const signature_b64 = await signObject(fullJWT);
          const signedFullJWT = { fullJWT, signature_b64 };
          res.writeHead(200, { // destination client
            "content-type": "application/json",
          });
          res.end(JSON.stringify({
            "msg": "Identity successfully chosen.",
            "errorFlag" : false,
            "data": {
              "chosenIdentity": chosenIdentity,
              "signedFullJWT": signedFullJWT
            },
          }))
        }
      }
    }
  } catch(err) {
    console.log("An error occured while authenticating and validating the clients's half JWT");
    console.log(err);
  }
};


