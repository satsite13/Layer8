import { Request, Response, NextFunction } from "express";
import { getCitizenId } from "../database/MockedDatabase.mjs"
import {
  createUserId,
  storeCryptoAsset,
  getPubSJWK,
  getPubDHJWK,
  getSharedSalt,
  doubleDerivedSharedSecret,
  symmetricEncrypt,
  symmetricDecrypt,
  verifySignedString,
  signString,
} from "./moduleCryptoFunctions.js";

// INTERFACES & TYPES
interface IStdRes<T> {
  errorFlag: boolean,
  msg: string,
  data: T;
}

interface L8Request extends Request {
  citizen: string,
  citizenId: string,
  citizenCheck: boolean,
  L8: any
};

interface ISPResponse {
  msg: string | null,
  errorFlag: boolean,
  data: object | null
}

interface ISealedEnvelope {
  errorFlag: boolean,
  msg: string | null,
  encryptedData_b64: string,
  encryptedDataSignature_b64: string
}

interface IEncryptedData_spa2m {
  init: true, 
  errorFlag: false,
  path: null,
  msg: null,
  method: null,
  query: null,
  options: null,
  data: null
}

// MODULE ROUTER (PRIMARY / DEFAULT FUNCTION)
function Layer8 (req: L8Request, res: Response, next: NextFunction): void {
  const parsedURL = new URL(req.url, "http://localhost");
  console.log(parsedURL);
  const pathname = parsedURL.pathname;
  req["citizenCheck"] = false;

  if(pathname === "/proxied"){
    proxied(req, res, next);
    return;
  } else if (pathname === "/ecdh_init"){
    ECDHInit(req, res, next);
    return;
  } else {
    console.log("This user is going to be anonymous");
    next();
    return;
  }
};

// LAYER8 ENDPOINTS
// Proxied Endpoint
async function proxied(req: L8Request, res: Response, next: NextFunction): Promise<void> {
  console.log("Hit: 'proxied' within 'module'.", "\n");
  try{
    const citizen = req.header("x-citizen");
    if(!citizen) throw new Error("Error reading 'x-citizen' header.");
    const citizenId = await getCitizenId(citizen);
    const sealedEnvelope_spa2m = <ISealedEnvelope>req.body.sealedEnvelope_spa2m;
    console.log("sealedEnvelope_spa2m.errorFlag: ", sealedEnvelope_spa2m.errorFlag);
    console.log("sealedEnvelope_spa2m.msg: ", sealedEnvelope_spa2m.msg);
    const {encryptedData_b64, encryptedDataSignature_b64} = sealedEnvelope_spa2m;
    const signatureVerification = await verifySignedString(citizenId, encryptedData_b64, encryptedDataSignature_b64); // SideEffects*

    if( signatureVerification === false ){

      console.log("The signature of the signed spa object did not pass.");

      res.writeHead(400, {
        "Content-Type" : "application/json",
        "x-citizen" : <string>citizen
      });

      const body = JSON.stringify({
        "errorFlag" : true,
        "msg": "The encrypted SPA data did not pass verification.",
        "data": null,
      })

      res.end(JSON.stringify(body));

    } else { // spa2m encrypted data is legitimately from the associated citizen.
      const unencryptedDataObj_spa2m_str = await symmetricDecrypt(citizenId, encryptedData_b64);
      const unencryptedDataObj_spa2m = JSON.parse(unencryptedDataObj_spa2m_str);
      //console.log("IEncryptedData_spa2m: ", unencryptedDataObj_spa2m);
      if ( unencryptedDataObj_spa2m.errorFlag === true ) {
        console.log("SPA is reporting an error.");

        res.writeHead(400, {
          "Content-Type" : "application/json",
          "x-citizen" : <string>citizen
        });
  
        const body = JSON.stringify({
          "errorFlag" : true,
          "msg": "SPA has reported error.",
          "data": null,
        })
  
        res.end(JSON.stringify(body));

      } else if ( unencryptedDataObj_spa2m.init === true ) {
        
        const serviceProviderResp: IStdRes<null> = {
          "errorFlag": false,
          "msg": "ECDH initiation response",
          "data": null,
        };

        const serviceProviderResp_str = JSON.stringify(serviceProviderResp);
        const encryptedData_b64 = await symmetricEncrypt(citizenId, serviceProviderResp_str);
        const encryptedDataSignature_b64 = await signString(citizenId, encryptedData_b64); // SideEffects*

        const sealedEnvelope: ISealedEnvelope = {
          errorFlag: false,
          msg: "Sealed Envelope in response to ECDH initialization request.",
          encryptedData_b64,
          encryptedDataSignature_b64,
         }

          res.writeHead(200, {
            "content-type": "application/json"
          });

          res.end(JSON.stringify(sealedEnvelope));

      } else if (unencryptedDataObj_spa2m.init === false) { // i.e. A standard request.
        // Here, the SPA's details can be added to the standard Node request object for access by the service provider
        req["citizen"] = citizen;
        req["citizenId"] = citizenId
        req["L8"] = unencryptedDataObj_spa2m;
        req["citizenCheck"] = true;
        req.url = `/${unencryptedDataObj_spa2m.path}`;
        req.method = unencryptedDataObj_spa2m.method;
        console.log("req.url: ", req.url)
        next();
        return;
      }
    }
  } catch(err){
    console.log("Error in the Module's 'proxied' route.");
  }
}

  // ECHD Endpoint
async function ECDHInit(req: L8Request, res: Response, next: NextFunction): Promise<void> {
  //Time to gather necessary info for ECDH
  try{
    const citizen = req.header("x-citizen");
    const pubDHJWK_spa2m_str = req.header("x-pubdhjwk-spa2m")
    const pubSJWK_spa2m_str = req.header("x-pubsjwk-spa2m")
    if(!citizen) throw new Error("x-citizen header not defined.");
    if(!pubDHJWK_spa2m_str) throw new Error("x-pubdhjwk-spa2m header not defined.");
    if(!pubSJWK_spa2m_str) throw new Error("x-pubsjwk-spa2m header not defined.");
    const citizenId = await createUserId(citizen); // TODO: What if citizen already exists?
    const pubSJWK_spa2m = JSON.parse(pubSJWK_spa2m_str);
    const pubDHJWK_spa2m = JSON.parse(pubDHJWK_spa2m_str);
    storeCryptoAsset(citizenId, "pubSJWK_spa2m", pubSJWK_spa2m);
    storeCryptoAsset(citizenId, "pubDHJWK_spa2m", pubDHJWK_spa2m);


    // TODO: See Fowler's Distilled UML: "queries" vs "modifiers". If a function returns a value, it's a query and aught NOT to have side effects. If a function has side effects, it aught NOT to return a value.
    const pubSJWK_m2spa = await getPubSJWK(citizenId); // Side Effects*
    const pubDHJWK_m2spa = await getPubDHJWK(citizenId); // Side Effects*
    const sharedSalt_b64 = await getSharedSalt(citizenId); // Side Effects*
    await doubleDerivedSharedSecret(citizenId); // Side Effects*

    const messageObj: IStdRes<null> = { //TODO: Of msg type?
      "msg": "module 2 spa check",
      "errorFlag": false,
      "data" : null
    }

    const messageStr = JSON.stringify(messageObj);

    const encryptedMsg_b64 = await symmetricEncrypt(citizenId, messageStr);

    res.writeHead(200, {
      "Content-Type" : "application/json",
      "x-citizen" : <string>citizen,
      "x-pubsjwk-m2spa" : <string>JSON.stringify(pubSJWK_m2spa),
      "x-pubdhjwk-m2spa" : <string>JSON.stringify(pubDHJWK_m2spa),
      "x-sharedsalt-b64" : <string>sharedSalt_b64
    });

    // TODO: Note that this is NOT a true ISealedEnvelope. The reason is that an attacker who supplies BOTH their pubSJWK and their signature could be anyone. The Layer8 reverse proxy should have the store of public signing keys and serve them to the SPA.

    const body /*ISealedEnvelope*/ = JSON.stringify({
      "errorFlag" : false,
      "msg": "See encryptedMsg_b64 for the encrypted",
      "encryptedData_b64": encryptedMsg_b64,
      "encryptedDataSignature_b64": null
    })

    res.end(body);
    return;
  } catch(err) {
    console.log("[Catch block of the Module's ECDH Init route.]", err);
    return;
  }
}

export default Layer8;

async function returnEncryptedData(req: L8Request, res: Response, data: any){
  console.log("Function 'returnEncryptedData' has been called on:", data.title);

  const citizenId = await createUserId(req['citizen']); // TODO: should be 'createCitizenId()'
  const encryptedReturnMsg_b64 = await symmetricEncrypt(citizenId, JSON.stringify(data));
  const signature_b64_m2spa = await signString(citizenId, encryptedReturnMsg_b64);
  
  const msgAndSignature_m2spa: ISealedEnvelope = {
    errorFlag: false,
    msg: "this is it bud.",
    encryptedData_b64: encryptedReturnMsg_b64,
    encryptedDataSignature_b64: signature_b64_m2spa
  };

  res.writeHead(200, {
    "content-type": "application/json",
    "x-citizen" : req['citizen'],
  });

  res.end(JSON.stringify(msgAndSignature_m2spa));
}


export const L8 = {
  returnEncryptedData
}