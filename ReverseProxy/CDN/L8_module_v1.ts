// CONNECTION CHECK
console.log("'L8_module_v1.js' connected...", "v8");

import { b64ToUint8Arr, uInt8ArrToB64 } from './b64_utils.js';

declare global { // Declare an...
  interface Window { L8: L8 } // ...Interface as Global called 'Window' that has the property 'L8'
}

// TYPES
type SignupData = { availableIdentities: string[] };
type AvailableIdentities = { availableIdentities: string[] };

type PreCheckData = { 
  userSalt_b64: string,
  pubSJWK_s: string
}

type LoginData = {
  userId: string,
  signedHalfJWT: { halfJWT: IHalfJWT, authSignature_b64: string },
  availableIdentities: string[],
}

type ChooseIdentityData = {
  chosenIdentity: string,
  signedFullJWT: ISignedFullJWT
}

// INTERFACES
interface IStdRes<T> {
  errorFlag: boolean,
  msg: string | null,
  data: T | null;
}

interface IJWTHeader {
  typ: string,
  sig: string
}

interface IHalfJWT {
  JWTHeader: {
    typ: string,
    sig: string
  },
  ivedPayload_encrypted_b64: string,
  HMAC_b64: string,
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

interface IEncryptedData_spa2m extends IStdRes<JSON> {
  init: boolean,
  method: string | null,
  path: string | null,
  query: object | null,
  options: object | null,
}

interface ISealedEnvelope {
  errorFlag: boolean,
  msg: string | null,
  encryptedData_b64: string,
  encryptedDataSignature_b64: string
}

// L8 CLASS IMPLEMENTATION
class L8 {
  private serviceProviderId: string | undefined;
  private providerIsValid: boolean | undefined;
  private keyPairS_c: CryptoKeyPair | undefined;
  private halfJWT: IHalfJWT | undefined;
  //private stringifiedJWKs: Map<string, string> = new Map();
  private keyPairDH_spa: CryptoKeyPair | undefined;
  private pubSJWK_m2spa: JsonWebKey | undefined;
  private pubDHJWK_m2spa: JsonWebKey | undefined;
  private sharedSalt_b64: string | undefined;
  private sharedSecret: CryptoKey | undefined;
  private privSJWK_c: JsonWebKey | undefined;
  private pubSJWK_c: JsonWebKey | undefined;
  private pubSJWK_s: JsonWebKey | undefined;

  constructor() {}

  // PUBLIC FUNCTIONS
  private async checkServiceProviderId(id: string | null): Promise<boolean> {
    // Mocked implementation.
    if(id){
      return true;
    } else {
      throw new Error("Error while checking service provider");
    }
  }

  async registerServiceProviderId(trialProviderId: string): Promise<boolean> {
    // TODO: There is yet no proposed mechanism for this.
    try{
      const idIsValid = await this.checkServiceProviderId(trialProviderId);
      if(idIsValid === false ){
        console.log("serviceProviderId is invalid. Layer8 failed to initialize");
        return false;
      } else {
        this.serviceProviderId = trialProviderId;
        this.providerIsValid = true;
        return true;
      }
    } catch(err) {
      console.log(err);
      return false;
    }
  }

  async trialSignup(trialUsername: string, password: string): Promise<IStdRes<SignupData>> {
    const username_uInt8 = new TextEncoder().encode(trialUsername);
    const username_sha256 = await crypto.subtle.digest('SHA-256', username_uInt8);
    const username_b64 = uInt8ArrToB64(new Uint8Array(username_sha256));
    const salt_uInt8 = crypto.getRandomValues(new Uint8Array(16));
    const password_encoded_uInt8 = new TextEncoder().encode(password);

    const password_key = await crypto.subtle.importKey(
      "raw",
      password_encoded_uInt8,
      "PBKDF2",
      false,
      ["deriveBits"]
    )

    const hashedPassword_buff = await crypto.subtle.deriveBits(
      {
        name: "PBKDF2",
        hash: "SHA-256",
        salt: salt_uInt8,
        iterations: 10000
      },
      password_key,
      256
    );

    const hashedPassword_b64 = uInt8ArrToB64(new Uint8Array(hashedPassword_buff));

    try {
      const response1 = await fetch("http://localhost:3000/signup",{
        method: "POST",
        headers: {
          "content-type": "application/json",
        },
        body: JSON.stringify({
          userId: username_b64.slice(0,5),
          requestedUsername: trialUsername,
          userSalt_b64: uInt8ArrToB64(salt_uInt8),
          hashedPassword_b64
        })
      });

      let signupResponse: IStdRes<SignupData> = await response1.json()
      return signupResponse;
    } catch (err) {
      console.log(err);
      const errorObject = {
        msg: "Error Posting to 'http://localhost:3000/signup'",
        errorFlag: true,
        data: null,
      };
      return errorObject;
    }
  }

  async attemptLogin(username: string, password: string): Promise<IStdRes<AvailableIdentities>> {
    const userId = await this.usernameToUserId(username);
    // TODO: Key management.
    // Does this user already have a key pair for signing?
    if(this.keyPairS_c === undefined){ // If no, create a client keypair for signing and store it for later
      this.keyPairS_c = await crypto.subtle.generateKey(
          {
            name: "ECDSA",
            namedCurve: "P-256"
          },
          true, 
          ['sign', "verify"]
      );
    }
    // Export public signing JWK and store for later use.
    if(this.keyPairS_c === undefined) throw new Error("L8's keyPairS_c is undefined.");
    const pubSJWK_c = await crypto.subtle.exportKey("jwk", <CryptoKey>this.keyPairS_c.publicKey);
    const privSJWK_c = await crypto.subtle.exportKey("jwk", <CryptoKey>this.keyPairS_c.privateKey);

    //this.stringifiedJWKs.set("pubSJWK_c", JSON.stringify(pubSJWK_c));
    this.pubSJWK_c = pubSJWK_c;
    //this.stringifiedJWKs.set("privSJWK_c", JSON.stringify(privSJWK_c));
    this.privSJWK_c = privSJWK_c;

    // Get the user's salt and test that the userId is valid.
    const response1 = await fetch("./login/precheck", {
        method: "POST",
        headers: {
           "Content-Type": "application/JSON",
        },
        body: JSON.stringify({
          pubSJWK_c: pubSJWK_c,
          trialUserId: userId
       })
    })

    const response1_json: IStdRes<PreCheckData> = await response1.json();

    if(response1_json.errorFlag === true) {
      throw new Error(`Login precheck failed. Server message: ${response1_json.msg}`);
    }

    const preCheckData = <PreCheckData>response1_json.data
    //this.stringifiedJWKs.set('pubSJWK_s', preCheckData.pubSJWK_s);
    this.pubSJWK_s = <JsonWebKey>JSON.parse(preCheckData.pubSJWK_s);
    //const pubSJWK_s:  = JSON.parse(preCheckData.pubSJWK_s);

    //Derive password locally & send the hash to l8 for validation.
    const password_encoded_uInt8 = new TextEncoder().encode(password);
    const password_key = await crypto.subtle.importKey(
       "raw",
       password_encoded_uInt8,
       "PBKDF2",
       false,
       ["deriveBits"]
    );
    const hashedPassword_buff = await crypto.subtle.deriveBits(
       {
         name: "PBKDF2",
         hash: "SHA-256",
         salt: b64ToUint8Arr(preCheckData.userSalt_b64, 0),
         iterations: 10000
       },
       password_key,
       256
    );
    const hashedPassword_b64 = uInt8ArrToB64(new Uint8Array(hashedPassword_buff));

    const response2 = await fetch("/login", {
       method: "POST",
       headers: {
          "Content-Type": "application/JSON",
       },
       body: JSON.stringify({
          trialUserId: userId,
          trialPassword: hashedPassword_b64
       })
    })

    const response2_json: IStdRes<LoginData> = await response2.json();

    if( response2_json.errorFlag === true ) {
      throw new Error(`Login failure. Server's message: ${response2_json.msg}`);
    }

    const loginData = <LoginData> response2_json.data;
    const { userId: userId2, signedHalfJWT, availableIdentities } = loginData;

    if(userId != userId2){
      throw new Error("the userId used during login precheck does not match that returned after the login was attempted.");
    }

    const { halfJWT, authSignature_b64 } = signedHalfJWT;

    const halfJWTValidation = await this.verifySignedObject(halfJWT, this.pubSJWK_s, authSignature_b64);
    if(halfJWTValidation === false){
      throw new Error("Server's response could not be verified with the pubSJWK_s previously provided.")
    } else {
      this.halfJWT = halfJWT;
      const L8Response: IStdRes<AvailableIdentities> = {
        msg: "Server has provided the following identities: ",
        errorFlag: false,
        data: {
          availableIdentities: availableIdentities,
        }
      }
      return L8Response;
    }
  }

  async chooseIdentity(username: string, chosenIdentity: string): Promise<IStdRes<null>> {
    // Use fetch to POST a request to the server containing the chosen identity and the halfJWT
    if(this.keyPairS_c === undefined) throw new Error("Client key pair is undefined. It needs initiation.");
    const privSKey_c = <CryptoKey> this.keyPairS_c.privateKey;
    if(this.halfJWT === undefined) throw new Error("this.halfJWT must be defined before identity is chosen.");
    const authSignature_c_b64 = await this.signObject(this.halfJWT, privSKey_c);
    const userId = await this.usernameToUserId(username);
    const response1 = await fetch("http://localhost:3000/login/identity", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-signedhalfjwt-c": JSON.stringify({halfJWT: this.halfJWT, authSignature_c_b64}),
      },
      body: JSON.stringify({
        userId,
        chosenIdentity
      })
    });

    const response1_json: IStdRes<ChooseIdentityData> = await response1.json();

    if(response1_json.errorFlag === true){
      throw new Error(`Error after 'POST' to /login/identity, ${response1_json.msg}`);
    }
    
    
    const chooseIdentityData = <ChooseIdentityData>response1_json.data;
    
    //const pubSJWK_s = this.stringifiedJWKs.get('pubSJWK_s');
    if(this.pubSJWK_s === undefined) throw new Error("Server's public signing JWK was not found.");
    //const pubSJWK = JSON.parse(this.pubSJWK_s);
    const { chosenIdentity: chosenIdentity2, signedFullJWT } = chooseIdentityData;
    const { fullJWT, signature_b64 } = <ISignedFullJWT>signedFullJWT;
    console.log("****",fullJWT);

    const fullJWTVerification = await this.verifySignedObject(fullJWT, this.pubSJWK_s, signature_b64);
    if(fullJWTVerification === false){
      throw new Error("fullJWT did not pass verification");
    } else {
      if( chosenIdentity != chosenIdentity2 ){
        throw new Error( "Chosen Identity Corruption.");
      }
      await this.registerCitizenship(fullJWT, chosenIdentity); // Probably should be an asynchronous IndexedDB write in time.
      return { // <IL8Response>
        errorFlag: false,
        msg: "Citizenship registered.",
        data: null
      }
    }
  }

  async registerCitizenship(fullJWT: IFullJWT, chosenIdentity: string): Promise<void> {
    sessionStorage.clear();
    try {
      // const privSJWK_c = this.stringifiedJWKs.get("privSJWK_c");
      // if ( !privSJWK_c ) throw new Error("Problem retrieving the 'privSJWK_c'");
      // const pubSJWK_c = this.stringifiedJWKs.get("pubSJWK_c");
      // if ( !pubSJWK_c ) throw new Error("Problem retrieving the 'pubSJWK_C'");

      sessionStorage.setItem("privSJWK_c", JSON.stringify(this.privSJWK_c));
      sessionStorage.setItem("pubSJWK_c", JSON.stringify(this.pubSJWK_c));
      sessionStorage.setItem("fullJWT", JSON.stringify(fullJWT));
      sessionStorage.setItem("citizen", chosenIdentity);
    } catch (err){
      console.log("Errror while registering the citizen.", err);
    }
  }

  async establishTunnel(): Promise<void>{
    // Create a key pair for doing DH with the service provider and save for later.
    this.keyPairDH_spa = await crypto.subtle.generateKey(
      {
         name: "ECDH",
         namedCurve: "P-256"
      },
      true,
      ["deriveKey", "deriveBits"]
    );

    let pubDHJWK_spa = await crypto.subtle.exportKey(
      "jwk",
      <CryptoKey>this.keyPairDH_spa.publicKey
    );

    const pubDHJWK_spa_str = JSON.stringify(pubDHJWK_spa);

    //this.stringifiedJWKs.set("pubDHJWK_spa", pubDHJWK_spa_str);

    const pubSJWK_spa_str = sessionStorage.getItem("pubSJWK_c");//note conversion from 'client'(c) to 'single page application' (spa).
    if(!pubSJWK_spa_str) throw new Error("pubSJWK_c was not set.");
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

    const JWTauthSignature_b64 = await this.signObject(fullJWT_spa_obj, privSKey_spa); // TODO: Sign obj or str?
    
    const signedFullJWT_spa2p: ISignedFullJWT = {
      fullJWT: fullJWT_spa_obj,
      signature_b64: JWTauthSignature_b64
    };

    const response1 = await fetch("http://localhost:3000/ecdhinit", {
      method: "POST",
      headers: {
        "content-type": "application/JSON",
        "x-citizen": citizen,
        "x-signedfulljwt-spa": JSON.stringify(signedFullJWT_spa2p),
        "x-pubdhjwk-spa2m": pubDHJWK_spa_str,
        "x-pubsjwk-spa2m" : pubSJWK_spa_str
      },
      body: JSON.stringify({
        "msg": "SPA Attempting ECDH",
        "erroFlag": null,
        "data": null
      })
    });

    const response1_json = await response1.json(); //Almost an <ISealedEnvelope> 

    //At this point, you should have everything you need to message the module end-to-end encrypted.
    const pubsjwk_m2spa_str = response1.headers.get('x-pubsjwk-m2spa');
    const pubdhjwk_m2spa_str = response1.headers.get('x-pubdhjwk-m2spa');
    const sharedSalt_b64 = response1.headers.get('x-sharedsalt-b64')
    if(!pubsjwk_m2spa_str) throw new Error("pubsjwk_m2spa_str undefined or null.");
    if(!pubdhjwk_m2spa_str) throw new Error("pubsjwk_m2spa_str undefined or null.");
    if(!sharedSalt_b64) throw new Error("sharedSalt_b64 undefined or null.");
    const pubSJWK_m2spa = JSON.parse(pubsjwk_m2spa_str);
    const pubDHJWK_m2spa = JSON.parse(pubdhjwk_m2spa_str);
    this.pubSJWK_m2spa = pubSJWK_m2spa;
    this.pubDHJWK_m2spa = pubDHJWK_m2spa;
    this.sharedSalt_b64 = sharedSalt_b64;
    await this.doubleDerivedSharedSecret(); // Side Effects*
    
    //Symmetric decryption test. In the future, a signature should be checked first before any decryption using a pubSJWK_m2spa served by the L8 reverse proxy.

    // TOMORROWS LABOUT JULY 31, 2022
    const encryptedData_b64_m = response1_json.encryptedData_b64;
    
    try {
      const plaintextDataFromModule_str = await this.symmetricDecrypt(encryptedData_b64_m);
      const plaintextDataFromModule_obj = JSON.parse(plaintextDataFromModule_str);
      if(plaintextDataFromModule_obj === true){
        throw new Error("The symmetric decryption test failed.");
      }
    } catch(err) {
      console.log("[Error while performing symmetriDecrypt on the Service Provider's response.]", err);
    }

    const plaintextDataObj_spa2m: IEncryptedData_spa2m = {
      init: true, // Is this the best place to put an init flag?
      errorFlag: false,
      path: null,
      msg: null,
      method: null,
      query: null,
      options: null,
      data: null
    }

    const plaintextDataObj_spa2m_str = JSON.stringify(plaintextDataObj_spa2m);
    const encryptedDataObj_spa2m_b64 = await this.symmetricEncrypt(plaintextDataObj_spa2m_str);

    const signature_b64_spa2m = await this.signString(encryptedDataObj_spa2m_b64, privSKey_spa);

    const sealedEnvelope_spa2m: ISealedEnvelope = {
      errorFlag: false, 
      msg: "SPA is testing the initiated tunnel.",
      encryptedData_b64: encryptedDataObj_spa2m_b64,
      encryptedDataSignature_b64: signature_b64_spa2m
    };
    
    const response2 = await fetch("http://localhost:3000/proxyme", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-citizen": citizen,
        "x-signedfulljwt-spa": JSON.stringify(signedFullJWT_spa2p),
      },
      body: JSON.stringify( {sealedEnvelope_spa2m} )
    });

    const response2_obj: ISealedEnvelope = await response2.json();

    if(response2_obj.errorFlag === true){
      // Register an error.
    } else {
      try{
        if( !this.pubSJWK_m2spa ) throw new Error("pubSJWK_m2spa was not properly initialized.");
        const {encryptedData_b64, encryptedDataSignature_b64} = response2_obj;
        const encryptedDataValidation = await this.verifySignedString(encryptedData_b64, this.pubSJWK_m2spa, encryptedDataSignature_b64);
        if( encryptedDataValidation === false ){
        } else {
          const plainText_m2spa_str = await this.symmetricDecrypt(response2_obj.encryptedData_b64);
          const { errorFlag, msg, data } = JSON.parse(plainText_m2spa_str);
          if( msg ) console.log("[response2.msg from fetch 'http://localhost:3000/proxyme']: ", msg);
          if( errorFlag === true ) throw new Error(`Service Provider is reporting and error: ${msg}`);
        }
      } catch(err) {
        console.log("Error while decrypting or validating the sealed envelope.", err);
      }
    };
  }

  async proxy(data: JSON): Promise<any>{
    if(false) throw new Error("L8 is not properly initialized. You cannot send E2E encrypted messages yet. Try loging in.");
    let citizen = sessionStorage.getItem("citizen");

    let fullJWT_spa_str = sessionStorage.getItem("fullJWT");

    let privSJWK_spa_str = sessionStorage.getItem("privSJWK_c"); // Again note the conversion of 'c' to 'spa'.

    if(!fullJWT_spa_str || !citizen){
      throw new Error("Retrieval of 'citizen' and/or 'fullJWT' failed");
    } else if (!privSJWK_spa_str){
      throw new Error("privSJWK_c is not initialized on sessionStorage.");
    } else {

      const fullJWT_spa_obj = JSON.parse(fullJWT_spa_str);
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

      const fullJWTSig_b64 = await this.signObject(fullJWT_spa_obj, privSKey_spa);

      const signedFullJWT_spa2p: ISignedFullJWT = {
        fullJWT: fullJWT_spa_obj,
        signature_b64: fullJWTSig_b64
      };

      // Encrypt the data
      const data_str = JSON.stringify(data);
      const encryptedData_b64 = await this.symmetricEncrypt(data_str);
      const encryptedDataSignature_b64 = await this.signString(encryptedData_b64, privSKey_spa);
      
      const sealedEnvelope_spa2m: ISealedEnvelope = {
        errorFlag: false,
        msg: "From SPA to Service Provider",
        encryptedData_b64,
        encryptedDataSignature_b64
      }

      const response1 = await fetch("http://localhost:3000/proxyme", {
        method: "POST",
        headers: {
          "Content-Type": "application/JSON",
          "x-citizen": citizen,
          "x-signedfulljwt-spa": JSON.stringify(signedFullJWT_spa2p),
        },
        body: JSON.stringify( {sealedEnvelope_spa2m} )
      })

      const response1_obj = await response1.json();

      try {
        const { errorFlag, msg, encryptedData_b64, encryptedDataSignature_b64 } = <ISealedEnvelope>response1_obj;
        if(msg) console.log("[response1.msg from 'http://localhost:3000/proxyme']: ", msg);
        if(errorFlag === true) throw new Error("Service Provider is reporting an error in it's response.");
        if(!this.pubDHJWK_m2spa) throw new Error("this.pubSJWK_m2spa was not properly initialized.");
        const encryptedMsgValidation = await this.verifySignedString(encryptedData_b64, <JsonWebKey>this.pubSJWK_m2spa, encryptedDataSignature_b64);
        if( encryptedMsgValidation === false ){
          throw new Error("The encrypted data from the service provider did not pass validation.");
        } else {
          const unencryptedData = await this.symmetricDecrypt(encryptedData_b64);
          return JSON.parse(unencryptedData);
        }
      } catch (err) {
      }
    }
  }

  //PRIVATE FUNCTIONS
  async usernameToUserId(username: string): Promise<string> {
    const username_uInt8 = new TextEncoder().encode(username);
    const username_sha256 = await crypto.subtle.digest('SHA-256', username_uInt8);
    const username_b64 = uInt8ArrToB64(new Uint8Array(username_sha256));
    const userId = username_b64.slice(0,5);
    return userId;
  };

  async verifySignedObject(object: object, pubSJWK: JsonWebKey, signature_b64: string): Promise<boolean> {
    const stringifiedObject = JSON.stringify(object);
    const signature_uInt8 = b64ToUint8Arr(signature_b64, 0);
    const pubSKey_s = await crypto.subtle.importKey(
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
    const verification = await crypto.subtle.verify(
      {
        name: "ECDSA",
        hash: "SHA-256"
      },
      pubSKey_s, // Server's public ECDSA key
      signature_uInt8, // Server's signature
      textToVerify // Encrypted object
    )
  
    return verification;
  };

  async verifySignedString(string: string, pubSJWK: JsonWebKey, signature_b64: string): Promise<boolean> {
    const signature_uInt8 = b64ToUint8Arr(signature_b64, 0);
    const pubSKey_s = await crypto.subtle.importKey(
      "jwk",
      pubSJWK,
      {
      name: "ECDSA",
      namedCurve: "P-256",
      },
      false,
      ['verify']
    );
  
    const textToVerify = new TextEncoder().encode(string);
    const verification = await crypto.subtle.verify(
      {
        name: "ECDSA",
        hash: "SHA-256"
      },
      pubSKey_s, // Server's public ECDSA key
      signature_uInt8, // Server's signature
      textToVerify // Encrypted object
    )
  
    return verification;
  };

  async signObject(object: object, privSKey: CryptoKey): Promise<string> {
    const object_string = JSON.stringify(object);
    const object_uInt8 = new TextEncoder().encode(object_string);
  
    const authSig_c = await crypto.subtle.sign(
       {
         name: "ECDSA",
         hash: "SHA-256"
       },
       privSKey,
       object_uInt8
    );
  
    const authSignature_c_b64 = uInt8ArrToB64(new Uint8Array(authSig_c));
  
    return authSignature_c_b64;
  };

  async signString(string: string, privSKey: CryptoKey): Promise<string> {
    const string_uInt8 = new TextEncoder().encode(string);
  
    const authSig_c = await crypto.subtle.sign(
       {
         name: "ECDSA",
         hash: "SHA-256"
       },
       privSKey,
       string_uInt8
    );
  
    const authSignature_c_b64 = uInt8ArrToB64(new Uint8Array(authSig_c));
  
    return authSignature_c_b64;
  };

  private async doubleDerivedSharedSecret(){
    if(!this.sharedSalt_b64) throw new Error("Layer8 sharedSalt_b64 was not initialized properly.");
    if(!this.pubDHJWK_m2spa) throw new Error("Layer8 pubDHJWK was not initialized properly.");
    if(!this.keyPairDH_spa) throw new Error("Layer8 keyPairDH was not initialized properly.");
    const sharedSalt_uInt8 = b64ToUint8Arr(this.sharedSalt_b64, 0);
    const pubDHKey_m2spa = await crypto.subtle.importKey(
      "jwk",
      <JsonWebKey>this.pubDHJWK_m2spa,
      {
        name: "ECDH",
        namedCurve: "P-256"
      },
      true,
      []
    );
    const ecdhResult = await crypto.subtle.deriveBits(
        {
          name: "ECDH",
          public: pubDHKey_m2spa
        },
        <CryptoKey>this.keyPairDH_spa.privateKey,
        256
    );
    const sharedKeyMaterial = await crypto.subtle.importKey(
        "raw",
        ecdhResult,
        {
          name: "PBKDF2"
        },
        false,
        ["deriveBits"]
    );
    
    const sharedDerivedBits = await crypto.subtle.deriveBits(
        {
          name: "PBKDF2",
          salt: sharedSalt_uInt8,
          iterations: 10000,
          hash: 'SHA-256'
        },
        sharedKeyMaterial,
        256
    );
    
    this.sharedSecret = await crypto.subtle.importKey(
        'raw',
        sharedDerivedBits,
        {
          name: "AES-GCM",
        },
        true,
        ['encrypt', 'decrypt']
    );

    return null;
  };

  private async symmetricDecrypt(ciphertext_b64: string) {
    if(!this.sharedSecret) throw new Error("Layer 8 sharedSecret was not properly initialized.");
    const ciphertext = b64ToUint8Arr(ciphertext_b64, 0);  
    const iv = ciphertext.slice(0, 16);
    const encrypted = ciphertext.slice(16);
    
    const plaintext_uInt8 = await crypto.subtle.decrypt(
      {name: 'AES-GCM', iv: iv},
      this.sharedSecret,
      encrypted
    )

    const plaintext = new TextDecoder().decode(plaintext_uInt8);

    return plaintext;
  }

  private async symmetricEncrypt(plaintext: string){
    if(!this.sharedSecret) throw new Error("Layer8 this.sharedSecret was not properly initialized.");
    const plaintext_uInt8 = new TextEncoder().encode(plaintext);
    const iv = new Uint8Array(16);
    crypto.getRandomValues(iv);
    const encrypted = await crypto.subtle.encrypt(
       {name: "AES-GCM", iv: iv},
       this.sharedSecret,
       plaintext_uInt8
    )
  
    const ciphertext_uInt8 = new Uint8Array([
       ...iv,
       ...new Uint8Array(encrypted)
    ]);
  
    const ciphertext_b64 = uInt8ArrToB64(ciphertext_uInt8);
  
    return ciphertext_b64;
  }

}

window.L8 = new L8();
