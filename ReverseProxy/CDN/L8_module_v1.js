var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
// CONNECTION CHECK
console.log("'L8_module_v1.js' connected...", "v8");
import { b64ToUint8Arr, uInt8ArrToB64 } from './b64_utils.js';
// L8 CLASS IMPLEMENTATION
class L8 {
    constructor() { }
    // PUBLIC FUNCTIONS
    checkServiceProviderId(id) {
        return __awaiter(this, void 0, void 0, function* () {
            // Mocked implementation.
            if (id) {
                return true;
            }
            else {
                throw new Error("Error while checking service provider");
            }
        });
    }
    registerServiceProviderId(trialProviderId) {
        return __awaiter(this, void 0, void 0, function* () {
            // TODO: There is yet no proposed mechanism for this.
            try {
                const idIsValid = yield this.checkServiceProviderId(trialProviderId);
                if (idIsValid === false) {
                    console.log("serviceProviderId is invalid. Layer8 failed to initialize");
                    return false;
                }
                else {
                    this.serviceProviderId = trialProviderId;
                    this.providerIsValid = true;
                    return true;
                }
            }
            catch (err) {
                console.log(err);
                return false;
            }
        });
    }
    trialSignup(trialUsername, password) {
        return __awaiter(this, void 0, void 0, function* () {
            const username_uInt8 = new TextEncoder().encode(trialUsername);
            const username_sha256 = yield crypto.subtle.digest('SHA-256', username_uInt8);
            const username_b64 = uInt8ArrToB64(new Uint8Array(username_sha256));
            const salt_uInt8 = crypto.getRandomValues(new Uint8Array(16));
            const password_encoded_uInt8 = new TextEncoder().encode(password);
            const password_key = yield crypto.subtle.importKey("raw", password_encoded_uInt8, "PBKDF2", false, ["deriveBits"]);
            const hashedPassword_buff = yield crypto.subtle.deriveBits({
                name: "PBKDF2",
                hash: "SHA-256",
                salt: salt_uInt8,
                iterations: 10000
            }, password_key, 256);
            const hashedPassword_b64 = uInt8ArrToB64(new Uint8Array(hashedPassword_buff));
            try {
                const response1 = yield fetch("http://localhost:3000/signup", {
                    method: "POST",
                    headers: {
                        "content-type": "application/json",
                    },
                    body: JSON.stringify({
                        userId: username_b64.slice(0, 5),
                        requestedUsername: trialUsername,
                        userSalt_b64: uInt8ArrToB64(salt_uInt8),
                        hashedPassword_b64
                    })
                });
                let signupResponse = yield response1.json();
                return signupResponse;
            }
            catch (err) {
                console.log(err);
                const errorObject = {
                    msg: "Error Posting to 'http://localhost:3000/signup'",
                    errorFlag: true,
                    data: null,
                };
                return errorObject;
            }
        });
    }
    attemptLogin(username, password) {
        return __awaiter(this, void 0, void 0, function* () {
            const userId = yield this.usernameToUserId(username);
            // TODO: Key management.
            // Does this user already have a key pair for signing?
            if (this.keyPairS_c === undefined) { // If no, create a client keypair for signing and store it for later
                this.keyPairS_c = yield crypto.subtle.generateKey({
                    name: "ECDSA",
                    namedCurve: "P-256"
                }, true, ['sign', "verify"]);
            }
            // Export public signing JWK and store for later use.
            if (this.keyPairS_c === undefined)
                throw new Error("L8's keyPairS_c is undefined.");
            const pubSJWK_c = yield crypto.subtle.exportKey("jwk", this.keyPairS_c.publicKey);
            const privSJWK_c = yield crypto.subtle.exportKey("jwk", this.keyPairS_c.privateKey);
            //this.stringifiedJWKs.set("pubSJWK_c", JSON.stringify(pubSJWK_c));
            this.pubSJWK_c = pubSJWK_c;
            //this.stringifiedJWKs.set("privSJWK_c", JSON.stringify(privSJWK_c));
            this.privSJWK_c = privSJWK_c;
            // Get the user's salt and test that the userId is valid.
            const response1 = yield fetch("./login/precheck", {
                method: "POST",
                headers: {
                    "Content-Type": "application/JSON",
                },
                body: JSON.stringify({
                    pubSJWK_c: pubSJWK_c,
                    trialUserId: userId
                })
            });
            const response1_json = yield response1.json();
            if (response1_json.errorFlag === true) {
                throw new Error(`Login precheck failed. Server message: ${response1_json.msg}`);
            }
            const preCheckData = response1_json.data;
            //this.stringifiedJWKs.set('pubSJWK_s', preCheckData.pubSJWK_s);
            this.pubSJWK_s = JSON.parse(preCheckData.pubSJWK_s);
            //const pubSJWK_s:  = JSON.parse(preCheckData.pubSJWK_s);
            //Derive password locally & send the hash to l8 for validation.
            const password_encoded_uInt8 = new TextEncoder().encode(password);
            const password_key = yield crypto.subtle.importKey("raw", password_encoded_uInt8, "PBKDF2", false, ["deriveBits"]);
            const hashedPassword_buff = yield crypto.subtle.deriveBits({
                name: "PBKDF2",
                hash: "SHA-256",
                salt: b64ToUint8Arr(preCheckData.userSalt_b64, 0),
                iterations: 10000
            }, password_key, 256);
            const hashedPassword_b64 = uInt8ArrToB64(new Uint8Array(hashedPassword_buff));
            const response2 = yield fetch("/login", {
                method: "POST",
                headers: {
                    "Content-Type": "application/JSON",
                },
                body: JSON.stringify({
                    trialUserId: userId,
                    trialPassword: hashedPassword_b64
                })
            });
            const response2_json = yield response2.json();
            if (response2_json.errorFlag === true) {
                throw new Error(`Login failure. Server's message: ${response2_json.msg}`);
            }
            const loginData = response2_json.data;
            const { userId: userId2, signedHalfJWT, availableIdentities } = loginData;
            if (userId != userId2) {
                throw new Error("the userId used during login precheck does not match that returned after the login was attempted.");
            }
            const { halfJWT, authSignature_b64 } = signedHalfJWT;
            const halfJWTValidation = yield this.verifySignedObject(halfJWT, this.pubSJWK_s, authSignature_b64);
            if (halfJWTValidation === false) {
                throw new Error("Server's response could not be verified with the pubSJWK_s previously provided.");
            }
            else {
                this.halfJWT = halfJWT;
                const L8Response = {
                    msg: "Server has provided the following identities: ",
                    errorFlag: false,
                    data: {
                        availableIdentities: availableIdentities,
                    }
                };
                return L8Response;
            }
        });
    }
    chooseIdentity(username, chosenIdentity) {
        return __awaiter(this, void 0, void 0, function* () {
            // Use fetch to POST a request to the server containing the chosen identity and the halfJWT
            if (this.keyPairS_c === undefined)
                throw new Error("Client key pair is undefined. It needs initiation.");
            const privSKey_c = this.keyPairS_c.privateKey;
            if (this.halfJWT === undefined)
                throw new Error("this.halfJWT must be defined before identity is chosen.");
            const authSignature_c_b64 = yield this.signObject(this.halfJWT, privSKey_c);
            const userId = yield this.usernameToUserId(username);
            const response1 = yield fetch("http://localhost:3000/login/identity", {
                method: "POST",
                headers: {
                    "content-type": "application/json",
                    "x-signedhalfjwt-c": JSON.stringify({ halfJWT: this.halfJWT, authSignature_c_b64 }),
                },
                body: JSON.stringify({
                    userId,
                    chosenIdentity
                })
            });
            const response1_json = yield response1.json();
            if (response1_json.errorFlag === true) {
                throw new Error(`Error after 'POST' to /login/identity, ${response1_json.msg}`);
            }
            const chooseIdentityData = response1_json.data;
            //const pubSJWK_s = this.stringifiedJWKs.get('pubSJWK_s');
            if (this.pubSJWK_s === undefined)
                throw new Error("Server's public signing JWK was not found.");
            //const pubSJWK = JSON.parse(this.pubSJWK_s);
            const { chosenIdentity: chosenIdentity2, signedFullJWT } = chooseIdentityData;
            const { fullJWT, signature_b64 } = signedFullJWT;
            console.log("****", fullJWT);
            const fullJWTVerification = yield this.verifySignedObject(fullJWT, this.pubSJWK_s, signature_b64);
            if (fullJWTVerification === false) {
                throw new Error("fullJWT did not pass verification");
            }
            else {
                if (chosenIdentity != chosenIdentity2) {
                    throw new Error("Chosen Identity Corruption.");
                }
                yield this.registerCitizenship(fullJWT, chosenIdentity); // Probably should be an asynchronous IndexedDB write in time.
                return {
                    errorFlag: false,
                    msg: "Citizenship registered.",
                    data: null
                };
            }
        });
    }
    registerCitizenship(fullJWT, chosenIdentity) {
        return __awaiter(this, void 0, void 0, function* () {
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
            }
            catch (err) {
                console.log("Errror while registering the citizen.", err);
            }
        });
    }
    establishTunnel() {
        return __awaiter(this, void 0, void 0, function* () {
            // Create a key pair for doing DH with the service provider and save for later.
            this.keyPairDH_spa = yield crypto.subtle.generateKey({
                name: "ECDH",
                namedCurve: "P-256"
            }, true, ["deriveKey", "deriveBits"]);
            let pubDHJWK_spa = yield crypto.subtle.exportKey("jwk", this.keyPairDH_spa.publicKey);
            const pubDHJWK_spa_str = JSON.stringify(pubDHJWK_spa);
            //this.stringifiedJWKs.set("pubDHJWK_spa", pubDHJWK_spa_str);
            const pubSJWK_spa_str = sessionStorage.getItem("pubSJWK_c"); //note conversion from 'client'(c) to 'single page application' (spa).
            if (!pubSJWK_spa_str)
                throw new Error("pubSJWK_c was not set.");
            const fullJWT_spa_str = sessionStorage.getItem("fullJWT");
            const citizen = sessionStorage.getItem("citizen");
            if (!fullJWT_spa_str || !citizen)
                throw new Error("fullJWT or citizen not properly initialized.");
            const fullJWT_spa_obj = JSON.parse(fullJWT_spa_str);
            const privSJWK_spa_str = sessionStorage.getItem("privSJWK_c"); //note conversion from 'client'(c) to 'single page application' (spa).
            if (!privSJWK_spa_str)
                throw new Error("Signing key was not initialized.");
            const privSJWK_spa = JSON.parse(privSJWK_spa_str);
            const privSKey_spa = yield crypto.subtle.importKey("jwk", privSJWK_spa, {
                name: "ECDSA",
                namedCurve: "P-256",
            }, false, ["sign"]);
            const JWTauthSignature_b64 = yield this.signObject(fullJWT_spa_obj, privSKey_spa); // TODO: Sign obj or str?
            const signedFullJWT_spa2p = {
                fullJWT: fullJWT_spa_obj,
                signature_b64: JWTauthSignature_b64
            };
            const response1 = yield fetch("http://localhost:3000/ecdhinit", {
                method: "POST",
                headers: {
                    "content-type": "application/JSON",
                    "x-citizen": citizen,
                    "x-signedfulljwt-spa": JSON.stringify(signedFullJWT_spa2p),
                    "x-pubdhjwk-spa2m": pubDHJWK_spa_str,
                    "x-pubsjwk-spa2m": pubSJWK_spa_str
                },
                body: JSON.stringify({
                    "msg": "SPA Attempting ECDH",
                    "erroFlag": null,
                    "data": null
                })
            });
            const response1_json = yield response1.json(); //Almost an <ISealedEnvelope> 
            //At this point, you should have everything you need to message the module end-to-end encrypted.
            const pubsjwk_m2spa_str = response1.headers.get('x-pubsjwk-m2spa');
            const pubdhjwk_m2spa_str = response1.headers.get('x-pubdhjwk-m2spa');
            const sharedSalt_b64 = response1.headers.get('x-sharedsalt-b64');
            if (!pubsjwk_m2spa_str)
                throw new Error("pubsjwk_m2spa_str undefined or null.");
            if (!pubdhjwk_m2spa_str)
                throw new Error("pubsjwk_m2spa_str undefined or null.");
            if (!sharedSalt_b64)
                throw new Error("sharedSalt_b64 undefined or null.");
            const pubSJWK_m2spa = JSON.parse(pubsjwk_m2spa_str);
            const pubDHJWK_m2spa = JSON.parse(pubdhjwk_m2spa_str);
            this.pubSJWK_m2spa = pubSJWK_m2spa;
            this.pubDHJWK_m2spa = pubDHJWK_m2spa;
            this.sharedSalt_b64 = sharedSalt_b64;
            yield this.doubleDerivedSharedSecret(); // Side Effects*
            //Symmetric decryption test. In the future, a signature should be checked first before any decryption using a pubSJWK_m2spa served by the L8 reverse proxy.
            // TOMORROWS LABOUT JULY 31, 2022
            const encryptedData_b64_m = response1_json.encryptedData_b64;
            try {
                const plaintextDataFromModule_str = yield this.symmetricDecrypt(encryptedData_b64_m);
                const plaintextDataFromModule_obj = JSON.parse(plaintextDataFromModule_str);
                if (plaintextDataFromModule_obj === true) {
                    throw new Error("The symmetric decryption test failed.");
                }
            }
            catch (err) {
                console.log("[Error while performing symmetriDecrypt on the Service Provider's response.]", err);
            }
            const plaintextDataObj_spa2m = {
                init: true,
                errorFlag: false,
                path: null,
                msg: null,
                method: null,
                query: null,
                options: null,
                data: null
            };
            const plaintextDataObj_spa2m_str = JSON.stringify(plaintextDataObj_spa2m);
            const encryptedDataObj_spa2m_b64 = yield this.symmetricEncrypt(plaintextDataObj_spa2m_str);
            const signature_b64_spa2m = yield this.signString(encryptedDataObj_spa2m_b64, privSKey_spa);
            const sealedEnvelope_spa2m = {
                errorFlag: false,
                msg: "SPA is testing the initiated tunnel.",
                encryptedData_b64: encryptedDataObj_spa2m_b64,
                encryptedDataSignature_b64: signature_b64_spa2m
            };
            const response2 = yield fetch("http://localhost:3000/proxyme", {
                method: "POST",
                headers: {
                    "content-type": "application/json",
                    "x-citizen": citizen,
                    "x-signedfulljwt-spa": JSON.stringify(signedFullJWT_spa2p),
                },
                body: JSON.stringify({ sealedEnvelope_spa2m })
            });
            const response2_obj = yield response2.json();
            if (response2_obj.errorFlag === true) {
                // Register an error.
            }
            else {
                try {
                    if (!this.pubSJWK_m2spa)
                        throw new Error("pubSJWK_m2spa was not properly initialized.");
                    const { encryptedData_b64, encryptedDataSignature_b64 } = response2_obj;
                    const encryptedDataValidation = yield this.verifySignedString(encryptedData_b64, this.pubSJWK_m2spa, encryptedDataSignature_b64);
                    if (encryptedDataValidation === false) {
                    }
                    else {
                        const plainText_m2spa_str = yield this.symmetricDecrypt(response2_obj.encryptedData_b64);
                        const { errorFlag, msg, data } = JSON.parse(plainText_m2spa_str);
                        if (msg)
                            console.log("[response2.msg from fetch 'http://localhost:3000/proxyme']: ", msg);
                        if (errorFlag === true)
                            throw new Error(`Service Provider is reporting and error: ${msg}`);
                    }
                }
                catch (err) {
                    console.log("Error while decrypting or validating the sealed envelope.", err);
                }
            }
            ;
        });
    }
    proxy(data) {
        return __awaiter(this, void 0, void 0, function* () {
            if (false)
                throw new Error("L8 is not properly initialized. You cannot send E2E encrypted messages yet. Try loging in.");
            let citizen = sessionStorage.getItem("citizen");
            let fullJWT_spa_str = sessionStorage.getItem("fullJWT");
            let privSJWK_spa_str = sessionStorage.getItem("privSJWK_c"); // Again note the conversion of 'c' to 'spa'.
            if (!fullJWT_spa_str || !citizen) {
                throw new Error("Retrieval of 'citizen' and/or 'fullJWT' failed");
            }
            else if (!privSJWK_spa_str) {
                throw new Error("privSJWK_c is not initialized on sessionStorage.");
            }
            else {
                const fullJWT_spa_obj = JSON.parse(fullJWT_spa_str);
                const privSJWK_spa = JSON.parse(privSJWK_spa_str);
                const privSKey_spa = yield crypto.subtle.importKey("jwk", privSJWK_spa, {
                    name: "ECDSA",
                    namedCurve: "P-256",
                }, false, ["sign"]);
                const fullJWTSig_b64 = yield this.signObject(fullJWT_spa_obj, privSKey_spa);
                const signedFullJWT_spa2p = {
                    fullJWT: fullJWT_spa_obj,
                    signature_b64: fullJWTSig_b64
                };
                // Encrypt the data
                const data_str = JSON.stringify(data);
                const encryptedData_b64 = yield this.symmetricEncrypt(data_str);
                const encryptedDataSignature_b64 = yield this.signString(encryptedData_b64, privSKey_spa);
                const sealedEnvelope_spa2m = {
                    errorFlag: false,
                    msg: "From SPA to Service Provider",
                    encryptedData_b64,
                    encryptedDataSignature_b64
                };
                const response1 = yield fetch("http://localhost:3000/proxyme", {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/JSON",
                        "x-citizen": citizen,
                        "x-signedfulljwt-spa": JSON.stringify(signedFullJWT_spa2p),
                    },
                    body: JSON.stringify({ sealedEnvelope_spa2m })
                });
                const response1_obj = yield response1.json();
                try {
                    const { errorFlag, msg, encryptedData_b64, encryptedDataSignature_b64 } = response1_obj;
                    if (msg)
                        console.log("[response1.msg from 'http://localhost:3000/proxyme']: ", msg);
                    if (errorFlag === true)
                        throw new Error("Service Provider is reporting an error in it's response.");
                    if (!this.pubDHJWK_m2spa)
                        throw new Error("this.pubSJWK_m2spa was not properly initialized.");
                    const encryptedMsgValidation = yield this.verifySignedString(encryptedData_b64, this.pubSJWK_m2spa, encryptedDataSignature_b64);
                    if (encryptedMsgValidation === false) {
                        throw new Error("The encrypted data from the service provider did not pass validation.");
                    }
                    else {
                        const unencryptedData = yield this.symmetricDecrypt(encryptedData_b64);
                        return JSON.parse(unencryptedData);
                    }
                }
                catch (err) {
                }
            }
        });
    }
    //PRIVATE FUNCTIONS
    usernameToUserId(username) {
        return __awaiter(this, void 0, void 0, function* () {
            const username_uInt8 = new TextEncoder().encode(username);
            const username_sha256 = yield crypto.subtle.digest('SHA-256', username_uInt8);
            const username_b64 = uInt8ArrToB64(new Uint8Array(username_sha256));
            const userId = username_b64.slice(0, 5);
            return userId;
        });
    }
    ;
    verifySignedObject(object, pubSJWK, signature_b64) {
        return __awaiter(this, void 0, void 0, function* () {
            const stringifiedObject = JSON.stringify(object);
            const signature_uInt8 = b64ToUint8Arr(signature_b64, 0);
            const pubSKey_s = yield crypto.subtle.importKey("jwk", pubSJWK, {
                name: "ECDSA",
                namedCurve: "P-256",
            }, false, ['verify']);
            const textToVerify = new TextEncoder().encode(stringifiedObject);
            const verification = yield crypto.subtle.verify({
                name: "ECDSA",
                hash: "SHA-256"
            }, pubSKey_s, // Server's public ECDSA key
            signature_uInt8, // Server's signature
            textToVerify // Encrypted object
            );
            return verification;
        });
    }
    ;
    verifySignedString(string, pubSJWK, signature_b64) {
        return __awaiter(this, void 0, void 0, function* () {
            const signature_uInt8 = b64ToUint8Arr(signature_b64, 0);
            const pubSKey_s = yield crypto.subtle.importKey("jwk", pubSJWK, {
                name: "ECDSA",
                namedCurve: "P-256",
            }, false, ['verify']);
            const textToVerify = new TextEncoder().encode(string);
            const verification = yield crypto.subtle.verify({
                name: "ECDSA",
                hash: "SHA-256"
            }, pubSKey_s, // Server's public ECDSA key
            signature_uInt8, // Server's signature
            textToVerify // Encrypted object
            );
            return verification;
        });
    }
    ;
    signObject(object, privSKey) {
        return __awaiter(this, void 0, void 0, function* () {
            const object_string = JSON.stringify(object);
            const object_uInt8 = new TextEncoder().encode(object_string);
            const authSig_c = yield crypto.subtle.sign({
                name: "ECDSA",
                hash: "SHA-256"
            }, privSKey, object_uInt8);
            const authSignature_c_b64 = uInt8ArrToB64(new Uint8Array(authSig_c));
            return authSignature_c_b64;
        });
    }
    ;
    signString(string, privSKey) {
        return __awaiter(this, void 0, void 0, function* () {
            const string_uInt8 = new TextEncoder().encode(string);
            const authSig_c = yield crypto.subtle.sign({
                name: "ECDSA",
                hash: "SHA-256"
            }, privSKey, string_uInt8);
            const authSignature_c_b64 = uInt8ArrToB64(new Uint8Array(authSig_c));
            return authSignature_c_b64;
        });
    }
    ;
    doubleDerivedSharedSecret() {
        return __awaiter(this, void 0, void 0, function* () {
            if (!this.sharedSalt_b64)
                throw new Error("Layer8 sharedSalt_b64 was not initialized properly.");
            if (!this.pubDHJWK_m2spa)
                throw new Error("Layer8 pubDHJWK was not initialized properly.");
            if (!this.keyPairDH_spa)
                throw new Error("Layer8 keyPairDH was not initialized properly.");
            const sharedSalt_uInt8 = b64ToUint8Arr(this.sharedSalt_b64, 0);
            const pubDHKey_m2spa = yield crypto.subtle.importKey("jwk", this.pubDHJWK_m2spa, {
                name: "ECDH",
                namedCurve: "P-256"
            }, true, []);
            const ecdhResult = yield crypto.subtle.deriveBits({
                name: "ECDH",
                public: pubDHKey_m2spa
            }, this.keyPairDH_spa.privateKey, 256);
            const sharedKeyMaterial = yield crypto.subtle.importKey("raw", ecdhResult, {
                name: "PBKDF2"
            }, false, ["deriveBits"]);
            const sharedDerivedBits = yield crypto.subtle.deriveBits({
                name: "PBKDF2",
                salt: sharedSalt_uInt8,
                iterations: 10000,
                hash: 'SHA-256'
            }, sharedKeyMaterial, 256);
            this.sharedSecret = yield crypto.subtle.importKey('raw', sharedDerivedBits, {
                name: "AES-GCM",
            }, true, ['encrypt', 'decrypt']);
            return null;
        });
    }
    ;
    symmetricDecrypt(ciphertext_b64) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!this.sharedSecret)
                throw new Error("Layer 8 sharedSecret was not properly initialized.");
            const ciphertext = b64ToUint8Arr(ciphertext_b64, 0);
            const iv = ciphertext.slice(0, 16);
            const encrypted = ciphertext.slice(16);
            const plaintext_uInt8 = yield crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv }, this.sharedSecret, encrypted);
            const plaintext = new TextDecoder().decode(plaintext_uInt8);
            return plaintext;
        });
    }
    symmetricEncrypt(plaintext) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!this.sharedSecret)
                throw new Error("Layer8 this.sharedSecret was not properly initialized.");
            const plaintext_uInt8 = new TextEncoder().encode(plaintext);
            const iv = new Uint8Array(16);
            crypto.getRandomValues(iv);
            const encrypted = yield crypto.subtle.encrypt({ name: "AES-GCM", iv: iv }, this.sharedSecret, plaintext_uInt8);
            const ciphertext_uInt8 = new Uint8Array([
                ...iv,
                ...new Uint8Array(encrypted)
            ]);
            const ciphertext_b64 = uInt8ArrToB64(ciphertext_uInt8);
            return ciphertext_b64;
        });
    }
}
window.L8 = new L8();
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiTDhfbW9kdWxlX3YxLmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiTDhfbW9kdWxlX3YxLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7Ozs7Ozs7OztBQUFBLG1CQUFtQjtBQUNuQixPQUFPLENBQUMsR0FBRyxDQUFDLGdDQUFnQyxFQUFFLElBQUksQ0FBQyxDQUFDO0FBRXBELE9BQU8sRUFBRSxhQUFhLEVBQUUsYUFBYSxFQUFFLE1BQU0sZ0JBQWdCLENBQUM7QUEwRTlELDBCQUEwQjtBQUMxQixNQUFNLEVBQUU7SUFlTixnQkFBZSxDQUFDO0lBRWhCLG1CQUFtQjtJQUNMLHNCQUFzQixDQUFDLEVBQWlCOztZQUNwRCx5QkFBeUI7WUFDekIsSUFBRyxFQUFFLEVBQUM7Z0JBQ0osT0FBTyxJQUFJLENBQUM7YUFDYjtpQkFBTTtnQkFDTCxNQUFNLElBQUksS0FBSyxDQUFDLHVDQUF1QyxDQUFDLENBQUM7YUFDMUQ7UUFDSCxDQUFDO0tBQUE7SUFFSyx5QkFBeUIsQ0FBQyxlQUF1Qjs7WUFDckQscURBQXFEO1lBQ3JELElBQUc7Z0JBQ0QsTUFBTSxTQUFTLEdBQUcsTUFBTSxJQUFJLENBQUMsc0JBQXNCLENBQUMsZUFBZSxDQUFDLENBQUM7Z0JBQ3JFLElBQUcsU0FBUyxLQUFLLEtBQUssRUFBRTtvQkFDdEIsT0FBTyxDQUFDLEdBQUcsQ0FBQywyREFBMkQsQ0FBQyxDQUFDO29CQUN6RSxPQUFPLEtBQUssQ0FBQztpQkFDZDtxQkFBTTtvQkFDTCxJQUFJLENBQUMsaUJBQWlCLEdBQUcsZUFBZSxDQUFDO29CQUN6QyxJQUFJLENBQUMsZUFBZSxHQUFHLElBQUksQ0FBQztvQkFDNUIsT0FBTyxJQUFJLENBQUM7aUJBQ2I7YUFDRjtZQUFDLE9BQU0sR0FBRyxFQUFFO2dCQUNYLE9BQU8sQ0FBQyxHQUFHLENBQUMsR0FBRyxDQUFDLENBQUM7Z0JBQ2pCLE9BQU8sS0FBSyxDQUFDO2FBQ2Q7UUFDSCxDQUFDO0tBQUE7SUFFSyxXQUFXLENBQUMsYUFBcUIs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QUMzQixNQUFNLFNBQVMsR0FBRyxNQUFNLE1BQU0sQ0FBQyxNQUFNLENBQUMsT0FBTyxDQUMxQyxFQUFDLElBQUksRUFBRSxTQUFTLEVBQUUsRUFBRSxFQUFFLEVBQUUsRUFBQyxFQUN6QixJQUFJLENBQUMsWUFBWSxFQUNqQixlQUFlLENBQ2pCLENBQUE7WUFFRCxNQUFNLGdCQUFnQixHQUFHLElBQUksVUFBVSxDQUFDO2dCQUNyQyxHQUFHLEVBQUU7Z0JBQ0wsR0FBRyxJQUFJLFVBQVUsQ0FBQyxTQUFTLENBQUM7YUFDOUIsQ0FBQyxDQUFDO1lBRUgsTUFBTSxjQUFjLEdBQUcsYUFBYSxDQUFDLGdCQUFnQixDQUFDLENBQUM7WUFFdkQsT0FBTyxjQUFjLENBQUM7UUFDeEIsQ0FBQztLQUFBO0NBRUY7QUFFRCxNQUFNLENBQUMsRUFBRSxHQUFHLElBQUksRUFBRSxFQUFFLENBQUMiLCJzb3VyY2VzQ29udGVudCI6WyIvLyBDT05ORUNUSU9OIENIRUNLXHJcbmNvbnNvbGUubG9nKFwiJ0w4X21vZHVsZV92MS5qcycgY29ubmVjdGVkLi4uXCIsIFwidjhcIik7XHJcblxyXG5pbXBvcnQgeyBiNjRUb1VpbnQ4QXJyLCB1SW50OEFyclRvQjY0IH0gZnJvbSAnLi9iNjRfdXRpbHMuanMnO1xyXG5cclxuZGVjbGFyZSBnbG9iYWwgeyAvLyBEZWNsYXJlIGFuLi4uXHJcbiAgaW50ZXJmYWNlIFdpbmRvdyB7IEw4OiBMOCB9IC8vIC4uLkludGVyZmFjZSBhcyBHbG9iYWwgY2FsbGVkICdXaW5kb3cnIHRoYXQgaGFzIHRoZSBwcm9wZXJ0eSAnTDgnXHJcbn1cclxuXHJcbi8vIFRZUEVTXHJcbnR5cGUgU2lnbnVwRGF0YSA9IHsgYXZhaWxhYmxlSWRlbnRpdGllczogc3RyaW5nW10gfTtcclxudHlwZSBBdmFpbGFibGVJZGVudGl0aWVzID0geyBhdmFpbGFibGVJZGVudGl0aWVzOiBzdHJpbmdbXSB9O1xyXG5cclxudHlwZSBQcmVDaGVja0RhdGEgPSB7IFxyXG4gIHVzZXJTYWx0X2I2NDogc3RyaW5nLFxyXG4gIHB1YlNKV0tfczogc3RyaW5nXHJcbn1cclxuXHJcbnR5cGUgTG9naW5EYXRhID0ge1xyXG4gIHVzZXJJZDogc3RyaW5nLFxyXG4gIHNpZ25lZEhhbGZKV1Q6IHsgaGFsZkpXVDogSUhhbGZKV1QsIGF1dGhTaWduYXR1cmVfYjY0OiBzdHJpbmcgfSxcclxuICBhdmFpbGFibGVJZGVudGl0aWVzOiBzdHJpbmdbXSxcclxufVxyXG5cclxudHlwZSBDaG9vc2VJZGVudGl0eURhdGEgPSB7XHJcbiAgY2hvc2VuSWRlbnRpdHk6IHN0cmluZyxcclxuICBzaWduZWRGdWxsSldUOiBJU2lnbmVkRnVsbEpXVFxyXG59XHJcblxyXG4vLyBJTlRFUkZBQ0VTXHJcbmludGVyZmFjZSBJU3RkUmVzPFQ+IHtcclxuICBlcnJvckZsYWc6IGJvb2xlYW4sXHJcbiAgbXNnOiBzdHJpbmcgfCBudWxsLFxyXG4gIGRhdGE6IFQgfCBudWxsO1xyXG59XHJcblxyXG5pbnRlcmZhY2UgSUpXVEhlYWRlciB7XHJcbiAgdHlwOiBzdHJpbmcsXHJcbiAgc2lnOiBzdHJpbmdcclxufVxyXG5cclxuaW50ZXJmYWNlIElIYWxmSldUIHtcclxuICBKV1RIZWFkZXI6IHtcclxuICAgIHR5cDogc3RyaW5nLFxyXG4gICAgc2lnOiBzdHJpbmdcclxuICB9LFxyXG4gIGl2ZWRQYXlsb2FkX2VuY3J5cHRlZF9iNjQ6IHN0cmluZyxcclxuICBITUFDX2I2NDogc3RyaW5nLFxyXG59XHJcblxyXG5pbnRlcmZhY2UgSUZ1bGxKV1Qge1xyXG4gIEpXVEhlYWRlcjogSUpXVEhlYWRlcixcclxuICBpdmVkUGF5bG9hZF9lbmNyeXB0ZWRfYjY0OiBzdHJpbmcsXHJcbiAgSE1BQ19iNjQ6IHN0cmluZ1xyXG59XHJcblxyXG5cclxuaW50ZXJmYWNlIElTaWduZWRGdWxsSldUIHtcclxuICBmdWxsSldUOiBJRnVsbEpXVCxcclxuICBzaWduYXR1cmVfYjY0OiBzdHJpbmdcclxufVxyXG5cclxuaW50ZXJmYWNlIElFbmNyeXB0ZWREYXRhX3NwYTJtIGV4dGVuZHMgSVN0ZFJlczxKU09OPiB7XHJcbiAgaW5pdDogYm9vbGVhbixcclxuICBtZXRob2Q6IHN0cmluZyB8IG51bGwsXHJcbiAgcGF0aDogc3RyaW5nIHwgbnVsbCxcclxuICBxdWVyeTogb2JqZWN0IHwgbnVsbCxcclxuICBvcHRpb25zOiBvYmplY3QgfCBudWxsLFxyXG59XHJcblxyXG5pbnRlcmZhY2UgSVNlYWxlZEVudmVsb3BlIHtcclxuICBlcnJvckZsYWc6IGJvb2xlYW4sXHJcbiAgbXNnOiBzdHJpbmcgfCBudWxsLFxyXG4gIGVuY3J5cHRlZERhdGFfYjY0OiBzdHJpbmcsXHJcbiAgZW5jcnlwdGVkRGF0YVNpZ25hdHVyZV9iNjQ6IHN0cmluZ1xyXG59XHJcblxyXG4vLyBMOCBDTEFTUyBJTVBMRU1FTlRBVElPTlxyXG5jbGFzcyBMOCB7XHJcbiAgcHJpdmF0ZSBzZXJ2aWNlUHJvdmlkZXJJZDogc3RyaW5nIHwgdW5kZWZpbmVkO1xyXG4gIHByaXZhdGUgcHJvdmlkZXJJc1ZhbGlkOiBib29sZWFuIHwgdW5kZWZpbmVkO1xyXG4gIHByaXZhdGUga2V5UGFpclNfYzogQ3J5cHRvS2V5UGFpciB8IHVuZGVmaW5lZDtcclxuICBwcml2YXRlIGhhbGZKV1Q6IElIYWxmSldUIHwgdW5kZWZpbmVkO1xyXG4gIC8vcHJpdmF0ZSBzdHJpbmdpZmllZEpXS3M6IE1hcDxzdHJpbmcsIHN0cmluZz4gPSBuZXcgTWFwKCk7XHJcbiAgcHJpdmF0ZSBrZXlQYWlyREhfc3BhOiBDcnlwdG9LZXlQYWlyIHwgdW5kZWZpbmVkO1xyXG4gIHByaXZhdGUgcHViU0pXS19tMnNwYTogSnNvbldlYktleSB8IHVuZGVmaW5lZDtcclxuICBwcml2YXRlIHB1YkRISldLX20yc3BhOiBKc29uV2ViS2V5IHwgdW5kZWZpbmVkO1xyXG4gIHByaXZhdGUgc2hhcmVkU2FsdF9iNjQ6IHN0cmluZyB8IHVuZGVmaW5lZDtcclxuICBwcml2YXRlIHNoYXJlZFNlY3JldDogQ3J5cHRvS2V5IHwgdW5kZWZpbmVkO1xyXG4gIHByaXZhdGUgcHJpdlNKV0tfYzogSnNvbldlYktleSB8IHVuZGVmaW5lZDtcclxuICBwcml2YXRlIHB1YlNKV0tfYzogSnNvbldlYktleSB8IHVuZGVmaW5lZDtcclxuICBwcml2YXRlIHB1YlNKV0tfczogSnNvbldlYktleSB8IHVuZGVmaW5lZDtcclxuXHJcbiAgY29uc3RydWN0b3IoKSB7fVxyXG5cclxuICAvLyBQVUJMSUMgRlVOQ1RJT05TXHJcbiAgcHJpdmF0ZSBhc3luYyBjaGVja1NlcnZpY2VQcm92aWRlcklkKGlkOiBzdHJpbmcgfCBudWxsKTogUHJvbWlzZTxib29sZWFuPiB7XHJcbiAgICAvLyBNb2NrZWQgaW1wbGVtZW50YXRpb24uXHJcbiAgICBpZihpZCl7XHJcbiAgICAgIHJldHVybiB0cnVlO1xyXG4gICAgfSBlbHNlIHtcclxuICAgICAgdGhyb3cgbmV3IEVycm9yKFwiRXJyb3Igd2hpbGUgY2hlY2tpbmcgc2VydmljZSBwcm92aWRlclwiKTtcclxuICAgIH1cclxuICB9XHJcblxyXG4gIGFzeW5jIHJlZ2lzdGVyU2VydmljZVByb3ZpZGVySWQodHJpYWxQcm92aWRlcklkOiBzdHJpbmcpOiBQcm9taXNlPGJvb2xlYW4+IHtcclxuICAgIC8vIFRPRE86IFRoZXJlIGlzIHlldCBubyBwcm9wb3NlZCBtZWNoYW5pc20gZm9yIHRoaXMuXHJcbiAgICB0cnl7XHJcbiAgICAgIGNvbnN0IGlkSXNWYWxpZCA9IGF3YWl0IHRoaXMuY2hlY2tTZXJ2aWNlUHJvdmlkZXJJZCh0cmlhbFByb3ZpZGVySWQpO1xyXG4gICAgICBpZihpZElzVmFsaWQgPT09IGZhbHNlICl7XHJcbiAgICAgICAgY29uc29sZS5sb2coXCJzZXJ2aWNlUHJvdmlkZXJJZCBpcyBpbnZhbGlkLiBMYXllcjggZmFpbGVkIHRvIGluaXRpYWxpemVcIik7XHJcbiAgICAgICAgcmV0dXJuIGZhbHNlO1xyXG4gICAgICB9IGVsc2Uge1xyXG4gICAgICAgIHRoaXMuc2VydmljZVByb3ZpZGVySWQgPSB0cmlhbFByb3ZpZGVySWQ7XHJcbiAgICAgICAgdGhpcy5wcm92aWRlcklzVmFsaWQgPSB0cnVlO1xyXG4gICAgICAgIHJldHVybiB0cnVlO1xyXG4gICAgICB9XHJcbiAgICB9IGNhdGNoKGVycikge1xyXG4gICAgICBjb25zb2xlLmxvZyhlcnIpO1xyXG4gICAgICByZXR1cm4gZmFsc2U7XHJcbiAgICB9XHJcbiAgfVxyXG5cclxuICBhc3luYyB0cmlhbFNpZ251cCh0cmlhbFVzZXJuYW1lOiBzdHJpbmcsIHBhc3N3b3JkOiBzdHJpbmcpOiBQcm9taXNlPElTdGRSZXM8U2lnbnVwRGF0YT4+IHtcclxuICAgIGNvbnN0IHVzZXJuYW1lX3VJbnQ4ID0gbmV3IFRleHRFbmNvZGVyKCkuZW5jb2RlKHRyaWFsVXNlcm5hbWUpO1xyXG4gICAgY29uc3QgdXNlcm5hbWVfc2hhMjU2ID0gYXdhaXQgY3J5cHRvLnN1YnRsZS5kaWdlc3QoJ1NIQS0yNTYnLCB1c2VybmFtZV91SW50OCk7XHJcbiAgICBjb25zdCB1c2VybmFtZV9iNjQgPSB1SW50OEFyclRvQjY0KG5ldyBVaW50OEFycmF5KHVzZXJuYW1lX3NoYTI1NikpO1xyXG4gICAgY29uc3Qgc2FsdF91SW50OCA9IGNyeXB0by5nZXRSYW5kb21WYWx1ZXMobmV3IFVpbnQ4QXJyYXkoMTYpKTtcclxuICAgIGNvbnN0IHBhc3N3b3JkX2VuY29kZWRfdUludDggPSBuZXcgVGV4dEVuY29kZXIoKS5lbmNvZGUocGFzc3dvcmQpO1xyXG5cclxuICAgIGNvbnN0IHBhc3N3b3JkX2tleSA9IGF3YWl0IGNyeXB0by5zdWJ0bGUuaW1wb3J0S2V5KFxyXG4gICAgICBcInJhd1wiLFxyXG4gICAgICBwYXNzd29yZF9lbmNvZGVkX3VJbnQ4LFxyXG4gICAgICBcIlBCS0RGMlwiLFxyXG4gICAgICBmYWxzZSxcclxuICAgICAgW1wiZGVyaXZlQml0c1wiXVxyXG4gICAgKVxyXG5cclxuICAgIGNvbnN0IGhhc2hlZFBhc3N3b3JkX2J1ZmYgPSBhd2FpdCBjcnlwdG8uc3VidGxlLmRlcml2ZUJpdHMoXHJcbiAgICAgIHtcclxuICAgICAgICBuYW1lOiBcIlBCS0RGMlwiLFxyXG4gICAgICAgIGhhc2g6IFwiU0hBLTI1NlwiLFxyXG4gICAgICAgIHNhbHQ6IHNhbHRfdUludDgsXHJcbiAgICAgICAgaXRlcmF0aW9uczogMTAwMDBcclxuICAgICAgfSxcclxuICAgICAgcGFzc3dvcmRfa2V5LFxyXG4gICAgICAyNTZcclxuICAgICk7XHJcblxyXG4gICAgY29uc3QgaGFzaGVkUGFzc3dvcmRfYjY0ID0gdUludDhBcnJUb0I2NChuZXcgVWludDhBcnJheShoYXNoZWRQYXNzd29yZF9idWZmKSk7XHJcblxyXG4gICAgdHJ5IHtcclxuICAgICAgY29uc3QgcmVzcG9uc2UxID0gYXdhaXQgZmV0Y2goXCJodHRwOi8vbG9jYWxob3N0OjMwMDAvc2lnbnVwXCIse1xyXG4gICAgICAgIG1ldGhvZDogXCJQT1NUXCIsXHJcbiAgICAgICAgaGVhZGVyczoge1xyXG4gICAgICAgICAgXCJjb250ZW50LXR5cGVcIjogXCJhcHBsaWNhdGlvbi9qc29uXCIsXHJcbiAgICAgICAgfSxcclxuICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeSh7XHJcbiAgICAgICAgICB1c2VySWQ6IHVzZXJuYW1lX2I2NC5zbGljZSgwLDUpLFxyXG4gICAgICAgICAgcmVxdWVzdGVkVXNlcm5hbWU6IHRyaWFsVXNlcm5hbWUsXHJcbiAgICAgICAgICB1c2VyU2FsdF9iNjQ6IHVJbnQ4QXJyVG9CNjQoc2FsdF91SW50OCksXHJcbiAgICAgICAgICBoYXNoZWRQYXNzd29yZF9iNjRcclxuICAgICAgICB9KVxyXG4gICAgICB9KTtcclxuXHJcbiAgICAgIGxldCBzaWdudXBSZXNwb25zZTogSVN0ZFJlczxTaWdudXBEYXRhPiA9IGF3YWl0IHJlc3BvbnNlMS5qc29uKClcclxuICAgICAgcmV0dXJuIHNpZ251cFJlc3BvbnNlO1xyXG4gICAgfSBjYXRjaCAoZXJyKSB7XHJcbiAgICAgIGNvbnNvbGUubG9nKGVycik7XHJcbiAgICAgIGNvbnN0IGVycm9yT2JqZWN0ID0ge1xyXG4gICAgICAgIG1zZzogXCJFcnJvciBQb3N0aW5nIHRvICdodHRwOi8vbG9jYWxob3N0OjMwMDAvc2lnbnVwJ1wiLFxyXG4gICAgICAgIGVycm9yRmxhZzogdHJ1ZSxcclxuICAgICAgICBkYXRhOiBudWxsLFxyXG4gICAgICB9O1xyXG4gICAgICByZXR1cm4gZXJyb3JPYmplY3Q7XHJcbiAgICB9XHJcbiAgfVxyXG5cclxuICBhc3luYyBhdHRlbXB0TG9naW4odXNlcm5hbWU6IHN0cmluZywgcGFzc3dvcmQ6IHN0cmluZyk6IFByb21pc2U8SVN0ZFJlczxBdmFpbGFibGVJZGVudGl0aWVzPj4ge1xyXG4gICAgY29uc3QgdXNlcklkID0gYXdhaXQgdGhpcy51c2VybmFtZVRvVXNlcklkKHVzZXJuYW1lKTtcclxuICAgIC8vIFRPRE86IEtleSBtYW5hZ2VtZW50LlxyXG4gICAgLy8gRG9lcyB0aGlzIHVzZXIgYWxyZWFkeSBoYXZlIGEga2V5IHBhaXIgZm9yIHNpZ25pbmc/XHJcbiAgICBpZih0aGlzLmtleVBhaXJTX2MgPT09IHVuZGVmaW5lZCl7IC8vIElmIG5vLCBjcmVhdGUgYSBjbGllbnQga2V5cGFpciBmb3Igc2lnbmluZyBhbmQgc3RvcmUgaXQgZm9yIGxhdGVyXHJcbiAgICAgIHRoaXMua2V5UGFpclNfYyA9IGF3YWl0IGNyeXB0by5zdWJ0bGUuZ2VuZXJhdGVLZXkoXHJcbiAgICAgICAgICB7XHJcbiAgICAgICAgICAgIG5hbWU6IFwiRUNEU0FcIixcclxuICAgICAgICAgICAgbmFtZWRDdXJ2ZTogXCJQLTI1NlwiXHJcbiAgICAgICAgICB9LFxyXG4gICAgICAgICAgdHJ1ZSwgXHJcbiAgICAgICAgICBbJ3NpZ24nLCBcInZlcmlmeVwiXVxyXG4gICAgICApO1xyXG4gICAgfVxyXG4gICAgLy8gRXhwb3J0IHB1YmxpYyBzaWduaW5nIEpXSyBhbmQgc3RvcmUgZm9yIGxhdGVyIHVzZS5cclxuICAgIGlmKHRoaXMua2V5UGFpclNfYyA9PT0gdW5kZWZpbmVkKSB0aHJvdyBuZXcgRXJyb3IoXCJMOCdzIGtleVBhaXJTX2MgaXMgdW5kZWZpbmVkLlwiKTtcclxuICAgIGNvbnN0IHB1YlNKV0tfYyA9IGF3YWl0IGNyeXB0by5zdWJ0bGUuZXhwb3J0S2V5KFwiandrXCIsIDxDcnlwdG9LZXk+dGhpcy5rZXlQYWlyU19jLnB1YmxpY0tleSk7XHJcbiAgICBjb25zdCBwcml2U0pXS19jID0gYXdhaXQgY3J5cHRvLnN1YnRsZS5leHBvcnRLZXkoXCJqd2tcIiwgPENyeXB0b0tleT50aGlzLmtleVBhaXJTX2MucHJpdmF0ZUtleSk7XHJcblxyXG4gICAgLy90aGlzLnN0cmluZ2lmaWVkSldLcy5zZXQoXCJwdWJTSldLX2NcIiwgSlNPTi5zdHJpbmdpZnkocHViU0pXS19jKSk7XHJcbiAgICB0aGlzLnB1YlNKV0tfYyA9IHB1YlNKV0tfYztcclxuICAgIC8vdGhpcy5zdHJpbmdpZmllZEpXS3Muc2V0KFwicHJpdlNKV0tfY1wiLCBKU09OLnN0cmluZ2lmeShwcml2U0pXS19jKSk7XHJcbiAgICB0aGlzLnByaXZTSldLX2MgPSBwcml2U0pXS19jO1xyXG5cclxuICAgIC8vIEdldCB0aGUgdXNlcidzIHNhbHQgYW5kIHRlc3QgdGhhdCB0aGUgdXNlcklkIGlzIHZhbGlkLlxyXG4gICAgY29uc3QgcmVzcG9uc2UxID0gYXdhaXQgZmV0Y2goXCIuL2xvZ2luL3ByZWNoZWNrXCIsIHtcclxuICAgICAgICBtZXRob2Q6IFwiUE9TVFwiLFxyXG4gICAgICAgIGhlYWRlcnM6IHtcclxuICAgICAgICAgICBcIkNvbnRlbnQtVHlwZVwiOiBcImFwcGxpY2F0aW9uL0pTT05cIixcclxuICAgICAgICB9LFxyXG4gICAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KHtcclxuICAgICAgICAgIHB1YlNKV0tfYzogcHViU0pXS19jLFxyXG4gICAgICAgICAgdHJpYWxVc2VySWQ6IHVzZXJJZFxyXG4gICAgICAgfSlcclxuICAgIH0pXHJcblxyXG4gICAgY29uc3QgcmVzcG9uc2UxX2pzb246IElTdGRSZXM8UHJlQ2hlY2tEYXRhPiA9IGF3YWl0IHJlc3BvbnNlMS5qc29uKCk7XHJcblxyXG4gICAgaWYocmVzcG9uc2UxX2pzb24uZXJyb3JGbGFnID09PSB0cnVlKSB7XHJcbiAgICAgIHRocm93IG5ldyBFcnJvcihgTG9naW4gcHJlY2hlY2sgZmFpbGVkLiBTZXJ2ZXIgbWVzc2FnZTogJHtyZXNwb25zZTFfanNvbi5tc2d9YCk7XHJcbiAgICB9XHJcblxyXG4gICAgY29uc3QgcHJlQ2hlY2tEYXRhID0gPFByZUNoZWNrRGF0YT5yZXNwb25zZTFfanNvbi5kYXRhXHJcbiAgICAvL3RoaXMuc3RyaW5naWZpZWRKV0tzLnNldCgncHViU0pXS19zJywgcHJlQ2hlY2tEYXRhLnB1YlNKV0tfcyk7XHJcbiAgICB0aGlzLnB1YlNKV0tfcyA9IDxKc29uV2ViS2V5PkpTT04ucGFyc2UocHJlQ2hlY2tEYXRhLnB1YlNKV0tfcyk7XHJcbiAgICAvL2NvbnN0IHB1YlNKV0tfczogID0gSlNPTi5wYXJzZShwcmVDaGVja0RhdGEucHViU0pXS19zKTtcclxuXHJcbiAgICAvL0Rlcml2ZSBwYXNzd29yZCBsb2NhbGx5ICYgc2VuZCB0aGUgaGFzaCB0byBsOCBmb3IgdmFsaWRhdGlvbi5cclxuICAgIGNvbnN0IHBhc3N3b3JkX2VuY29kZWRfdUludDggPSBuZXcgVGV4dEVuY29kZXIoKS5lbmNvZGUocGFzc3dvcmQpO1xyXG4gICAgY29uc3QgcGFzc3dvcmRfa2V5ID0gYXdhaXQgY3J5cHRvLnN1YnRsZS5pbXBvcnRLZXkoXHJcbiAgICAgICBcInJhd1wiLFxyXG4gICAgICAgcGFzc3dvcmRfZW5jb2RlZF91SW50OCxcclxuICAgICAgIFwiUEJLREYyXCIsXHJcbiAgICAgICBmYWxzZSxcclxuICAgICAgIFtcImRlcml2ZUJpdHNcIl1cclxuICAgICk7XHJcbiAgICBjb25zdCBoYXNoZWRQYXNzd29yZF9idWZmID0gYXdhaXQgY3J5cHRvLnN1YnRsZS5kZXJpdmVCaXRzKFxyXG4gICAgICAge1xyXG4gICAgICAgICBuYW1lOiBcIlBCS0RGMlwiLFxyXG4gICAgICAgICBoYXNoOiBcIlNIQS0yNTZcIixcclxuICAgICAgICAgc2FsdDogYjY0VG9VaW50OEFycihwcmVDaGVja0RhdGEudXNlclNhbHRfYjY0LCAwKSxcclxuICAgICAgICAgaXRlcmF0aW9uczogMTAwMDBcclxuICAgICAgIH0sXHJcbiAgICAgICBwYXNzd29yZF9rZXksXHJcbiAgICAgICAyNTZcclxuICAgICk7XHJcbiAgICBjb25zdCBoYXNoZWRQYXNzd29yZF9iNjQgPSB1SW50OEFyclRvQjY0KG5ldyBVaW50OEFycmF5KGhhc2hlZFBhc3N3b3JkX2J1ZmYpKTtcclxuXHJcbiAgICBjb25zdCByZXNwb25zZTIgPSBhd2FpdCBmZXRjaChcIi9sb2dpblwiLCB7XHJcbiAgICAgICBtZXRob2Q6IFwiUE9TVFwiLFxyXG4gICAgICAgaGVhZGVyczoge1xyXG4gICAgICAgICAgXCJDb250ZW50LVR5cGVcIjogXCJhcHBsaWNhdGlvbi9KU09OXCIsXHJcbiAgICAgICB9LFxyXG4gICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkoe1xyXG4gICAgICAgICAgdHJpYWxVc2VySWQ6IHVzZXJJZCxcclxuICAgICAgICAgIHRyaWFsUGFzc3dvcmQ6IGhhc2hlZFBhc3N3b3JkX2I2NFxyXG4gICAgICAgfSlcclxuICAgIH0pXHJcblxyXG4gICAgY29uc3QgcmVzcG9uc2UyX2pzb246IElTdGRSZXM8TG9naW5EYXRhPiA9IGF3YWl0IHJlc3BvbnNlMi5qc29uKCk7XHJcblxyXG4gICAgaWYoIHJlc3BvbnNlMl9qc29uLmVycm9yRmxhZyA9PT0gdHJ1ZSApIHtcclxuICAgICAgdGhyb3cgbmV3IEVycm9yKGBMb2dpbiBmYWlsdXJlLiBTZXJ2ZXIncyBtZXNzYWdlOiAke3Jlc3BvbnNlMl9qc29uLm1zZ31gKTtcclxuICAgIH1cclxuXHJcbiAgICBjb25zdCBsb2dpbkRhdGEgPSA8TG9naW5EYXRhPiByZXNwb25zZTJfanNvbi5kYXRhO1xyXG4gICAgY29uc3QgeyB1c2VySWQ6IHVzZXJJZDIsIHNpZ25lZEhhbGZKV1QsIGF2YWlsYWJsZUlkZW50aXRpZXMgfSA9IGxvZ2luRGF0YTtcclxuXHJcbiAgICBpZih1c2VySWQgIT0gdXNlcklkMil7XHJcbiAgICAgIHRocm93IG5ldyBFcnJvcihcInRoZSB1c2VySWQgdXNlZCBkdXJpbmcgbG9naW4gcHJlY2hlY2sgZG9lcyBub3QgbWF0Y2ggdGhhdCByZXR1cm5lZCBhZnRlciB0aGUgbG9naW4gd2FzIGF0dGVtcHRlZC5cIik7XHJcbiAgICB9XHJcblxyXG4gICAgY29uc3QgeyBoYWxmSldULCBhdXRoU2lnbmF0dXJlX2I2NCB9ID0gc2lnbmVkSGFsZkpXVDtcclxuXHJcbiAgICBjb25zdCBoYWxmSldUVmFsaWRhdGlvbiA9IGF3YWl0IHRoaXMudmVyaWZ5U2lnbmVkT2JqZWN0KGhhbGZKV1QsIHRoaXMucHViU0pXS19zLCBhdXRoU2lnbmF0dXJlX2I2NCk7XHJcbiAgICBpZihoYWxmSldUVmFsaWRhdGlvbiA9PT0gZmFsc2Upe1xyXG4gICAgICB0aHJvdyBuZXcgRXJyb3IoXCJTZXJ2ZXIncyByZXNwb25zZSBjb3VsZCBub3QgYmUgdmVyaWZpZWQgd2l0aCB0aGUgcHViU0pXS19zIHByZXZpb3VzbHkgcHJvdmlkZWQuXCIpXHJcbiAgICB9IGVsc2Uge1xyXG4gICAgICB0aGlzLmhhbGZKV1QgPSBoYWxmSldUO1xyXG4gICAgICBjb25zdCBMOFJlc3BvbnNlOiBJU3RkUmVzPEF2YWlsYWJsZUlkZW50aXRpZXM+ID0ge1xyXG4gICAgICAgIG1zZzogXCJTZXJ2ZXIgaGFzIHByb3ZpZGVkIHRoZSBmb2xsb3dpbmcgaWRlbnRpdGllczogXCIsXHJcbiAgICAgICAgZXJyb3JGbGFnOiBmYWxzZSxcclxuICAgICAgICBkYXRhOiB7XHJcbiAgICAgICAgICBhdmFpbGFibGVJZGVudGl0aWVzOiBhdmFpbGFibGVJZGVudGl0aWVzLFxyXG4gICAgICAgIH1cclxuICAgICAgfVxyXG4gICAgICByZXR1cm4gTDhSZXNwb25zZTtcclxuICAgIH1cclxuICB9XHJcblxyXG4gIGFzeW5jIGNob29zZUlkZW50aXR5KHVzZXJuYW1lOiBzdHJpbmcsIGNob3NlbklkZW50aXR5OiBzdHJpbmcpOiBQcm9taXNlPElTdGRSZXM8bnVsbD4+IHtcclxuICAgIC8vIFVzZSBmZXRjaCB0byBQT1NUIGEgcmVxdWVzdCB0byB0aGUgc2VydmVyIGNvbnRhaW5pbmcgdGhlIGNob3NlbiBpZGVudGl0eSBhbmQgdGhlIGhhbGZKV1RcclxuICAgIGlmKHRoaXMua2V5UGFpclNfYyA9PT0gdW5kZWZpbmVkKSB0aHJvdyBuZXcgRXJyb3IoXCJDbGllbnQga2V5IHBhaXIgaXMgdW5kZWZpbmVkLiBJdCBuZWVkcyBpbml0aWF0aW9uLlwiKTtcclxuICAgIGNvbnN0IHByaXZTS2V5X2MgPSA8Q3J5cHRvS2V5PiB0aGlzLmtleVBhaXJTX2MucHJpdmF0ZUtleTtcclxuICAgIGlmKHRoaXMuaGFsZkpXVCA9PT0gdW5kZWZpbmVkKSB0aHJvdyBuZXcgRXJyb3IoXCJ0aGlzLmhhbGZKV1QgbXVzdCBiZSBkZWZpbmVkIGJlZm9yZSBpZGVudGl0eSBpcyBjaG9zZW4uXCIpO1xyXG4gICAgY29uc3QgYXV0aFNpZ25hdHVyZV9jX2I2NCA9IGF3YWl0IHRoaXMuc2lnbk9iamVjdCh0aGlzLmhhbGZKV1QsIHByaXZTS2V5X2MpO1xyXG4gICAgY29uc3QgdXNlcklkID0gYXdhaXQgdGhpcy51c2VybmFtZVRvVXNlcklkKHVzZXJuYW1lKTtcclxuICAgIGNvbnN0IHJlc3BvbnNlMSA9IGF3YWl0IGZldGNoKFwiaHR0cDovL2xvY2FsaG9zdDozMDAwL2xvZ2luL2lkZW50aXR5XCIsIHtcclxuICAgICAgbWV0aG9kOiBcIlBPU1RcIixcclxuICAgICAgaGVhZGVyczoge1xyXG4gICAgICAgIFwiY29udGVudC10eXBlXCI6IFwiYXBwbGljYXRpb24vanNvblwiLFxyXG4gICAgICAgIFwieC1zaWduZWRoYWxmand0LWNcIjogSlNPTi5zdHJpbmdpZnkoe2hhbGZKV1Q6IHRoaXMuaGFsZkpXVCwgYXV0aFNpZ25hdHVyZV9jX2I2NH0pLFxyXG4gICAgICB9LFxyXG4gICAgICBib2R5OiBKU09OLnN0cmluZ2lmeSh7XHJcbiAgICAgICAgdXNlcklkLFxyXG4gICAgICAgIGNob3NlbklkZW50aXR5XHJcbiAgICAgIH0pXHJcbiAgICB9KTtcclxuXHJcbiAgICBjb25zdCByZXNwb25zZTFfanNvbjogSVN0ZFJlczxDaG9vc2VJZGVudGl0eURhdGE+ID0gYXdhaXQgcmVzcG9uc2UxLmpzb24oKTtcclxuXHJcbiAgICBpZihyZXNwb25zZTFfanNvbi5lcnJvckZsYWcgPT09IHRydWUpe1xyXG4gICAgICB0aHJvdyBuZXcgRXJyb3IoYEVycm9yIGFmdGVyICdQT1NUJyB0byAvbG9naW4vaWRlbnRpdHksICR7cmVzcG9uc2UxX2pzb24ubXNnfWApO1xyXG4gICAgfVxyXG4gICAgXHJcbiAgICBcclxuICAgIGNvbnN0IGNob29zZUlkZW50aXR5RGF0YSA9IDxDaG9vc2VJZGVudGl0eURhdGE+cmVzcG9uc2UxX2pzb24uZGF0YTtcclxuICAgIFxyXG4gICAgLy9jb25zdCBwdWJTSldLX3MgPSB0aGlzLnN0cmluZ2lmaWVkSldLcy5nZXQoJ3B1YlNKV0tfcycpO1xyXG4gICAgaWYodGhpcy5wdWJTSldLX3MgPT09IHVuZGVmaW5lZCkgdGhyb3cgbmV3IEVycm9yKFwiU2VydmVyJ3MgcHVibGljIHNpZ25pbmcgSldLIHdhcyBub3QgZm91bmQuXCIpO1xyXG4gICAgLy9jb25zdCBwdWJTSldLID0gSlNPTi5wYXJzZSh0aGlzLnB1YlNKV0tfcyk7XHJcbiAgICBjb25zdCB7IGNob3NlbklkZW50aXR5OiBjaG9zZW5JZGVudGl0eTIsIHNpZ25lZEZ1bGxKV1QgfSA9IGNob29zZUlkZW50aXR5RGF0YTtcclxuICAgIGNvbnN0IHsgZnVsbEpXVCwgc2lnbmF0dXJlX2I2NCB9ID0gPElTaWduZWRGdWxsSldUPnNpZ25lZEZ1bGxKV1Q7XHJcbiAgICBjb25zb2xlLmxvZyhcIioqKipcIixmdWxsSldUKTtcclxuXHJcbiAgICBjb25zdCBmdWxsSldUVmVyaWZpY2F0aW9uID0gYXdhaXQgdGhpcy52ZXJpZnlTaWduZWRPYmplY3QoZnVsbEpXVCwgdGhpcy5wdWJTSldLX3MsIHNpZ25hdHVyZV9iNjQpO1xyXG4gICAgaWYoZnVsbEpXVFZlcmlmaWNhdGlvbiA9PT0gZmFsc2Upe1xyXG4gICAgICB0aHJvdyBuZXcgRXJyb3IoXCJmdWxsSldUIGRpZCBub3QgcGFzcyB2ZXJpZmljYXRpb25cIik7XHJcbiAgICB9IGVsc2Uge1xyXG4gICAgICBpZiggY2hvc2VuSWRlbnRpdHkgIT0gY2hvc2VuSWRlbnRpdHkyICl7XHJcbiAgICAgICAgdGhyb3cgbmV3IEVycm9yKCBcIkNob3NlbiBJZGVudGl0eSBDb3JydXB0aW9uLlwiKTtcclxuICAgICAgfVxyXG4gICAgICBhd2FpdCB0aGlzLnJlZ2lzdGVyQ2l0aXplbnNoaXAoZnVsbEpXVCwgY2hvc2VuSWRlbnRpdHkpOyAvLyBQcm9iYWJseSBzaG91bGQgYmUgYW4gYXN5bmNocm9ub3VzIEluZGV4ZWREQiB3cml0ZSBpbiB0aW1lLlxyXG4gICAgICByZXR1cm4geyAvLyA8SUw4UmVzcG9uc2U+XHJcbiAgICAgICAgZXJyb3JGbGFnOiBmYWxzZSxcclxuICAgICAgICBtc2c6IFwiQ2l0aXplbnNoaXAgcmVnaXN0ZXJlZC5cIixcclxuICAgICAgICBkYXRhOiBudWxsXHJcbiAgICAgIH1cclxuICAgIH1cclxuICB9XHJcblxyXG4gIGFzeW5jIHJlZ2lzdGVyQ2l0aXplbnNoaXAoZnVsbEpXVDogSUZ1bGxKV1QsIGNob3NlbklkZW50aXR5OiBzdHJpbmcpOiBQcm9taXNlPHZvaWQ+IHtcclxuICAgIHNlc3Npb25TdG9yYWdlLmNsZWFyKCk7XHJcbiAgICB0cnkge1xyXG4gICAgICAvLyBjb25zdCBwcml2U0pXS19jID0gdGhpcy5zdHJpbmdpZmllZEpXS3MuZ2V0KFwicHJpdlNKV0tfY1wiKTtcclxuICAgICAgLy8gaWYgKCAhcHJpdlNKV0tfYyApIHRocm93IG5ldyBFcnJvcihcIlByb2JsZW0gcmV0cmlldmluZyB0aGUgJ3ByaXZTSldLX2MnXCIpO1xyXG4gICAgICAvLyBjb25zdCBwdWJTSldLX2MgPSB0aGlzLnN0cmluZ2lmaWVkSldLcy5nZXQoXCJwdWJTSldLX2NcIik7XHJcbiAgICAgIC8vIGlmICggIXB1YlNKV0tfYyApIHRocm93IG5ldyBFcnJvcihcIlByb2JsZW0gcmV0cmlldmluZyB0aGUgJ3B1YlNKV0tfQydcIik7XHJcblxyXG4gICAgICBzZXNzaW9uU3RvcmFnZS5zZXRJdGVtKFwicHJpdlNKV0tfY1wiLCBKU09OLnN0cmluZ2lmeSh0aGlzLnByaXZTSldLX2MpKTtcclxuICAgICAgc2Vzc2lvblN0b3JhZ2Uuc2V0SXRlbShcInB1YlNKV0tfY1wiLCBKU09OLnN0cmluZ2lmeSh0aGlzLnB1YlNKV0tfYykpO1xyXG4gICAgICBzZXNzaW9uU3RvcmFnZS5zZXRJdGVtKFwiZnVsbEpXVFwiLCBKU09OLnN0cmluZ2lmeShmdWxsSldUKSk7XHJcbiAgICAgIHNlc3Npb25TdG9yYWdlLnNldEl0ZW0oXCJjaXRpemVuXCIsIGNob3NlbklkZW50aXR5KTtcclxuICAgIH0gY2F0Y2ggKGVycil7XHJcbiAgICAgIGNvbnNvbGUubG9nKFwiRXJycm9yIHdoaWxlIHJlZ2lzdGVyaW5nIHRoZSBjaXRpemVuLlwiLCBlcnIpO1xyXG4gICAgfVxyXG4gIH1cclxuXHJcbiAgYXN5bmMgZXN0YWJsaXNoVHVubmVsKCk6IFByb21pc2U8dm9pZD57XHJcbiAgICAvLyBDcmVhdGUgYSBrZXkgcGFpciBmb3IgZG9pbmcgREggd2l0aCB0aGUgc2VydmljZSBwcm92aWRlciBhbmQgc2F2ZSBmb3IgbGF0ZXIuXHJcbiAgICB0aGlzLmtleVBhaXJESF9zcGEgPSBhd2FpdCBjcnlwdG8uc3VidGxlLmdlbmVyYXRlS2V5KFxyXG4gICAgICB7XHJcbiAgICAgICAgIG5hbWU6IFwiRUNESFwiLFxyXG4gICAgICAgICBuYW1lZEN1cnZlOiBcIlAtMjU2XCJcclxuICAgICAgfSxcclxuICAgICAgdHJ1ZSxcclxuICAgICAgW1wiZGVyaXZlS2V5XCIsIFwiZGVyaXZlQml0c1wiXVxyXG4gICAgKTtcclxuXHJcbiAgICBsZXQgcHViREhKV0tfc3BhID0gYXdhaXQgY3J5cHRvLnN1YnRsZS5leHBvcnRLZXkoXHJcbiAgICAgIFwiandrXCIsXHJcbiAgICAgIDxDcnlwdG9LZXk+dGhpcy5rZXlQYWlyREhfc3BhLnB1YmxpY0tleVxyXG4gICAgKTtcclxuXHJcbiAgICBjb25zdCBwdWJESEpXS19zcGFfc3RyID0gSlNPTi5zdHJpbmdpZnkocHViREhKV0tfc3BhKTtcclxuXHJcbiAgICAvL3RoaXMuc3RyaW5naWZpZWRKV0tzLnNldChcInB1YkRISldLX3NwYVwiLCBwdWJESEpXS19zcGFfc3RyKTtcclxuXHJcbiAgICBjb25zdCBwdWJTSldLX3NwYV9zdHIgPSBzZXNzaW9uU3RvcmFnZS5nZXRJdGVtKFwicHViU0pXS19jXCIpOy8vbm90ZSBjb252ZXJzaW9uIGZyb20gJ2NsaWVudCcoYykgdG8gJ3NpbmdsZSBwYWdlIGFwcGxpY2F0aW9uJyAoc3BhKS5cclxuICAgIGlmKCFwdWJTSldLX3NwYV9zdHIpIHRocm93IG5ldyBFcnJvcihcInB1YlNKV0tfYyB3YXMgbm90IHNldC5cIik7XHJcbiAgICBjb25zdCBmdWxsSldUX3NwYV9zdHIgPSBzZXNzaW9uU3RvcmFnZS5nZXRJdGVtKFwiZnVsbEpXVFwiKTtcclxuICAgIGNvbnN0IGNpdGl6ZW4gPSBzZXNzaW9uU3RvcmFnZS5nZXRJdGVtKFwiY2l0aXplblwiKTtcclxuICAgIGlmICggIWZ1bGxKV1Rfc3BhX3N0ciB8fCAhY2l0aXplbiApIHRocm93IG5ldyBFcnJvcihcImZ1bGxKV1Qgb3IgY2l0aXplbiBub3QgcHJvcGVybHkgaW5pdGlhbGl6ZWQuXCIpO1xyXG4gICAgY29uc3QgZnVsbEpXVF9zcGFfb2JqID0gSlNPTi5wYXJzZShmdWxsSldUX3NwYV9zdHIpO1xyXG4gICAgY29uc3QgcHJpdlNKV0tfc3BhX3N0ciA9IHNlc3Npb25TdG9yYWdlLmdldEl0ZW0oXCJwcml2U0pXS19jXCIpOyAvL25vdGUgY29udmVyc2lvbiBmcm9tICdjbGllbnQnKGMpIHRvICdzaW5nbGUgcGFnZSBhcHBsaWNhdGlvbicgKHNwYSkuXHJcbiAgICBpZiAoICFwcml2U0pXS19zcGFfc3RyICkgdGhyb3cgbmV3IEVycm9yKFwiU2lnbmluZyBrZXkgd2FzIG5vdCBpbml0aWFsaXplZC5cIik7XHJcbiAgICBjb25zdCBwcml2U0pXS19zcGEgPSBKU09OLnBhcnNlKHByaXZTSldLX3NwYV9zdHIpO1xyXG4gICAgY29uc3QgcHJpdlNLZXlfc3BhID0gYXdhaXQgY3J5cHRvLnN1YnRsZS5pbXBvcnRLZXkoXHJcbiAgICAgIFwiandrXCIsXHJcbiAgICAgIHByaXZTSldLX3NwYSxcclxuICAgICAge1xyXG4gICAgICAgIG5hbWU6IFwiRUNEU0FcIixcclxuICAgICAgICBuYW1lZEN1cnZlOiBcIlAtMjU2XCIsXHJcbiAgICAgIH0sXHJcbiAgICAgIGZhbHNlLFxyXG4gICAgICBbXCJzaWduXCJdXHJcbiAgICApO1xyXG5cclxuICAgIGNvbnN0IEpXVGF1dGhTaWduYXR1cmVfYjY0ID0gYXdhaXQgdGhpcy5zaWduT2JqZWN0KGZ1bGxKV1Rfc3BhX29iaiwgcHJpdlNLZXlfc3BhKTsgLy8gVE9ETzogU2lnbiBvYmogb3Igc3RyP1xyXG4gICAgXHJcbiAgICBjb25zdCBzaWduZWRGdWxsSldUX3NwYTJwOiBJU2lnbmVkRnVsbEpXVCA9IHtcclxuICAgICAgZnVsbEpXVDogZnVsbEpXVF9zcGFfb2JqLFxyXG4gICAgICBzaWduYXR1cmVfYjY0OiBKV1RhdXRoU2lnbmF0dXJlX2I2NFxyXG4gICAgfTtcclxuXHJcbiAgICBjb25zdCByZXNwb25zZTEgPSBhd2FpdCBmZXRjaChcImh0dHA6Ly9sb2NhbGhvc3Q6MzAwMC9lY2RoaW5pdFwiLCB7XHJcbiAgICAgIG1ldGhvZDogXCJQT1NUXCIsXHJcbiAgICAgIGhlYWRlcnM6IHtcclxuICAgICAgICBcImNvbnRlbnQtdHlwZVwiOiBcImFwcGxpY2F0aW9uL0pTT05cIixcclxuICAgICAgICBcIngtY2l0aXplblwiOiBjaXRpemVuLFxyXG4gICAgICAgIFwieC1zaWduZWRmdWxsand0LXNwYVwiOiBKU09OLnN0cmluZ2lmeShzaWduZWRGdWxsSldUX3NwYTJwKSxcclxuICAgICAgICBcIngtcHViZGhqd2stc3BhMm1cIjogcHViREhKV0tfc3BhX3N0cixcclxuICAgICAgICBcIngtcHVic2p3ay1zcGEybVwiIDogcHViU0pXS19zcGFfc3RyXHJcbiAgICAgIH0sXHJcbiAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KHtcclxuICAgICAgICBcIm1zZ1wiOiBcIlNQQSBBdHRlbXB0aW5nIEVDREhcIixcclxuICAgICAgICBcImVycm9GbGFnXCI6IG51bGwsXHJcbiAgICAgICAgXCJkYXRhXCI6IG51bGxcclxuICAgICAgfSlcclxuICAgIH0pO1xyXG5cclxuICAgIGNvbnN0IHJlc3BvbnNlMV9qc29uID0gYXdhaXQgcmVzcG9uc2UxLmpzb24oKTsgLy9BbG1vc3QgYW4gPElTZWFsZWRFbnZlbG9wZT4gXHJcblxyXG4gICAgLy9BdCB0aGlzIHBvaW50LCB5b3Ugc2hvdWxkIGhhdmUgZXZlcnl0aGluZyB5b3UgbmVlZCB0byBtZXNzYWdlIHRoZSBtb2R1bGUgZW5kLXRvLWVuZCBlbmNyeXB0ZWQuXHJcbiAgICBjb25zdCBwdWJzandrX20yc3BhX3N0ciA9IHJlc3BvbnNlMS5oZWFkZXJzLmdldCgneC1wdWJzandrLW0yc3BhJyk7XHJcbiAgICBjb25zdCBwdWJkaGp3a19tMnNwYV9zdHIgPSByZXNwb25zZTEuaGVhZGVycy5nZXQoJ3gtcHViZGhqd2stbTJzcGEnKTtcclxuICAgIGNvbnN0IHNoYXJlZFNhbHRfYjY0ID0gcmVzcG9uc2UxLmhlYWRlcnMuZ2V0KCd4LXNoYXJlZHNhbHQtYjY0JylcclxuICAgIGlmKCFwdWJzandrX20yc3BhX3N0cikgdGhyb3cgbmV3IEVycm9yKFwicHVic2p3a19tMnNwYV9zdHIgdW5kZWZpbmVkIG9yIG51bGwuXCIpO1xyXG4gICAgaWYoIXB1YmRoandrX20yc3BhX3N0cikgdGhyb3cgbmV3IEVycm9yKFwicHVic2p3a19tMnNwYV9zdHIgdW5kZWZpbmVkIG9yIG51bGwuXCIpO1xyXG4gICAgaWYoIXNoYXJlZFNhbHRfYjY0KSB0aHJvdyBuZXcgRXJyb3IoXCJzaGFyZWRTYWx0X2I2NCB1bmRlZmluZWQgb3IgbnVsbC5cIik7XHJcbiAgICBjb25zdCBwdWJTSldLX20yc3BhID0gSlNPTi5wYXJzZShwdWJzandrX20yc3BhX3N0cik7XHJcbiAgICBjb25zdCBwdWJESEpXS19tMnNwYSA9IEpTT04ucGFyc2UocHViZGhqd2tfbTJzcGFfc3RyKTtcclxuICAgIHRoaXMucHViU0pXS19tMnNwYSA9IHB1YlNKV0tfbTJzcGE7XHJcbiAgICB0aGlzLnB1YkRISldLX20yc3BhID0gcHViREhKV0tfbTJzcGE7XHJcbiAgICB0aGlzLnNoYXJlZFNhbHRfYjY0ID0gc2hhcmVkU2FsdF9iNjQ7XHJcbiAgICBhd2FpdCB0aGlzLmRvdWJsZURlcml2ZWRTaGFyZWRTZWNyZXQoKTsgLy8gU2lkZSBFZmZlY3RzKlxyXG4gICAgXHJcbiAgICAvL1N5bW1ldHJpYyBkZWNyeXB0aW9uIHRlc3QuIEluIHRoZSBmdXR1cmUsIGEgc2lnbmF0dXJlIHNob3VsZCBiZSBjaGVja2VkIGZpcnN0IGJlZm9yZSBhbnkgZGVjcnlwdGlvbiB1c2luZyBhIHB1YlNKV0tfbTJzcGEgc2VydmVkIGJ5IHRoZSBMOCByZXZlcnNlIHByb3h5LlxyXG5cclxuICAgIC8vIFRPTU9SUk9XUyBMQUJPVVQgSlVMWSAzMSwgMjAyMlxyXG4gICAgY29uc3QgZW5jcnlwdGVkRGF0YV9iNjRfbSA9IHJlc3BvbnNlMV9qc29uLmVuY3J5cHRlZERhdGFfYjY0O1xyXG4gICAgXHJcbiAgICB0cnkge1xyXG4gICAgICBjb25zdCBwbGFpbnRleHREYXRhRnJvbU1vZHVsZV9zdHIgPSBhd2FpdCB0aGlzLnN5bW1ldHJpY0RlY3J5cHQoZW5jcnlwdGVkRGF0YV9iNjRfbSk7XHJcbiAgICAgIGNvbnN0IHBsYWludGV4dERhdGFGcm9tTW9kdWxlX29iaiA9IEpTT04ucGFyc2UocGxhaW50ZXh0RGF0YUZyb21Nb2R1bGVfc3RyKTtcclxuICAgICAgaWYocGxhaW50ZXh0RGF0YUZyb21Nb2R1bGVfb2JqID09PSB0cnVlKXtcclxuICAgICAgICB0aHJvdyBuZXcgRXJyb3IoXCJUaGUgc3ltbWV0cmljIGRlY3J5cHRpb24gdGVzdCBmYWlsZWQuXCIpO1xyXG4gICAgICB9XHJcbiAgICB9IGNhdGNoKGVycikge1xyXG4gICAgICBjb25zb2xlLmxvZyhcIltFcnJvciB3aGlsZSBwZXJmb3JtaW5nIHN5bW1ldHJpRGVjcnlwdCBvbiB0aGUgU2VydmljZSBQcm92aWRlcidzIHJlc3BvbnNlLl1cIiwgZXJyKTtcclxuICAgIH1cclxuXHJcbiAgICBjb25zdCBwbGFpbnRleHREYXRhT2JqX3NwYTJtOiBJRW5jcnlwdGVkRGF0YV9zcGEybSA9IHtcclxuICAgICAgaW5pdDogdHJ1ZSwgLy8gSXMgdGhpcyB0aGUgYmVzdCBwbGFjZSB0byBwdXQgYW4gaW5pdCBmbGFnP1xyXG4gICAgICBlcnJvckZsYWc6IGZhbHNlLFxyXG4gICAgICBwYXRoOiBudWxsLFxyXG4gICAgICBtc2c6IG51bGwsXHJcbiAgICAgIG1ldGhvZDogbnVsbCxcclxuICAgICAgcXVlcnk6IG51bGwsXHJcbiAgICAgIG9wdGlvbnM6IG51bGwsXHJcbiAgICAgIGRhdGE6IG51bGxcclxuICAgIH1cclxuXHJcbiAgICBjb25zdCBwbGFpbnRleHREYXRhT2JqX3NwYTJtX3N0ciA9IEpTT04uc3RyaW5naWZ5KHBsYWludGV4dERhdGFPYmpfc3BhMm0pO1xyXG4gICAgY29uc3QgZW5jcnlwdGVkRGF0YU9ial9zcGEybV9iNjQgPSBhd2FpdCB0aGlzLnN5bW1ldHJpY0VuY3J5cHQocGxhaW50ZXh0RGF0YU9ial9zcGEybV9zdHIpO1xyXG5cclxuICAgIGNvbnN0IHNpZ25hdHVyZV9iNjRfc3BhMm0gPSBhd2FpdCB0aGlzLnNpZ25TdHJpbmcoZW5jcnlwdGVkRGF0YU9ial9zcGEybV9iNjQsIHByaXZTS2V5X3NwYSk7XHJcblxyXG4gICAgY29uc3Qgc2VhbGVkRW52ZWxvcGVfc3BhMm06IElTZWFsZWRFbnZlbG9wZSA9IHtcclxuICAgICAgZXJyb3JGbGFnOiBmYWxzZSwgXHJcbiAgICAgIG1zZzogXCJTUEEgaXMgdGVzdGluZyB0aGUgaW5pdGlhdGVkIHR1bm5lbC5cIixcclxuICAgICAgZW5jcnlwdGVkRGF0YV9iNjQ6IGVuY3J5cHRlZERhdGFPYmpfc3BhMm1fYjY0LFxyXG4gICAgICBlbmNyeXB0ZWREYXRhU2lnbmF0dXJlX2I2NDogc2lnbmF0dXJlX2I2NF9zcGEybVxyXG4gICAgfTtcclxuICAgIFxyXG4gICAgY29uc3QgcmVzcG9uc2UyID0gYXdhaXQgZmV0Y2goXCJodHRwOi8vbG9jYWxob3N0OjMwMDAvcHJveHltZVwiLCB7XHJcbiAgICAgIG1ldGhvZDogXCJQT1NUXCIsXHJcbiAgICAgIGhlYWRlcnM6IHtcclxuICAgICAgICBcImNvbnRlbnQtdHlwZVwiOiBcImFwcGxpY2F0aW9uL2pzb25cIixcclxuICAgICAgICBcIngtY2l0aXplblwiOiBjaXRpemVuLFxyXG4gICAgICAgIFwieC1zaWduZWRmdWxsand0LXNwYVwiOiBKU09OLnN0cmluZ2lmeShzaWduZWRGdWxsSldUX3NwYTJwKSxcclxuICAgICAgfSxcclxuICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkoIHtzZWFsZWRFbnZlbG9wZV9zcGEybX0gKVxyXG4gICAgfSk7XHJcblxyXG4gICAgY29uc3QgcmVzcG9uc2UyX29iajogSVNlYWxlZEVudmVsb3BlID0gYXdhaXQgcmVzcG9uc2UyLmpzb24oKTtcclxuXHJcbiAgICBpZihyZXNwb25zZTJfb2JqLmVycm9yRmxhZyA9PT0gdHJ1ZSl7XHJcbiAgICAgIC8vIFJlZ2lzdGVyIGFuIGVycm9yLlxyXG4gICAgfSBlbHNlIHtcclxuICAgICAgdHJ5e1xyXG4gICAgICAgIGlmKCAhdGhpcy5wdWJTSldLX20yc3BhICkgdGhyb3cgbmV3IEVycm9yKFwicHViU0pXS19tMnNwYSB3YXMgbm90IHByb3Blcmx5IGluaXRpYWxpemVkLlwiKTtcclxuICAgICAgICBjb25zdCB7ZW5jcnlwdGVkRGF0YV9iNjQsIGVuY3J5cHRlZERhdGFTaWduYXR1cmVfYjY0fSA9IHJlc3BvbnNlMl9vYmo7XHJcbiAgICAgICAgY29uc3QgZW5jcnlwdGVkRGF0YVZhbGlkYXRpb24gPSBhd2FpdCB0aGlzLnZlcmlmeVNpZ25lZFN0cmluZyhlbmNyeXB0ZWREYXRhX2I2NCwgdGhpcy5wdWJTSldLX20yc3BhLCBlbmNyeXB0ZWREYXRhU2lnbmF0dXJlX2I2NCk7XHJcbiAgICAgICAgaWYoIGVuY3J5cHRlZERhdGFWYWxpZGF0aW9uID09PSBmYWxzZSApe1xyXG4gICAgICAgIH0gZWxzZSB7XHJcbiAgICAgICAgICBjb25zdCBwbGFpblRleHRfbTJzcGFfc3RyID0gYXdhaXQgdGhpcy5zeW1tZXRyaWNEZWNyeXB0KHJlc3BvbnNlMl9vYmouZW5jcnlwdGVkRGF0YV9iNjQpO1xyXG4gICAgICAgICAgY29uc3QgeyBlcnJvckZsYWcsIG1zZywgZGF0YSB9ID0gSlNPTi5wYXJzZShwbGFpblRleHRfbTJzcGFfc3RyKTtcclxuICAgICAgICAgIGlmKCBtc2cgKSBjb25zb2xlLmxvZyhcIltyZXNwb25zZTIubXNnIGZyb20gZmV0Y2ggJ2h0dHA6Ly9sb2NhbGhvc3Q6MzAwMC9wcm94eW1lJ106IFwiLCBtc2cpO1xyXG4gICAgICAgICAgaWYoIGVycm9yRmxhZyA9PT0gdHJ1ZSApIHRocm93IG5ldyBFcnJvcihgU2VydmljZSBQcm92aWRlciBpcyByZXBvcnRpbmcgYW5kIGVycm9yOiAke21zZ31gKTtcclxuICAgICAgICB9XHJcbiAgICAgIH0gY2F0Y2goZXJyKSB7XHJcbiAgICAgICAgY29uc29sZS5sb2coXCJFcnJvciB3aGlsZSBkZWNyeXB0aW5nIG9yIHZhbGlkYXRpbmcgdGhlIHNlYWxlZCBlbnZlbG9wZS5cIiwgZXJyKTtcclxuICAgICAgfVxyXG4gICAgfTtcclxuICB9XHJcblxyXG4gIGFzeW5jIHByb3h5KGRhdGE6IEpTT04pOiBQcm9taXNlPGFueT57XHJcbiAgICBpZihmYWxzZSkgdGhyb3cgbmV3IEVycm9yKFwiTDggaXMgbm90IHByb3Blcmx5IGluaXRpYWxpemVkLiBZb3UgY2Fubm90IHNlbmQgRTJFIGVuY3J5cHRlZCBtZXNzYWdlcyB5ZXQuIFRyeSBsb2dpbmcgaW4uXCIpO1xyXG4gICAgbGV0IGNpdGl6ZW4gPSBzZXNzaW9uU3RvcmFnZS5nZXRJdGVtKFwiY2l0aXplblwiKTtcclxuXHJcbiAgICBsZXQgZnVsbEpXVF9zcGFfc3RyID0gc2Vzc2lvblN0b3JhZ2UuZ2V0SXRlbShcImZ1bGxKV1RcIik7XHJcblxyXG4gICAgbGV0IHByaXZTSldLX3NwYV9zdHIgPSBzZXNzaW9uU3RvcmFnZS5nZXRJdGVtKFwicHJpdlNKV0tfY1wiKTsgLy8gQWdhaW4gbm90ZSB0aGUgY29udmVyc2lvbiBvZiAnYycgdG8gJ3NwYScuXHJcblxyXG4gICAgaWYoIWZ1bGxKV1Rfc3BhX3N0ciB8fCAhY2l0aXplbil7XHJcbiAgICAgIHRocm93IG5ldyBFcnJvcihcIlJldHJpZXZhbCBvZiAnY2l0aXplbicgYW5kL29yICdmdWxsSldUJyBmYWlsZWRcIik7XHJcbiAgICB9IGVsc2UgaWYgKCFwcml2U0pXS19zcGFfc3RyKXtcclxuICAgICAgdGhyb3cgbmV3IEVycm9yKFwicHJpdlNKV0tfYyBpcyBub3QgaW5pdGlhbGl6ZWQgb24gc2Vzc2lvblN0b3JhZ2UuXCIpO1xyXG4gICAgfSBlbHNlIHtcclxuXHJcbiAgICAgIGNvbnN0IGZ1bGxKV1Rfc3BhX29iaiA9IEpTT04ucGFyc2UoZnVsbEpXVF9zcGFfc3RyKTtcclxuICAgICAgY29uc3QgcHJpdlNKV0tfc3BhID0gSlNPTi5wYXJzZShwcml2U0pXS19zcGFfc3RyKTtcclxuICAgICAgXHJcbiAgICAgIGNvbnN0IHByaXZTS2V5X3NwYSA9IGF3YWl0IGNyeXB0by5zdWJ0bGUuaW1wb3J0S2V5KFxyXG4gICAgICAgIFwiandrXCIsXHJcbiAgICAgICAgcHJpdlNKV0tfc3BhLFxyXG4gICAgICAgIHtcclxuICAgICAgICAgIG5hbWU6IFwiRUNEU0FcIixcclxuICAgICAgICAgIG5hbWVkQ3VydmU6IFwiUC0yNTZcIixcclxuICAgICAgICB9LFxyXG4gICAgICAgIGZhbHNlLFxyXG4gICAgICAgIFtcInNpZ25cIl1cclxuICAgICAgKTtcclxuXHJcbiAgICAgIGNvbnN0IGZ1bGxKV1RTaWdfYjY0ID0gYXdhaXQgdGhpcy5zaWduT2JqZWN0KGZ1bGxKV1Rfc3BhX29iaiwgcHJpdlNLZXlfc3BhKTtcclxuXHJcbiAgICAgIGNvbnN0IHNpZ25lZEZ1bGxKV1Rfc3BhMnA6IElTaWduZWRGdWxsSldUID0ge1xyXG4gICAgICAgIGZ1bGxKV1Q6IGZ1bGxKV1Rfc3BhX29iaixcclxuICAgICAgICBzaWduYXR1cmVfYjY0OiBmdWxsSldUU2lnX2I2NFxyXG4gICAgICB9O1xyXG5cclxuICAgICAgLy8gRW5jcnlwdCB0aGUgZGF0YVxyXG4gICAgICBjb25zdCBkYXRhX3N0ciA9IEpTT04uc3RyaW5naWZ5KGRhdGEpO1xyXG4gICAgICBjb25zdCBlbmNyeXB0ZWREYXRhX2I2NCA9IGF3YWl0IHRoaXMuc3ltbWV0cmljRW5jcnlwdChkYXRhX3N0cik7XHJcbiAgICAgIGNvbnN0IGVuY3J5cHRlZERhdGFTaWduYXR1cmVfYjY0ID0gYXdhaXQgdGhpcy5zaWduU3RyaW5nKGVuY3J5cHRlZERhdGFfYjY0LCBwcml2U0tleV9zcGEpO1xyXG4gICAgICBcclxuICAgICAgY29uc3Qgc2VhbGVkRW52ZWxvcGVfc3BhMm06IElTZWFsZWRFbnZlbG9wZSA9IHtcclxuICAgICAgICBlcnJvckZsYWc6IGZhbHNlLFxyXG4gICAgICAgIG1zZzogXCJGcm9tIFNQQSB0byBTZXJ2aWNlIFByb3ZpZGVyXCIsXHJcbiAgICAgICAgZW5jcnlwdGVkRGF0YV9iNjQsXHJcbiAgICAgICAgZW5jcnlwdGVkRGF0YVNpZ25hdHVyZV9iNjRcclxuICAgICAgfVxyXG5cclxuICAgICAgY29uc3QgcmVzcG9uc2UxID0gYXdhaXQgZmV0Y2goXCJodHRwOi8vbG9jYWxob3N0OjMwMDAvcHJveHltZVwiLCB7XHJcbiAgICAgICAgbWV0aG9kOiBcIlBPU1RcIixcclxuICAgICAgICBoZWFkZXJzOiB7XHJcbiAgICAgICAgICBcIkNvbnRlbnQtVHlwZVwiOiBcImFwcGxpY2F0aW9uL0pTT05cIixcclxuICAgICAgICAgIFwieC1jaXRpemVuXCI6IGNpdGl6ZW4sXHJcbiAgICAgICAgICBcIngtc2lnbmVkZnVsbGp3dC1zcGFcIjogSlNPTi5zdHJpbmdpZnkoc2lnbmVkRnVsbEpXVF9zcGEycCksXHJcbiAgICAgICAgfSxcclxuICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeSgge3NlYWxlZEVudmVsb3BlX3NwYTJtfSApXHJcbiAgICAgIH0pXHJcblxyXG4gICAgICBjb25zdCByZXNwb25zZTFfb2JqID0gYXdhaXQgcmVzcG9uc2UxLmpzb24oKTtcclxuXHJcbiAgICAgIHRyeSB7XHJcbiAgICAgICAgY29uc3QgeyBlcnJvckZsYWcsIG1zZywgZW5jcnlwdGVkRGF0YV9iNjQsIGVuY3J5cHRlZERhdGFTaWduYXR1cmVfYjY0IH0gPSA8SVNlYWxlZEVudmVsb3BlPnJlc3BvbnNlMV9vYmo7XHJcbiAgICAgICAgaWYobXNnKSBjb25zb2xlLmxvZyhcIltyZXNwb25zZTEubXNnIGZyb20gJ2h0dHA6Ly9sb2NhbGhvc3Q6MzAwMC9wcm94eW1lJ106IFwiLCBtc2cpO1xyXG4gICAgICAgIGlmKGVycm9yRmxhZyA9PT0gdHJ1ZSkgdGhyb3cgbmV3IEVycm9yKFwiU2VydmljZSBQcm92aWRlciBpcyByZXBvcnRpbmcgYW4gZXJyb3IgaW4gaXQncyByZXNwb25zZS5cIik7XHJcbiAgICAgICAgaWYoIXRoaXMucHViREhKV0tfbTJzcGEpIHRocm93IG5ldyBFcnJvcihcInRoaXMucHViU0pXS19tMnNwYSB3YXMgbm90IHByb3Blcmx5IGluaXRpYWxpemVkLlwiKTtcclxuICAgICAgICBjb25zdCBlbmNyeXB0ZWRNc2dWYWxpZGF0aW9uID0gYXdhaXQgdGhpcy52ZXJpZnlTaWduZWRTdHJpbmcoZW5jcnlwdGVkRGF0YV9iNjQsIDxKc29uV2ViS2V5PnRoaXMucHViU0pXS19tMnNwYSwgZW5jcnlwdGVkRGF0YVNpZ25hdHVyZV9iNjQpO1xyXG4gICAgICAgIGlmKCBlbmNyeXB0ZWRNc2dWYWxpZGF0aW9uID09PSBmYWxzZSApe1xyXG4gICAgICAgICAgdGhyb3cgbmV3IEVycm9yKFwiVGhlIGVuY3J5cHRlZCBkYXRhIGZyb20gdGhlIHNlcnZpY2UgcHJvdmlkZXIgZGlkIG5vdCBwYXNzIHZhbGlkYXRpb24uXCIpO1xyXG4gICAgICAgIH0gZWxzZSB7XHJcbiAgICAgICAgICBjb25zdCB1bmVuY3J5cHRlZERhdGEgPSBhd2FpdCB0aGlzLnN5bW1ldHJpY0RlY3J5cHQoZW5jcnlwdGVkRGF0YV9iNjQpO1xyXG4gICAgICAgICAgcmV0dXJuIEpTT04ucGFyc2UodW5lbmNyeXB0ZWREYXRhKTtcclxuICAgICAgICB9XHJcbiAgICAgIH0gY2F0Y2ggKGVycikge1xyXG4gICAgICB9XHJcbiAgICB9XHJcbiAgfVxyXG5cclxuICAvL1BSSVZBVEUgRlVOQ1RJT05TXHJcbiAgYXN5bmMgdXNlcm5hbWVUb1VzZXJJZCh1c2VybmFtZTogc3RyaW5nKTogUHJvbWlzZTxzdHJpbmc+IHtcclxuICAgIGNvbnN0IHVzZXJuYW1lX3VJbnQ4ID0gbmV3IFRleHRFbmNvZGVyKCkuZW5jb2RlKHVzZXJuYW1lKTtcclxuICAgIGNvbnN0IHVzZXJuYW1lX3NoYTI1NiA9IGF3YWl0IGNyeXB0by5zdWJ0bGUuZGlnZXN0KCdTSEEtMjU2JywgdXNlcm5hbWVfdUludDgpO1xyXG4gICAgY29uc3QgdXNlcm5hbWVfYjY0ID0gdUludDhBcnJUb0I2NChuZXcgVWludDhBcnJheSh1c2VybmFtZV9zaGEyNTYpKTtcclxuICAgIGNvbnN0IHVzZXJJZCA9IHVzZXJuYW1lX2I2NC5zbGljZSgwLDUpO1xyXG4gICAgcmV0dXJuIHVzZXJJZDtcclxuICB9O1xyXG5cclxuICBhc3luYyB2ZXJpZnlTaWduZWRPYmplY3Qob2JqZWN0OiBvYmplY3QsIHB1YlNKV0s6IEpzb25XZWJLZXksIHNpZ25hdHVyZV9iNjQ6IHN0cmluZyk6IFByb21pc2U8Ym9vbGVhbj4ge1xyXG4gICAgY29uc3Qgc3RyaW5naWZpZWRPYmplY3QgPSBKU09OLnN0cmluZ2lmeShvYmplY3QpO1xyXG4gICAgY29uc3Qgc2lnbmF0dXJlX3VJbnQ4ID0gYjY0VG9VaW50OEFycihzaWduYXR1cmVfYjY0LCAwKTtcclxuICAgIGNvbnN0IHB1YlNLZXlfcyA9IGF3YWl0IGNyeXB0by5zdWJ0bGUuaW1wb3J0S2V5KFxyXG4gICAgICBcImp3a1wiLFxyXG4gICAgICBwdWJTSldLLFxyXG4gICAgICB7XHJcbiAgICAgIG5hbWU6IFwiRUNEU0FcIixcclxuICAgICAgbmFtZWRDdXJ2ZTogXCJQLTI1NlwiLFxyXG4gICAgICB9LFxyXG4gICAgICBmYWxzZSxcclxuICAgICAgWyd2ZXJpZnknXVxyXG4gICAgKTtcclxuICBcclxuICAgIGNvbnN0IHRleHRUb1ZlcmlmeSA9IG5ldyBUZXh0RW5jb2RlcigpLmVuY29kZShzdHJpbmdpZmllZE9iamVjdCk7XHJcbiAgICBjb25zdCB2ZXJpZmljYXRpb24gPSBhd2FpdCBjcnlwdG8uc3VidGxlLnZlcmlmeShcclxuICAgICAge1xyXG4gICAgICAgIG5hbWU6IFwiRUNEU0FcIixcclxuICAgICAgICBoYXNoOiBcIlNIQS0yNTZcIlxyXG4gICAgICB9LFxyXG4gICAgICBwdWJTS2V5X3MsIC8vIFNlcnZlcidzIHB1YmxpYyBFQ0RTQSBrZXlcclxuICAgICAgc2lnbmF0dXJlX3VJbnQ4LCAvLyBTZXJ2ZXIncyBzaWduYXR1cmVcclxuICAgICAgdGV4dFRvVmVyaWZ5IC8vIEVuY3J5cHRlZCBvYmplY3RcclxuICAgIClcclxuICBcclxuICAgIHJldHVybiB2ZXJpZmljYXRpb247XHJcbiAgfTtcclxuXHJcbiAgYXN5bmMgdmVyaWZ5U2lnbmVkU3RyaW5nKHN0cmluZzogc3RyaW5nLCBwdWJTSldLOiBKc29uV2ViS2V5LCBzaWduYXR1cmVfYjY0OiBzdHJpbmcpOiBQcm9taXNlPGJvb2xlYW4+IHtcclxuICAgIGNvbnN0IHNpZ25hdHVyZV91SW50OCA9IGI2NFRvVWludDhBcnIoc2lnbmF0dXJlX2I2NCwgMCk7XHJcbiAgICBjb25zdCBwdWJTS2V5X3MgPSBhd2FpdCBjcnlwdG8uc3VidGxlLmltcG9ydEtleShcclxuICAgICAgXCJqd2tcIixcclxuICAgICAgcHViU0pXSyxcclxuICAgICAge1xyXG4gICAgICBuYW1lOiBcIkVDRFNBXCIsXHJcbiAgICAgIG5hbWVkQ3VydmU6IFwiUC0yNTZcIixcclxuICAgICAgfSxcclxuICAgICAgZmFsc2UsXHJcbiAgICAgIFsndmVyaWZ5J11cclxuICAgICk7XHJcbiAgXHJcbiAgICBjb25zdCB0ZXh0VG9WZXJpZnkgPSBuZXcgVGV4dEVuY29kZXIoKS5lbmNvZGUoc3RyaW5nKTtcclxuICAgIGNvbnN0IHZlcmlmaWNhdGlvbiA9IGF3YWl0IGNyeXB0by5zdWJ0bGUudmVyaWZ5KFxyXG4gICAgICB7XHJcbiAgICAgICAgbmFtZTogXCJFQ0RTQVwiLFxyXG4gICAgICAgIGhhc2g6IFwiU0hBLTI1NlwiXHJcbiAgICAgIH0sXHJcbiAgICAgIHB1YlNLZXlfcywgLy8gU2VydmVyJ3MgcHVibGljIEVDRFNBIGtleVxyXG4gICAgICBzaWduYXR1cmVfdUludDgsIC8vIFNlcnZlcidzIHNpZ25hdHVyZVxyXG4gICAgICB0ZXh0VG9WZXJpZnkgLy8gRW5jcnlwdGVkIG9iamVjdFxyXG4gICAgKVxyXG4gIFxyXG4gICAgcmV0dXJuIHZlcmlmaWNhdGlvbjtcclxuICB9O1xyXG5cclxuICBhc3luYyBzaWduT2JqZWN0KG9iamVjdDogb2JqZWN0LCBwcml2U0tleTogQ3J5cHRvS2V5KTogUHJvbWlzZTxzdHJpbmc+IHtcclxuICAgIGNvbnN0IG9iamVjdF9zdHJpbmcgPSBKU09OLnN0cmluZ2lmeShvYmplY3QpO1xyXG4gICAgY29uc3Qgb2JqZWN0X3VJbnQ4ID0gbmV3IFRleHRFbmNvZGVyKCkuZW5jb2RlKG9iamVjdF9zdHJpbmcpO1xyXG4gIFxyXG4gICAgY29uc3QgYXV0aFNpZ19jID0gYXdhaXQgY3J5cHRvLnN1YnRsZS5zaWduKFxyXG4gICAgICAge1xyXG4gICAgICAgICBuYW1lOiBcIkVDRFNBXCIsXHJcbiAgICAgICAgIGhhc2g6IFwiU0hBLTI1NlwiXHJcbiAgICAgICB9LFxyXG4gICAgICAgcHJpdlNLZXksXHJcbiAgICAgICBvYmplY3RfdUludDhcclxuICAgICk7XHJcbiAgXHJcbiAgICBjb25zdCBhdXRoU2lnbmF0dXJlX2NfYjY0ID0gdUludDhBcnJUb0I2NChuZXcgVWludDhBcnJheShhdXRoU2lnX2MpKTtcclxuICBcclxuICAgIHJldHVybiBhdXRoU2lnbmF0dXJlX2NfYjY0O1xyXG4gIH07XHJcblxyXG4gIGFzeW5jIHNpZ25TdHJpbmcoc3RyaW5nOiBzdHJpbmcsIHByaXZTS2V5OiBDcnlwdG9LZXkpOiBQcm9taXNlPHN0cmluZz4ge1xyXG4gICAgY29uc3Qgc3RyaW5nX3VJbnQ4ID0gbmV3IFRleHRFbmNvZGVyKCkuZW5jb2RlKHN0cmluZyk7XHJcbiAgXHJcbiAgICBjb25zdCBhdXRoU2lnX2MgPSBhd2FpdCBjcnlwdG8uc3VidGxlLnNpZ24oXHJcbiAgICAgICB7XHJcbiAgICAgICAgIG5hbWU6IFwiRUNEU0FcIixcclxuICAgICAgICAgaGFzaDogXCJTSEEtMjU2XCJcclxuICAgICAgIH0sXHJcbiAgICAgICBwcml2U0tleSxcclxuICAgICAgIHN0cmluZ191SW50OFxyXG4gICAgKTtcclxuICBcclxuICAgIGNvbnN0IGF1dGhTaWduYXR1cmVfY19iNjQgPSB1SW50OEFyclRvQjY0KG5ldyBVaW50OEFycmF5KGF1dGhTaWdfYykpO1xyXG4gIFxyXG4gICAgcmV0dXJuIGF1dGhTaWduYXR1cmVfY19iNjQ7XHJcbiAgfTtcclxuXHJcbiAgcHJpdmF0ZSBhc3luYyBkb3VibGVEZXJpdmVkU2hhcmVkU2VjcmV0KCl7XHJcbiAgICBpZighdGhpcy5zaGFyZWRTYWx0X2I2NCkgdGhyb3cgbmV3IEVycm9yKFwiTGF5ZXI4IHNoYXJlZFNhbHRfYjY0IHdhcyBub3QgaW5pdGlhbGl6ZWQgcHJvcGVybHkuXCIpO1xyXG4gICAgaWYoIXRoaXMucHViREhKV0tfbTJzcGEpIHRocm93IG5ldyBFcnJvcihcIkxheWVyOCBwdWJESEpXSyB3YXMgbm90IGluaXRpYWxpemVkIHByb3Blcmx5LlwiKTtcclxuICAgIGlmKCF0aGlzLmtleVBhaXJESF9zcGEpIHRocm93IG5ldyBFcnJvcihcIkxheWVyOCBrZXlQYWlyREggd2FzIG5vdCBpbml0aWFsaXplZCBwcm9wZXJseS5cIik7XHJcbiAgICBjb25zdCBzaGFyZWRTYWx0X3VJbnQ4ID0gYjY0VG9VaW50OEFycih0aGlzLnNoYXJlZFNhbHRfYjY0LCAwKTtcclxuICAgIGNvbnN0IHB1YkRIS2V5X20yc3BhID0gYXdhaXQgY3J5cHRvLnN1YnRsZS5pbXBvcnRLZXkoXHJcbiAgICAgIFwiandrXCIsXHJcbiAgICAgIDxKc29uV2ViS2V5PnRoaXMucHViREhKV0tfbTJzcGEsXHJcbiAgICAgIHtcclxuICAgICAgICBuYW1lOiBcIkVDREhcIixcclxuICAgICAgICBuYW1lZEN1cnZlOiBcIlAtMjU2XCJcclxuICAgICAgfSxcclxuICAgICAgdHJ1ZSxcclxuICAgICAgW11cclxuICAgICk7XHJcbiAgICBjb25zdCBlY2RoUmVzdWx0ID0gYXdhaXQgY3J5cHRvLnN1YnRsZS5kZXJpdmVCaXRzKFxyXG4gICAgICAgIHtcclxuICAgICAgICAgIG5hbWU6IFwiRUNESFwiLFxyXG4gICAgICAgICAgcHVibGljOiBwdWJESEtleV9tMnNwYVxyXG4gICAgICAgIH0sXHJcbiAgICAgICAgPENyeXB0b0tleT50aGlzLmtleVBhaXJESF9zcGEucHJpdmF0ZUtleSxcclxuICAgICAgICAyNTZcclxuICAgICk7XHJcbiAgICBjb25zdCBzaGFyZWRLZXlNYXRlcmlhbCA9IGF3YWl0IGNyeXB0by5zdWJ0bGUuaW1wb3J0S2V5KFxyXG4gICAgICAgIFwicmF3XCIsXHJcbiAgICAgICAgZWNkaFJlc3VsdCxcclxuICAgICAgICB7XHJcbiAgICAgICAgICBuYW1lOiBcIlBCS0RGMlwiXHJcbiAgICAgICAgfSxcclxuICAgICAgICBmYWxzZSxcclxuICAgICAgICBbXCJkZXJpdmVCaXRzXCJdXHJcbiAgICApO1xyXG4gICAgXHJcbiAgICBjb25zdCBzaGFyZWREZXJpdmVkQml0cyA9IGF3YWl0IGNyeXB0by5zdWJ0bGUuZGVyaXZlQml0cyhcclxuICAgICAgICB7XHJcbiAgICAgICAgICBuYW1lOiBcIlBCS0RGMlwiLFxyXG4gICAgICAgICAgc2FsdDogc2hhcmVkU2FsdF91SW50OCxcclxuICAgICAgICAgIGl0ZXJhdGlvbnM6IDEwMDAwLFxyXG4gICAgICAgICAgaGFzaDogJ1NIQS0yNTYnXHJcbiAgICAgICAgfSxcclxuICAgICAgICBzaGFyZWRLZXlNYXRlcmlhbCxcclxuICAgICAgICAyNTZcclxuICAgICk7XHJcbiAgICBcclxuICAgIHRoaXMuc2hhcmVkU2VjcmV0ID0gYXdhaXQgY3J5cHRvLnN1YnRsZS5pbXBvcnRLZXkoXHJcbiAgICAgICAgJ3JhdycsXHJcbiAgICAgICAgc2hhcmVkRGVyaXZlZEJpdHMsXHJcbiAgICAgICAge1xyXG4gICAgICAgICAgbmFtZTogXCJBRVMtR0NNXCIsXHJcbiAgICAgICAgfSxcclxuICAgICAgICB0cnVlLFxyXG4gICAgICAgIFsnZW5jcnlwdCcsICdkZWNyeXB0J11cclxuICAgICk7XHJcblxyXG4gICAgcmV0dXJuIG51bGw7XHJcbiAgfTtcclxuXHJcbiAgcHJpdmF0ZSBhc3luYyBzeW1tZXRyaWNEZWNyeXB0KGNpcGhlcnRleHRfYjY0OiBzdHJpbmcpIHtcclxuICAgIGlmKCF0aGlzLnNoYXJlZFNlY3JldCkgdGhyb3cgbmV3IEVycm9yKFwiTGF5ZXIgOCBzaGFyZWRTZWNyZXQgd2FzIG5vdCBwcm9wZXJseSBpbml0aWFsaXplZC5cIik7XHJcbiAgICBjb25zdCBjaXBoZXJ0ZXh0ID0gYjY0VG9VaW50OEFycihjaXBoZXJ0ZXh0X2I2NCwgMCk7ICBcclxuICAgIGNvbnN0IGl2ID0gY2lwaGVydGV4dC5zbGljZSgwLCAxNik7XHJcbiAgICBjb25zdCBlbmNyeXB0ZWQgPSBjaXBoZXJ0ZXh0LnNsaWNlKDE2KTtcclxuICAgIFxyXG4gICAgY29uc3QgcGxhaW50ZXh0X3VJbnQ4ID0gYXdhaXQgY3J5cHRvLnN1YnRsZS5kZWNyeXB0KFxyXG4gICAgICB7bmFtZTogJ0FFUy1HQ00nLCBpdjogaXZ9LFxyXG4gICAgICB0aGlzLnNoYXJlZFNlY3JldCxcclxuICAgICAgZW5jcnlwdGVkXHJcbiAgICApXHJcblxyXG4gICAgY29uc3QgcGxhaW50ZXh0ID0gbmV3IFRleHREZWNvZGVyKCkuZGVjb2RlKHBsYWludGV4dF91SW50OCk7XHJcblxyXG4gICAgcmV0dXJuIHBsYWludGV4dDtcclxuICB9XHJcblxyXG4gIHByaXZhdGUgYXN5bmMgc3ltbWV0cmljRW5jcnlwdChwbGFpbnRleHQ6IHN0cmluZyl7XHJcbiAgICBpZighdGhpcy5zaGFyZWRTZWNyZXQpIHRocm93IG5ldyBFcnJvcihcIkxheWVyOCB0aGlzLnNoYXJlZFNlY3JldCB3YXMgbm90IHByb3Blcmx5IGluaXRpYWxpemVkLlwiKTtcclxuICAgIGNvbnN0IHBsYWludGV4dF91SW50OCA9IG5ldyBUZXh0RW5jb2RlcigpLmVuY29kZShwbGFpbnRleHQpO1xyXG4gICAgY29uc3QgaXYgPSBuZXcgVWludDhBcnJheSgxNik7XHJcbiAgICBjcnlwdG8uZ2V0UmFuZG9tVmFsdWVzKGl2KTtcclxuICAgIGNvbnN0IGVuY3J5cHRlZCA9IGF3YWl0IGNyeXB0by5zdWJ0bGUuZW5jcnlwdChcclxuICAgICAgIHtuYW1lOiBcIkFFUy1HQ01cIiwgaXY6IGl2fSxcclxuICAgICAgIHRoaXMuc2hhcmVkU2VjcmV0LFxyXG4gICAgICAgcGxhaW50ZXh0X3VJbnQ4XHJcbiAgICApXHJcbiAgXHJcbiAgICBjb25zdCBjaXBoZXJ0ZXh0X3VJbnQ4ID0gbmV3IFVpbnQ4QXJyYXkoW1xyXG4gICAgICAgLi4uaXYsXHJcbiAgICAgICAuLi5uZXcgVWludDhBcnJheShlbmNyeXB0ZWQpXHJcbiAgICBdKTtcclxuICBcclxuICAgIGNvbnN0IGNpcGhlcnRleHRfYjY0ID0gdUludDhBcnJUb0I2NChjaXBoZXJ0ZXh0X3VJbnQ4KTtcclxuICBcclxuICAgIHJldHVybiBjaXBoZXJ0ZXh0X2I2NDtcclxuICB9XHJcblxyXG59XHJcblxyXG53aW5kb3cuTDggPSBuZXcgTDgoKTtcclxuIl19