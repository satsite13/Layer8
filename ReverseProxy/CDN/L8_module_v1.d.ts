declare global {
    interface Window {
        L8: L8;
    }
}
declare type SignupData = {
    availableIdentities: string[];
};
declare type AvailableIdentities = {
    availableIdentities: string[];
};
interface IStdRes<T> {
    errorFlag: boolean;
    msg: string | null;
    data: T | null;
}
interface IJWTHeader {
    typ: string;
    sig: string;
}
interface IFullJWT {
    JWTHeader: IJWTHeader;
    ivedPayload_encrypted_b64: string;
    HMAC_b64: string;
}
declare class L8 {
    private serviceProviderId;
    private providerIsValid;
    private keyPairS_c;
    private halfJWT;
    private keyPairDH_spa;
    private pubSJWK_m2spa;
    private pubDHJWK_m2spa;
    private sharedSalt_b64;
    private sharedSecret;
    private privSJWK_c;
    private pubSJWK_c;
    private pubSJWK_s;
    constructor();
    private checkServiceProviderId;
    registerServiceProviderId(trialProviderId: string): Promise<boolean>;
    trialSignup(trialUsername: string, password: string): Promise<IStdRes<SignupData>>;
    attemptLogin(username: string, password: string): Promise<IStdRes<AvailableIdentities>>;
    chooseIdentity(username: string, chosenIdentity: string): Promise<IStdRes<null>>;
    registerCitizenship(fullJWT: IFullJWT, chosenIdentity: string): Promise<void>;
    establishTunnel(): Promise<void>;
    proxy(data: JSON): Promise<any>;
    usernameToUserId(username: string): Promise<string>;
    verifySignedObject(object: object, pubSJWK: JsonWebKey, signature_b64: string): Promise<boolean>;
    verifySignedString(string: string, pubSJWK: JsonWebKey, signature_b64: string): Promise<boolean>;
    signObject(object: object, privSKey: CryptoKey): Promise<string>;
    signString(string: string, privSKey: CryptoKey): Promise<string>;
    private doubleDerivedSharedSecret;
    private symmetricDecrypt;
    private symmetricEncrypt;
}
export {};
