var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { getIdByCitizenship, getUser } from "../database/users.mjs";
import { pubSJWKFromClients } from "../inMemoryKeyStore.mjs";
import { verifySignedObject, verifyMAC, verifyAndDecryptCipherText } from "../serverCryptoFunctions/serverCryptoFunctions.mjs";
// AUTHENTICATOR MIDDLEWARE
export function authenticator(req_c, res_rp, next) {
    return __awaiter(this, void 0, void 0, function* () {
        const headers = req_c.headers;
        const citizen = req_c.header("x-citizen");
        try {
            if (!citizen)
                throw new Error("'x-citizen' http header was null or undefined");
            const userId = yield getIdByCitizenship(citizen);
            const x_signedFullJWT_spa = JSON.parse(headers["x-signedfulljwt-spa"]);
            const { fullJWT, signature_b64 } = x_signedFullJWT_spa;
            const pubSJWK_spa2p = pubSJWKFromClients.get(userId);
            if (!pubSJWK_spa2p)
                throw new Error("Citizen does not have associated pubSJWK_spa2p?");
            const fullJWT_verification = yield verifySignedObject(fullJWT, pubSJWK_spa2p, signature_b64);
            if (fullJWT_verification === false) {
                console.log("[L138] fullJWT failed verification");
            }
            else { // Move on to check the MAC...
                const HMAC_b64 = fullJWT['HMAC_b64'];
                const ivedPayload_encrypted_b64 = fullJWT['ivedPayload_encrypted_b64'];
                const MAC_verification = yield verifyMAC(HMAC_b64, ivedPayload_encrypted_b64);
                if (MAC_verification === false) {
                    console.log("[Proxy] MAC failed verification");
                }
                else { // Move on to verify the encrypted body...
                    const plaintext_JSON = yield verifyAndDecryptCipherText(ivedPayload_encrypted_b64);
                    const { userId: decryptedUserId } = plaintext_JSON;
                    if (!plaintext_JSON) { // Final test of the full JWT
                        console.log("Error while, or unable to, decrypt the FullJWTs payload.");
                    }
                    else {
                        const chosenIdentity = citizen;
                        const identifiedUser = yield getUser(userId);
                        if (userId != decryptedUserId) {
                            throw new Error("Supplied userId does not equal the decryptedUserId");
                        }
                        else if (!identifiedUser.identities.includes(chosenIdentity)) {
                            throw new Error("Chosen identity not available on this user.");
                        }
                        else {
                            //Full JWT has passwed all checks.
                            next();
                        }
                    }
                }
            }
        }
        catch (err) {
            console.log("Error unknown while authenticating the FullJWT.");
            res_rp.end("FYI: Error unknown while authenticating the FullJWT.");
        }
    });
}
//EXPORT DEFAULT
export default authenticator;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiYXV0aGVudGljYXRvci5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbImF1dGhlbnRpY2F0b3IudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7Ozs7Ozs7O0FBQ0EsT0FBTyxFQUFFLGtCQUFrQixFQUFFLE9BQU8sRUFBRSxNQUFNLHVCQUF1QixDQUFDO0FBQ3BFLE9BQU8sRUFBRSxrQkFBa0IsRUFBRSxNQUFNLHlCQUF5QixDQUFDO0FBQzdELE9BQU8sRUFDTCxrQkFBa0IsRUFDbEIsU0FBUyxFQUNULDBCQUEwQixFQUMzQixNQUFNLG9EQUFvRCxDQUFDO0FBa0M1RCwyQkFBMkI7QUFDM0IsTUFBTSxVQUFnQixhQUFhLENBQUMsS0FBYyxFQUFFLE1BQWdCLEVBQUUsSUFBa0I7O1FBQ3RGLE1BQU0sT0FBTyxHQUFHLEtBQUssQ0FBQyxPQUFPLENBQUM7UUFDOUIsTUFBTSxPQUFPLEdBQUcsS0FBSyxDQUFDLE1BQU0sQ0FBQyxXQUFXLENBQUMsQ0FBQztRQUMxQyxJQUFHO1lBQ0QsSUFBRyxDQUFDLE9BQU87Z0JBQUUsTUFBTSxJQUFJLEtBQUssQ0FBQywrQ0FBK0MsQ0FBQyxDQUFDO1lBQzlFLE1BQU0sTUFBTSxHQUFHLE1BQU0sa0JBQWtCLENBQUMsT0FBTyxDQUFDLENBQUM7WUFDakQsTUFBTSxtQkFBbUIsR0FBRyxJQUFJLENBQUMsS0FBSyxDQUFTLE9BQU8sQ0FBQyxxQkFBcUIsQ0FBQyxDQUFDLENBQUM7WUFDL0UsTUFBTSxFQUFFLE9BQU8sRUFBRSxhQUFhLEVBQUUsR0FBbUIsbUJBQW1CLENBQUM7WUFDdkUsTUFBTSxhQUFhLEdBQUcsa0JBQWtCLENBQUMsR0FBRyxDQUFDLE1BQU0sQ0FBQyxDQUFDO1lBQ3JELElBQUcsQ0FBQyxhQUFhO2dCQUFFLE1BQU0sSUFBSSxLQUFLLENBQUMsaURBQWlELENBQUMsQ0FBQztZQUN0RixNQUFNLG9CQUFvQixHQUFHLE1BQU0sa0JBQWtCLENBQUMsT0FBTyxFQUFFLGFBQWEsRUFBRSxhQUFhLENBQUMsQ0FBQztZQUM3RixJQUFJLG9CQUFvQixLQUFLLEtBQUssRUFBRTtnQkFDbEMsT0FBTyxDQUFDLEdBQUcsQ0FBQyxvQ0FBb0MsQ0FBQyxDQUFDO2FBQ25EO2lCQUFNLEVBQUUsOEJBQThCO2dCQUNyQyxNQUFNLFFBQVEsR0FBRyxPQUFPLENBQUMsVUFBVSxDQUFDLENBQUM7Z0JBQ3JDLE1BQU0seUJBQXlCLEdBQUcsT0FBTyxDQUFDLDJCQUEyQixDQUFDLENBQUM7Z0JBQ3ZFLE1BQU0sZ0JBQWdCLEdBQUcsTUFBTSxTQUFTLENBQUUsUUFBUSxFQUFFLHlCQUF5QixDQUFFLENBQUM7Z0JBQ2hGLElBQUcsZ0JBQWdCLEtBQUssS0FBSyxFQUFFO29CQUM3QixPQUFPLENBQUMsR0FBRyxDQUFDLGlDQUFpQyxDQUFDLENBQUM7aUJBQ2hEO3FCQUFNLEVBQUUsMENBQTBDO29CQUNqRCxNQUFNLGNBQWMsR0FBYSxNQUFNLDBCQUEwQixDQUFDLHlCQUF5QixDQUFDLENBQUM7b0JBQzdGLE1BQU0sRUFBRSxNQUFNLEVBQUUsZUFBZSxFQUFFLEdBQUcsY0FBYyxDQUFDO29CQUVuRCxJQUFHLENBQUMsY0FBYyxFQUFDLEVBQUUsNkJBQTZCO3dCQUNoRCxPQUFPLENBQUMsR0FBRyxDQUFDLDBEQUEwRCxDQUFDLENBQUM7cUJBQ3pFO3lCQUFNO3dCQUNMLE1BQU0sY0FBYyxHQUFHLE9BQU8sQ0FBQzt3QkFDL0IsTUFBTSxjQUFjLEdBQVUsTUFBTSxPQUFPLENBQUMsTUFBTSxDQUFDLENBQUM7d0JBQ3BELElBQUcsTUFBTSxJQUFJLGVBQWUsRUFBQzs0QkFDM0IsTUFBTSxJQUFJLEtBQUssQ0FBQyxvREFBb0QsQ0FBQyxDQUFDO3lCQUN2RTs2QkFBTSxJQUFJLENBQUMsY0FBYyxDQUFDLFVBQVUsQ0FBQyxRQUFRLENBQUMsY0FBYyxDQUFDLEVBQUM7NEJBQzdELE1BQU0sSUFBSSxLQUFLLENBQUMsNkNBQTZDLENBQUMsQ0FBQTt5QkFDL0Q7NkJBQU07NEJBQ0wsa0NBQWtDOzRCQUNsQyxJQUFJLEVBQUUsQ0FBQzt5QkFDUjtxQkFDRjtpQkFDRjthQUNGO1NBQ0Y7UUFBQyxPQUFPLEdBQUcsRUFBQztZQUNYLE9BQU8sQ0FBQyxHQUFHLENBQUMsaURBQWlELENBQUMsQ0FBQztZQUMvRCxNQUFNLENBQUMsR0FBRyxDQUFDLHNEQUFzRCxDQUFDLENBQUM7U0FDcEU7SUFDSCxDQUFDO0NBQUE7QUFFRCxnQkFBZ0I7QUFDaEIsZUFBZSxhQUFhLENBQUMiLCJzb3VyY2VzQ29udGVudCI6WyJpbXBvcnQgeyBSZXF1ZXN0LCBSZXNwb25zZSwgTmV4dEZ1bmN0aW9uIH0gZnJvbSBcImV4cHJlc3NcIjtcclxuaW1wb3J0IHsgZ2V0SWRCeUNpdGl6ZW5zaGlwLCBnZXRVc2VyIH0gZnJvbSBcIi4uL2RhdGFiYXNlL3VzZXJzLm1qc1wiO1xyXG5pbXBvcnQgeyBwdWJTSldLRnJvbUNsaWVudHMgfSBmcm9tIFwiLi4vaW5NZW1vcnlLZXlTdG9yZS5tanNcIjtcclxuaW1wb3J0IHtcclxuICB2ZXJpZnlTaWduZWRPYmplY3QsXHJcbiAgdmVyaWZ5TUFDLFxyXG4gIHZlcmlmeUFuZERlY3J5cHRDaXBoZXJUZXh0XHJcbn0gZnJvbSBcIi4uL3NlcnZlckNyeXB0b0Z1bmN0aW9ucy9zZXJ2ZXJDcnlwdG9GdW5jdGlvbnMubWpzXCI7XHJcblxyXG5cclxuLy8gSU5URVJGQUNFU1xyXG5leHBvcnQgaW50ZXJmYWNlIElQYXlsb2FkIHtcclxuICB1c2VybmFtZTogc3RyaW5nLFxyXG4gIHVzZXJJZDogc3RyaW5nLFxyXG4gIGV4cGlyeTogbnVtYmVyLFxyXG4gIGNob3NlbklkZW50aXR5OiBzdHJpbmcgfCBudWxsO1xyXG59XHJcblxyXG5pbnRlcmZhY2UgSUpXVEhlYWRlciB7XHJcbiAgdHlwOiBzdHJpbmcsXHJcbiAgc2lnOiBzdHJpbmdcclxufVxyXG5cclxuaW50ZXJmYWNlIElGdWxsSldUIHtcclxuICBKV1RIZWFkZXI6IElKV1RIZWFkZXIsXHJcbiAgaXZlZFBheWxvYWRfZW5jcnlwdGVkX2I2NDogc3RyaW5nLFxyXG4gIEhNQUNfYjY0OiBzdHJpbmdcclxufVxyXG5cclxuaW50ZXJmYWNlIElTaWduZWRGdWxsSldUIHtcclxuICBmdWxsSldUOiBJRnVsbEpXVCxcclxuICBzaWduYXR1cmVfYjY0OiBzdHJpbmdcclxufVxyXG5cclxuaW50ZXJmYWNlIElVc2VyIHtcclxuICB1c2VybmFtZTogc3RyaW5nLFxyXG4gIGhhc2hlZFBhc3N3b3JkX2I2NDogc3RyaW5nLFxyXG4gIHVzZXJTYWx0X2I2NDogc3RyaW5nLFxyXG4gIGlkZW50aXRpZXM6IHN0cmluZ1tdLFxyXG59XHJcblxyXG4vLyBBVVRIRU5USUNBVE9SIE1JRERMRVdBUkVcclxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGF1dGhlbnRpY2F0b3IocmVxX2M6IFJlcXVlc3QsIHJlc19ycDogUmVzcG9uc2UsIG5leHQ6IE5leHRGdW5jdGlvbik6IFByb21pc2U8dm9pZD4ge1xyXG4gIGNvbnN0IGhlYWRlcnMgPSByZXFfYy5oZWFkZXJzO1xyXG4gIGNvbnN0IGNpdGl6ZW4gPSByZXFfYy5oZWFkZXIoXCJ4LWNpdGl6ZW5cIik7XHJcbiAgdHJ5e1xyXG4gICAgaWYoIWNpdGl6ZW4pIHRocm93IG5ldyBFcnJvcihcIid4LWNpdGl6ZW4nIGh0dHAgaGVhZGVyIHdhcyBudWxsIG9yIHVuZGVmaW5lZFwiKTtcclxuICAgIGNvbnN0IHVzZXJJZCA9IGF3YWl0IGdldElkQnlDaXRpemVuc2hpcChjaXRpemVuKTtcclxuICAgIGNvbnN0IHhfc2lnbmVkRnVsbEpXVF9zcGEgPSBKU09OLnBhcnNlKDxzdHJpbmc+aGVhZGVyc1tcIngtc2lnbmVkZnVsbGp3dC1zcGFcIl0pO1xyXG4gICAgY29uc3QgeyBmdWxsSldULCBzaWduYXR1cmVfYjY0IH0gPSA8SVNpZ25lZEZ1bGxKV1Q+eF9zaWduZWRGdWxsSldUX3NwYTtcclxuICAgIGNvbnN0IHB1YlNKV0tfc3BhMnAgPSBwdWJTSldLRnJvbUNsaWVudHMuZ2V0KHVzZXJJZCk7XHJcbiAgICBpZighcHViU0pXS19zcGEycCkgdGhyb3cgbmV3IEVycm9yKFwiQ2l0aXplbiBkb2VzIG5vdCBoYXZlIGFzc29jaWF0ZWQgcHViU0pXS19zcGEycD9cIik7XHJcbiAgICBjb25zdCBmdWxsSldUX3ZlcmlmaWNhdGlvbiA9IGF3YWl0IHZlcmlmeVNpZ25lZE9iamVjdChmdWxsSldULCBwdWJTSldLX3NwYTJwLCBzaWduYXR1cmVfYjY0KTtcclxuICAgIGlmKCBmdWxsSldUX3ZlcmlmaWNhdGlvbiA9PT0gZmFsc2UgKXtcclxuICAgICAgY29uc29sZS5sb2coXCJbTDEzOF0gZnVsbEpXVCBmYWlsZWQgdmVyaWZpY2F0aW9uXCIpO1xyXG4gICAgfSBlbHNlIHsgLy8gTW92ZSBvbiB0byBjaGVjayB0aGUgTUFDLi4uXHJcbiAgICAgIGNvbnN0IEhNQUNfYjY0ID0gZnVsbEpXVFsnSE1BQ19iNjQnXTtcclxuICAgICAgY29uc3QgaXZlZFBheWxvYWRfZW5jcnlwdGVkX2I2NCA9IGZ1bGxKV1RbJ2l2ZWRQYXlsb2FkX2VuY3J5cHRlZF9iNjQnXTtcclxuICAgICAgY29uc3QgTUFDX3ZlcmlmaWNhdGlvbiA9IGF3YWl0IHZlcmlmeU1BQyggSE1BQ19iNjQsIGl2ZWRQYXlsb2FkX2VuY3J5cHRlZF9iNjQgKTtcclxuICAgICAgaWYoTUFDX3ZlcmlmaWNhdGlvbiA9PT0gZmFsc2UgKXtcclxuICAgICAgICBjb25zb2xlLmxvZyhcIltQcm94eV0gTUFDIGZhaWxlZCB2ZXJpZmljYXRpb25cIik7XHJcbiAgICAgIH0gZWxzZSB7IC8vIE1vdmUgb24gdG8gdmVyaWZ5IHRoZSBlbmNyeXB0ZWQgYm9keS4uLlxyXG4gICAgICAgIGNvbnN0IHBsYWludGV4dF9KU09OOiBJUGF5bG9hZCA9IGF3YWl0IHZlcmlmeUFuZERlY3J5cHRDaXBoZXJUZXh0KGl2ZWRQYXlsb2FkX2VuY3J5cHRlZF9iNjQpO1xyXG4gICAgICAgIGNvbnN0IHsgdXNlcklkOiBkZWNyeXB0ZWRVc2VySWQgfSA9IHBsYWludGV4dF9KU09OO1xyXG5cclxuICAgICAgICBpZighcGxhaW50ZXh0X0pTT04peyAvLyBGaW5hbCB0ZXN0IG9mIHRoZSBmdWxsIEpXVFxyXG4gICAgICAgICAgY29uc29sZS5sb2coXCJFcnJvciB3aGlsZSwgb3IgdW5hYmxlIHRvLCBkZWNyeXB0IHRoZSBGdWxsSldUcyBwYXlsb2FkLlwiKTtcclxuICAgICAgICB9IGVsc2Uge1xyXG4gICAgICAgICAgY29uc3QgY2hvc2VuSWRlbnRpdHkgPSBjaXRpemVuO1xyXG4gICAgICAgICAgY29uc3QgaWRlbnRpZmllZFVzZXIgPSA8SVVzZXI+YXdhaXQgZ2V0VXNlcih1c2VySWQpO1xyXG4gICAgICAgICAgaWYodXNlcklkICE9IGRlY3J5cHRlZFVzZXJJZCl7XHJcbiAgICAgICAgICAgIHRocm93IG5ldyBFcnJvcihcIlN1cHBsaWVkIHVzZXJJZCBkb2VzIG5vdCBlcXVhbCB0aGUgZGVjcnlwdGVkVXNlcklkXCIpO1xyXG4gICAgICAgICAgfSBlbHNlIGlmICghaWRlbnRpZmllZFVzZXIuaWRlbnRpdGllcy5pbmNsdWRlcyhjaG9zZW5JZGVudGl0eSkpe1xyXG4gICAgICAgICAgICB0aHJvdyBuZXcgRXJyb3IoXCJDaG9zZW4gaWRlbnRpdHkgbm90IGF2YWlsYWJsZSBvbiB0aGlzIHVzZXIuXCIpXHJcbiAgICAgICAgICB9IGVsc2Uge1xyXG4gICAgICAgICAgICAvL0Z1bGwgSldUIGhhcyBwYXNzd2VkIGFsbCBjaGVja3MuXHJcbiAgICAgICAgICAgIG5leHQoKTtcclxuICAgICAgICAgIH1cclxuICAgICAgICB9XHJcbiAgICAgIH1cclxuICAgIH1cclxuICB9IGNhdGNoIChlcnIpe1xyXG4gICAgY29uc29sZS5sb2coXCJFcnJvciB1bmtub3duIHdoaWxlIGF1dGhlbnRpY2F0aW5nIHRoZSBGdWxsSldULlwiKTtcclxuICAgIHJlc19ycC5lbmQoXCJGWUk6IEVycm9yIHVua25vd24gd2hpbGUgYXV0aGVudGljYXRpbmcgdGhlIEZ1bGxKV1QuXCIpO1xyXG4gIH1cclxufVxyXG5cclxuLy9FWFBPUlQgREVGQVVMVFxyXG5leHBvcnQgZGVmYXVsdCBhdXRoZW50aWNhdG9yO1xyXG4iXX0=