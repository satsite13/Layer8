var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { getCitizenId } from "../database/MockedDatabase.mjs";
import { createUserId, storeCryptoAsset, getPubSJWK, getPubDHJWK, getSharedSalt, doubleDerivedSharedSecret, symmetricEncrypt, symmetricDecrypt, verifySignedString, signString, } from "./moduleCryptoFunctions.js";
;
// MODULE ROUTER (PRIMARY / DEFAULT FUNCTION)
function Layer8(req, res, next) {
    const parsedURL = new URL(req.url, "http://localhost");
    console.log(parsedURL);
    const pathname = parsedURL.pathname;
    req["citizenCheck"] = false;
    if (pathname === "/proxied") {
        proxied(req, res, next);
        return;
    }
    else if (pathname === "/ecdh_init") {
        ECDHInit(req, res, next);
        return;
    }
    else {
        console.log("This user is going to be anonymous");
        next();
        return;
    }
}
;
// LAYER8 ENDPOINTS
// Proxied Endpoint
function proxied(req, res, next) {
    return __awaiter(this, void 0, void 0, function* () {
        console.log("Hit: 'proxied' within 'module'.", "\n");
        try {
            const citizen = req.header("x-citizen");
            if (!citizen)
                throw new Error("Error reading 'x-citizen' header.");
            const citizenId = yield getCitizenId(citizen);
            const sealedEnvelope_spa2m = req.body.sealedEnvelope_spa2m;
            console.log("sealedEnvelope_spa2m.errorFlag: ", sealedEnvelope_spa2m.errorFlag);
            console.log("sealedEnvelope_spa2m.msg: ", sealedEnvelope_spa2m.msg);
            const { encryptedData_b64, encryptedDataSignature_b64 } = sealedEnvelope_spa2m;
            const signatureVerification = yield verifySignedString(citizenId, encryptedData_b64, encryptedDataSignature_b64); // SideEffects*
            if (signatureVerification === false) {
                console.log("The signature of the signed spa object did not pass.");
                res.writeHead(400, {
                    "Content-Type": "application/json",
                    "x-citizen": citizen
                });
                const body = JSON.stringify({
                    "errorFlag": true,
                    "msg": "The encrypted SPA data did not pass verification.",
                    "data": null,
                });
                res.end(JSON.stringify(body));
            }
            else { // spa2m encrypted data is legitimately from the associated citizen.
                const unencryptedDataObj_spa2m_str = yield symmetricDecrypt(citizenId, encryptedData_b64);
                const unencryptedDataObj_spa2m = JSON.parse(unencryptedDataObj_spa2m_str);
                //console.log("IEncryptedData_spa2m: ", unencryptedDataObj_spa2m);
                if (unencryptedDataObj_spa2m.errorFlag === true) {
                    console.log("SPA is reporting an error.");
                    res.writeHead(400, {
                        "Content-Type": "application/json",
                        "x-citizen": citizen
                    });
                    const body = JSON.stringify({
                        "errorFlag": true,
                        "msg": "SPA has reported error.",
                        "data": null,
                    });
                    res.end(JSON.stringify(body));
                }
                else if (unencryptedDataObj_spa2m.init === true) {
                    const serviceProviderResp = {
                        "errorFlag": false,
                        "msg": "ECDH initiation response",
                        "data": null,
                    };
                    const serviceProviderResp_str = JSON.stringify(serviceProviderResp);
                    const encryptedData_b64 = yield symmetricEncrypt(citizenId, serviceProviderResp_str);
                    const encryptedDataSignature_b64 = yield signString(citizenId, encryptedData_b64); // SideEffects*
                    const sealedEnvelope = {
                        errorFlag: false,
                        msg: "Sealed Envelope in response to ECDH initialization request.",
                        encryptedData_b64,
                        encryptedDataSignature_b64,
                    };
                    res.writeHead(200, {
                        "content-type": "application/json"
                    });
                    res.end(JSON.stringify(sealedEnvelope));
                }
                else if (unencryptedDataObj_spa2m.init === false) { // i.e. A standard request.
                    // Here, the SPA's details can be added to the standard Node request object for access by the service provider
                    req["citizen"] = citizen;
                    req["citizenId"] = citizenId;
                    req["L8"] = unencryptedDataObj_spa2m;
                    req["citizenCheck"] = true;
                    req.url = `/${unencryptedDataObj_spa2m.path}`;
                    req.method = unencryptedDataObj_spa2m.method;
                    console.log("req.url: ", req.url);
                    next();
                    return;
                }
            }
        }
        catch (err) {
            console.log("Error in the Module's 'proxied' route.");
        }
    });
}
// ECHD Endpoint
function ECDHInit(req, res, next) {
    return __awaiter(this, void 0, void 0, function* () {
        //Time to gather necessary info for ECDH
        try {
            const citizen = req.header("x-citizen");
            const pubDHJWK_spa2m_str = req.header("x-pubdhjwk-spa2m");
            const pubSJWK_spa2m_str = req.header("x-pubsjwk-spa2m");
            if (!citizen)
                throw new Error("x-citizen header not defined.");
            if (!pubDHJWK_spa2m_str)
                throw new Error("x-pubdhjwk-spa2m header not defined.");
            if (!pubSJWK_spa2m_str)
                throw new Error("x-pubsjwk-spa2m header not defined.");
            const citizenId = yield createUserId(citizen); // TODO: What if citizen already exists?
            const pubSJWK_spa2m = JSON.parse(pubSJWK_spa2m_str);
            const pubDHJWK_spa2m = JSON.parse(pubDHJWK_spa2m_str);
            storeCryptoAsset(citizenId, "pubSJWK_spa2m", pubSJWK_spa2m);
            storeCryptoAsset(citizenId, "pubDHJWK_spa2m", pubDHJWK_spa2m);
            const pubSJWK_m2spa = yield getPubSJWK(citizenId); // Side Effects*
            const pubDHJWK_m2spa = yield getPubDHJWK(citizenId); // Side Effects*
            const sharedSalt_b64 = yield getSharedSalt(citizenId); // Side Effects*
            yield doubleDerivedSharedSecret(citizenId); // Side Effects*
            const messageObj = {
                "msg": "module 2 spa check",
                "errorFlag": false,
                "data": null
            };
            const messageStr = JSON.stringify(messageObj);
            const encryptedMsg_b64 = yield symmetricEncrypt(citizenId, messageStr);
            res.writeHead(200, {
                "Content-Type": "application/json",
                "x-citizen": citizen,
                "x-pubsjwk-m2spa": JSON.stringify(pubSJWK_m2spa),
                "x-pubdhjwk-m2spa": JSON.stringify(pubDHJWK_m2spa),
                "x-sharedsalt-b64": sharedSalt_b64
            });
            // TODO: Note that this is NOT a true ISealedEnvelope. The reason is that an attacker who supplies BOTH their pubSJWK and their signature could be anyone. The Layer8 reverse proxy should have the store of public signing keys and serve them to the SPA.
            const body /*ISealedEnvelope*/ = JSON.stringify({
                "errorFlag": false,
                "msg": "See encryptedMsg_b64 for the encrypted",
                "encryptedData_b64": encryptedMsg_b64,
                "encryptedDataSignature_b64": null
            });
            res.end(body);
            return;
        }
        catch (err) {
            console.log("[Catch block of the Module's ECDH Init route.]", err);
            return;
        }
    });
}
export default Layer8;
function returnEncryptedData(req, res, data) {
    return __awaiter(this, void 0, void 0, function* () {
        console.log("Function 'returnEncryptedData' has been called on:", data.title);
        const citizenId = yield createUserId(req['citizen']); // TODO: should be 'createCitizenId()'
        const encryptedReturnMsg_b64 = yield symmetricEncrypt(citizenId, JSON.stringify(data));
        const signature_b64_m2spa = yield signString(citizenId, encryptedReturnMsg_b64);
        const msgAndSignature_m2spa = {
            errorFlag: false,
            msg: "this is it bud.",
            encryptedData_b64: encryptedReturnMsg_b64,
            encryptedDataSignature_b64: signature_b64_m2spa
        };
        res.writeHead(200, {
            "content-type": "application/json",
            "x-citizen": req['citizen'],
        });
        res.end(JSON.stringify(msgAndSignature_m2spa));
    });
}
export const L8 = {
    returnEncryptedData
};
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiTW9kdWxlLmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiTW9kdWxlLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7Ozs7Ozs7OztBQUNBLE9BQU8sRUFBRSxZQUFZLEVBQUUsTUFBTSxnQ0FBZ0MsQ0FBQTtBQUM3RCxPQUFPLEVBQ0wsWUFBWSxFQUNaLGdCQUFnQixFQUNoQixVQUFVLEVBQ1YsV0FBVyxFQUNYLGFBQWEsRUFDYix5QkFBeUIsRUFDekIsZ0JBQWdCLEVBQ2hCLGdCQUFnQixFQUNoQixrQkFBa0IsRUFDbEIsVUFBVSxHQUNYLE1BQU0sNEJBQTRCLENBQUM7QUFjbkMsQ0FBQztBQTBCRiw2Q0FBNkM7QUFDN0MsU0FBUyxNQUFNLENBQUUsR0FBYyxFQUFFLEdBQWEsRUFBRSxJQUFrQjtJQUNoRSxNQUFNLFNBQVMsR0FBRyxJQUFJLEdBQUcsQ0FBQyxHQUFHLENBQUMsR0FBRyxFQUFFLGtCQUFrQixDQUFDLENBQUM7SUFDdkQsT0FBTyxDQUFDLEdBQUcsQ0FBQyxTQUFTLENBQUMsQ0FBQztJQUN2QixNQUFNLFFBQVEsR0FBRyxTQUFTLENBQUMsUUFBUSxDQUFDO0lBQ3BDLEdBQUcsQ0FBQyxjQUFjLENBQUMsR0FBRyxLQUFLLENBQUM7SUFFNUIsSUFBRyxRQUFRLEtBQUssVUFBVSxFQUFDO1FBQ3pCLE9BQU8sQ0FBQyxHQUFHLEVBQUUsR0FBRyxFQUFFLElBQUksQ0FBQyxDQUFDO1FBQ3hCLE9BQU87S0FDUjtTQUFNLElBQUksUUFBUSxLQUFLLFlBQVksRUFBQztRQUNuQyxRQUFRLENBQUMsR0FBRyxFQUFFLEdBQUcsRUFBRSxJQUFJLENBQUMsQ0FBQztRQUN6QixPQUFPO0tBQ1I7U0FBTTtRQUNMLE9BQU8sQ0FBQyxHQUFHLENBQUMsb0NBQW9DLENBQUMsQ0FBQztRQUNsRCxJQUFJLEVBQUUsQ0FBQztRQUNQLE9BQU87S0FDUjtBQUNILENBQUM7QUFBQSxDQUFDO0FBRUYsbUJBQW1CO0FBQ25CLG1CQUFtQjtBQUNuQixTQUFlLE9BQU8s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LE9BQU8sQ0FBQyxHQUFHLENBQUMsb0RBQW9ELEVBQUUsSUFBSSxDQUFDLEtBQUssQ0FBQyxDQUFDO1FBRTlFLE1BQU0sU0FBUyxHQUFHLE1BQU0sWUFBWSxDQUFDLEdBQUcsQ0FBQyxTQUFTLENBQUMsQ0FBQyxDQUFDLENBQUMsc0NBQXNDO1FBQzVGLE1BQU0sc0JBQXNCLEdBQUcsTUFBTSxnQkFBZ0IsQ0FBQyxTQUFTLEVBQUUsSUFBSSxDQUFDLFNBQVMsQ0FBQyxJQUFJLENBQUMsQ0FBQyxDQUFDO1FBQ3ZGLE1BQU0sbUJBQW1CLEdBQUcsTUFBTSxVQUFVLENBQUMsU0FBUyxFQUFFLHNCQUFzQixDQUFDLENBQUM7UUFFaEYsTUFBTSxxQkFBcUIsR0FBb0I7WUFDN0MsU0FBUyxFQUFFLEtBQUs7WUFDaEIsR0FBRyxFQUFFLGlCQUFpQjtZQUN0QixpQkFBaUIsRUFBRSxzQkFBc0I7WUFDekMsMEJBQTBCLEVBQUUsbUJBQW1CO1NBQ2hELENBQUM7UUFFRixHQUFHLENBQUMsU0FBUyxDQUFDLEdBQUcsRUFBRTtZQUNqQixjQUFjLEVBQUUsa0JBQWtCO1lBQ2xDLFdBQVcsRUFBRyxHQUFHLENBQUMsU0FBUyxDQUFDO1NBQzdCLENBQUMsQ0FBQztRQUVILEdBQUcsQ0FBQyxHQUFHLENBQUMsSUFBSSxDQUFDLFNBQVMsQ0FBQyxxQkFBcUIsQ0FBQyxDQUFDLENBQUM7SUFDakQsQ0FBQztDQUFBO0FBR0QsTUFBTSxDQUFDLE1BQU0sRUFBRSxHQUFHO0lBQ2hCLG1CQUFtQjtDQUNwQixDQUFBIiwic291cmNlc0NvbnRlbnQiOlsiaW1wb3J0IHsgUmVxdWVzdCwgUmVzcG9uc2UsIE5leHRGdW5jdGlvbiB9IGZyb20gXCJleHByZXNzXCI7XHJcbmltcG9ydCB7IGdldENpdGl6ZW5JZCB9IGZyb20gXCIuLi9kYXRhYmFzZS9Nb2NrZWREYXRhYmFzZS5tanNcIlxyXG5pbXBvcnQge1xyXG4gIGNyZWF0ZVVzZXJJZCxcclxuICBzdG9yZUNyeXB0b0Fzc2V0LFxyXG4gIGdldFB1YlNKV0ssXHJcbiAgZ2V0UHViREhKV0ssXHJcbiAgZ2V0U2hhcmVkU2FsdCxcclxuICBkb3VibGVEZXJpdmVkU2hhcmVkU2VjcmV0LFxyXG4gIHN5bW1ldHJpY0VuY3J5cHQsXHJcbiAgc3ltbWV0cmljRGVjcnlwdCxcclxuICB2ZXJpZnlTaWduZWRTdHJpbmcsXHJcbiAgc2lnblN0cmluZyxcclxufSBmcm9tIFwiLi9tb2R1bGVDcnlwdG9GdW5jdGlvbnMuanNcIjtcclxuXHJcbi8vIElOVEVSRkFDRVMgJiBUWVBFU1xyXG5pbnRlcmZhY2UgSVN0ZFJlczxUPiB7XHJcbiAgZXJyb3JGbGFnOiBib29sZWFuLFxyXG4gIG1zZzogc3RyaW5nLFxyXG4gIGRhdGE6IFQ7XHJcbn1cclxuXHJcbmludGVyZmFjZSBMOFJlcXVlc3QgZXh0ZW5kcyBSZXF1ZXN0IHtcclxuICBjaXRpemVuOiBzdHJpbmcsXHJcbiAgY2l0aXplbklkOiBzdHJpbmcsXHJcbiAgY2l0aXplbkNoZWNrOiBib29sZWFuLFxyXG4gIEw4OiBhbnlcclxufTtcclxuXHJcbmludGVyZmFjZSBJU1BSZXNwb25zZSB7XHJcbiAgbXNnOiBzdHJpbmcgfCBudWxsLFxyXG4gIGVycm9yRmxhZzogYm9vbGVhbixcclxuICBkYXRhOiBvYmplY3QgfCBudWxsXHJcbn1cclxuXHJcbmludGVyZmFjZSBJU2VhbGVkRW52ZWxvcGUge1xyXG4gIGVycm9yRmxhZzogYm9vbGVhbixcclxuICBtc2c6IHN0cmluZyB8IG51bGwsXHJcbiAgZW5jcnlwdGVkRGF0YV9iNjQ6IHN0cmluZyxcclxuICBlbmNyeXB0ZWREYXRhU2lnbmF0dXJlX2I2NDogc3RyaW5nXHJcbn1cclxuXHJcbmludGVyZmFjZSBJRW5jcnlwdGVkRGF0YV9zcGEybSB7XHJcbiAgaW5pdDogdHJ1ZSwgXHJcbiAgZXJyb3JGbGFnOiBmYWxzZSxcclxuICBwYXRoOiBudWxsLFxyXG4gIG1zZzogbnVsbCxcclxuICBtZXRob2Q6IG51bGwsXHJcbiAgcXVlcnk6IG51bGwsXHJcbiAgb3B0aW9uczogbnVsbCxcclxuICBkYXRhOiBudWxsXHJcbn1cclxuXHJcbi8vIE1PRFVMRSBST1VURVIgKFBSSU1BUlkgLyBERUZBVUxUIEZVTkNUSU9OKVxyXG5mdW5jdGlvbiBMYXllcjggKHJlcTogTDhSZXF1ZXN0LCByZXM6IFJlc3BvbnNlLCBuZXh0OiBOZXh0RnVuY3Rpb24pOiB2b2lkIHtcclxuICBjb25zdCBwYXJzZWRVUkwgPSBuZXcgVVJMKHJlcS51cmwsIFwiaHR0cDovL2xvY2FsaG9zdFwiKTtcclxuICBjb25zb2xlLmxvZyhwYXJzZWRVUkwpO1xyXG4gIGNvbnN0IHBhdGhuYW1lID0gcGFyc2VkVVJMLnBhdGhuYW1lO1xyXG4gIHJlcVtcImNpdGl6ZW5DaGVja1wiXSA9IGZhbHNlO1xyXG5cclxuICBpZihwYXRobmFtZSA9PT0gXCIvcHJveGllZFwiKXtcclxuICAgIHByb3hpZWQocmVxLCByZXMsIG5leHQpO1xyXG4gICAgcmV0dXJuO1xyXG4gIH0gZWxzZSBpZiAocGF0aG5hbWUgPT09IFwiL2VjZGhfaW5pdFwiKXtcclxuICAgIEVDREhJbml0KHJlcSwgcmVzLCBuZXh0KTtcclxuICAgIHJldHVybjtcclxuICB9IGVsc2Uge1xyXG4gICAgY29uc29sZS5sb2coXCJUaGlzIHVzZXIgaXMgZ29pbmcgdG8gYmUgYW5vbnltb3VzXCIpO1xyXG4gICAgbmV4dCgpO1xyXG4gICAgcmV0dXJuO1xyXG4gIH1cclxufTtcclxuXHJcbi8vIExBWUVSOCBFTkRQT0lOVFNcclxuLy8gUHJveGllZCBFbmRwb2ludFxyXG5hc3luYyBmdW5jdGlvbiBwcm94aWVkKHJlcTogTDhSZXF1ZXN0LCByZXM6IFJlc3BvbnNlLCBuZXh0OiBOZXh0RnVuY3Rpb24pOiBQcm9taXNlPHZvaWQ+IHtcclxuICBjb25zb2xlLmxvZyhcIkhpdDogJ3Byb3hpZWQnIHdpdGhpbiAnbW9kdWxlJy5cIiwgXCJcXG5cIik7XHJcbiAgdHJ5e1xyXG4gICAgY29uc3QgY2l0aXplbiA9IHJlcS5oZWFkZXIoXCJ4LWNpdGl6ZW5cIik7XHJcbiAgICBpZighY2l0aXplbikgdGhyb3cgbmV3IEVycm9yKFwiRXJyb3IgcmVhZGluZyAneC1jaXRpemVuJyBoZWFkZXIuXCIpO1xyXG4gICAgY29uc3QgY2l0aXplbklkID0gYXdhaXQgZ2V0Q2l0aXplbklkKGNpdGl6ZW4pO1xyXG4gICAgY29uc3Qgc2VhbGVkRW52ZWxvcGVfc3BhMm0gPSA8SVNlYWxlZEVudmVsb3BlPnJlcS5ib2R5LnNlYWxlZEVudmVsb3BlX3NwYTJtO1xyXG4gICAgY29uc29sZS5sb2coXCJzZWFsZWRFbnZlbG9wZV9zcGEybS5lcnJvckZsYWc6IFwiLCBzZWFsZWRFbnZlbG9wZV9zcGEybS5lcnJvckZsYWcpO1xyXG4gICAgY29uc29sZS5sb2coXCJzZWFsZWRFbnZlbG9wZV9zcGEybS5tc2c6IFwiLCBzZWFsZWRFbnZlbG9wZV9zcGEybS5tc2cpO1xyXG4gICAgY29uc3Qge2VuY3J5cHRlZERhdGFfYjY0LCBlbmNyeXB0ZWREYXRhU2lnbmF0dXJlX2I2NH0gPSBzZWFsZWRFbnZlbG9wZV9zcGEybTtcclxuICAgIGNvbnN0IHNpZ25hdHVyZVZlcmlmaWNhdGlvbiA9IGF3YWl0IHZlcmlmeVNpZ25lZFN0cmluZyhjaXRpemVuSWQsIGVuY3J5cHRlZERhdGFfYjY0LCBlbmNyeXB0ZWREYXRhU2lnbmF0dXJlX2I2NCk7IC8vIFNpZGVFZmZlY3RzKlxyXG5cclxuICAgIGlmKCBzaWduYXR1cmVWZXJpZmljYXRpb24gPT09IGZhbHNlICl7XHJcblxyXG4gICAgICBjb25zb2xlLmxvZyhcIlRoZSBzaWduYXR1cmUgb2YgdGhlIHNpZ25lZCBzcGEgb2JqZWN0IGRpZCBub3QgcGFzcy5cIik7XHJcblxyXG4gICAgICByZXMud3JpdGVIZWFkKDQwMCwge1xyXG4gICAgICAgIFwiQ29udGVudC1UeXBlXCIgOiBcImFwcGxpY2F0aW9uL2pzb25cIixcclxuICAgICAgICBcIngtY2l0aXplblwiIDogPHN0cmluZz5jaXRpemVuXHJcbiAgICAgIH0pO1xyXG5cclxuICAgICAgY29uc3QgYm9keSA9IEpTT04uc3RyaW5naWZ5KHtcclxuICAgICAgICBcImVycm9yRmxhZ1wiIDogdHJ1ZSxcclxuICAgICAgICBcIm1zZ1wiOiBcIlRoZSBlbmNyeXB0ZWQgU1BBIGRhdGEgZGlkIG5vdCBwYXNzIHZlcmlmaWNhdGlvbi5cIixcclxuICAgICAgICBcImRhdGFcIjogbnVsbCxcclxuICAgICAgfSlcclxuXHJcbiAgICAgIHJlcy5lbmQoSlNPTi5zdHJpbmdpZnkoYm9keSkpO1xyXG5cclxuICAgIH0gZWxzZSB7IC8vIHNwYTJtIGVuY3J5cHRlZCBkYXRhIGlzIGxlZ2l0aW1hdGVseSBmcm9tIHRoZSBhc3NvY2lhdGVkIGNpdGl6ZW4uXHJcbiAgICAgIGNvbnN0IHVuZW5jcnlwdGVkRGF0YU9ial9zcGEybV9zdHIgPSBhd2FpdCBzeW1tZXRyaWNEZWNyeXB0KGNpdGl6ZW5JZCwgZW5jcnlwdGVkRGF0YV9iNjQpO1xyXG4gICAgICBjb25zdCB1bmVuY3J5cHRlZERhdGFPYmpfc3BhMm0gPSBKU09OLnBhcnNlKHVuZW5jcnlwdGVkRGF0YU9ial9zcGEybV9zdHIpO1xyXG4gICAgICAvL2NvbnNvbGUubG9nKFwiSUVuY3J5cHRlZERhdGFfc3BhMm06IFwiLCB1bmVuY3J5cHRlZERhdGFPYmpfc3BhMm0pO1xyXG4gICAgICBpZiAoIHVuZW5jcnlwdGVkRGF0YU9ial9zcGEybS5lcnJvckZsYWcgPT09IHRydWUgKSB7XHJcbiAgICAgICAgY29uc29sZS5sb2coXCJTUEEgaXMgcmVwb3J0aW5nIGFuIGVycm9yLlwiKTtcclxuXHJcbiAgICAgICAgcmVzLndyaXRlSGVhZCg0MDAsIHtcclxuICAgICAgICAgIFwiQ29udGVudC1UeXBlXCIgOiBcImFwcGxpY2F0aW9uL2pzb25cIixcclxuICAgICAgICAgIFwieC1jaXRpemVuXCIgOiA8c3RyaW5nPmNpdGl6ZW5cclxuICAgICAgICB9KTtcclxuICBcclxuICAgICAgICBjb25zdCBib2R5ID0gSlNPTi5zdHJpbmdpZnkoe1xyXG4gICAgICAgICAgXCJlcnJvckZsYWdcIiA6IHRydWUsXHJcbiAgICAgICAgICBcIm1zZ1wiOiBcIlNQQSBoYXMgcmVwb3J0ZWQgZXJyb3IuXCIsXHJcbiAgICAgICAgICBcImRhdGFcIjogbnVsbCxcclxuICAgICAgICB9KVxyXG4gIFxyXG4gICAgICAgIHJlcy5lbmQoSlNPTi5zdHJpbmdpZnkoYm9keSkpO1xyXG5cclxuICAgICAgfSBlbHNlIGlmICggdW5lbmNyeXB0ZWREYXRhT2JqX3NwYTJtLmluaXQgPT09IHRydWUgKSB7XHJcbiAgICAgICAgXHJcbiAgICAgICAgY29uc3Qgc2VydmljZVByb3ZpZGVyUmVzcDogSVN0ZFJlczxudWxsPiA9IHsgLy9UT0RPOiBTaG91bGQgYmUgYSBJTW9kdWxlUmVzcG9uc2VcclxuICAgICAgICAgIFwiZXJyb3JGbGFnXCI6IGZhbHNlLFxyXG4gICAgICAgICAgXCJtc2dcIjogXCJFQ0RIIGluaXRpYXRpb24gcmVzcG9uc2VcIixcclxuICAgICAgICAgIFwiZGF0YVwiOiBudWxsLFxyXG4gICAgICAgIH07XHJcblxyXG4gICAgICAgIGNvbnN0IHNlcnZpY2VQcm92aWRlclJlc3Bfc3RyID0gSlNPTi5zdHJpbmdpZnkoc2VydmljZVByb3ZpZGVyUmVzcCk7XHJcbiAgICAgICAgY29uc3QgZW5jcnlwdGVkRGF0YV9iNjQgPSBhd2FpdCBzeW1tZXRyaWNFbmNyeXB0KGNpdGl6ZW5JZCwgc2VydmljZVByb3ZpZGVyUmVzcF9zdHIpO1xyXG4gICAgICAgIGNvbnN0IGVuY3J5cHRlZERhdGFTaWduYXR1cmVfYjY0ID0gYXdhaXQgc2lnblN0cmluZyhjaXRpemVuSWQsIGVuY3J5cHRlZERhdGFfYjY0KTsgLy8gU2lkZUVmZmVjdHMqXHJcblxyXG4gICAgICAgIGNvbnN0IHNlYWxlZEVudmVsb3BlOiBJU2VhbGVkRW52ZWxvcGUgPSB7XHJcbiAgICAgICAgICBlcnJvckZsYWc6IGZhbHNlLFxyXG4gICAgICAgICAgbXNnOiBcIlNlYWxlZCBFbnZlbG9wZSBpbiByZXNwb25zZSB0byBFQ0RIIGluaXRpYWxpemF0aW9uIHJlcXVlc3QuXCIsXHJcbiAgICAgICAgICBlbmNyeXB0ZWREYXRhX2I2NCxcclxuICAgICAgICAgIGVuY3J5cHRlZERhdGFTaWduYXR1cmVfYjY0LFxyXG4gICAgICAgICB9XHJcblxyXG4gICAgICAgICAgcmVzLndyaXRlSGVhZCgyMDAsIHtcclxuICAgICAgICAgICAgXCJjb250ZW50LXR5cGVcIjogXCJhcHBsaWNhdGlvbi9qc29uXCJcclxuICAgICAgICAgIH0pO1xyXG5cclxuICAgICAgICAgIHJlcy5lbmQoSlNPTi5zdHJpbmdpZnkoc2VhbGVkRW52ZWxvcGUpKTtcclxuXHJcbiAgICAgIH0gZWxzZSBpZiAodW5lbmNyeXB0ZWREYXRhT2JqX3NwYTJtLmluaXQgPT09IGZhbHNlKSB7IC8vIGkuZS4gQSBzdGFuZGFyZCByZXF1ZXN0LlxyXG4gICAgICAgIC8vIEhlcmUsIHRoZSBTUEEncyBkZXRhaWxzIGNhbiBiZSBhZGRlZCB0byB0aGUgc3RhbmRhcmQgTm9kZSByZXF1ZXN0IG9iamVjdCBmb3IgYWNjZXNzIGJ5IHRoZSBzZXJ2aWNlIHByb3ZpZGVyXHJcbiAgICAgICAgcmVxW1wiY2l0aXplblwiXSA9IGNpdGl6ZW47XHJcbiAgICAgICAgcmVxW1wiY2l0aXplbklkXCJdID0gY2l0aXplbklkXHJcbiAgICAgICAgcmVxW1wiTDhcIl0gPSB1bmVuY3J5cHRlZERhdGFPYmpfc3BhMm07XHJcbiAgICAgICAgcmVxW1wiY2l0aXplbkNoZWNrXCJdID0gdHJ1ZTtcclxuICAgICAgICByZXEudXJsID0gYC8ke3VuZW5jcnlwdGVkRGF0YU9ial9zcGEybS5wYXRofWA7XHJcbiAgICAgICAgcmVxLm1ldGhvZCA9IHVuZW5jcnlwdGVkRGF0YU9ial9zcGEybS5tZXRob2Q7XHJcbiAgICAgICAgY29uc29sZS5sb2coXCJyZXEudXJsOiBcIiwgcmVxLnVybClcclxuICAgICAgICBuZXh0KCk7XHJcbiAgICAgICAgcmV0dXJuO1xyXG4gICAgICB9XHJcbiAgICB9XHJcbiAgfSBjYXRjaChlcnIpe1xyXG4gICAgY29uc29sZS5sb2coXCJFcnJvciBpbiB0aGUgTW9kdWxlJ3MgJ3Byb3hpZWQnIHJvdXRlLlwiKTtcclxuICB9XHJcbn1cclxuXHJcbiAgLy8gRUNIRCBFbmRwb2ludFxyXG5hc3luYyBmdW5jdGlvbiBFQ0RISW5pdChyZXE6IEw4UmVxdWVzdCwgcmVzOiBSZXNwb25zZSwgbmV4dDogTmV4dEZ1bmN0aW9uKTogUHJvbWlzZTx2b2lkPiB7XHJcbiAgLy9UaW1lIHRvIGdhdGhlciBuZWNlc3NhcnkgaW5mbyBmb3IgRUNESFxyXG4gIHRyeXtcclxuICAgIGNvbnN0IGNpdGl6ZW4gPSByZXEuaGVhZGVyKFwieC1jaXRpemVuXCIpO1xyXG4gICAgY29uc3QgcHViREhKV0tfc3BhMm1fc3RyID0gcmVxLmhlYWRlcihcIngtcHViZGhqd2stc3BhMm1cIilcclxuICAgIGNvbnN0IHB1YlNKV0tfc3BhMm1fc3RyID0gcmVxLmhlYWRlcihcIngtcHVic2p3ay1zcGEybVwiKVxyXG4gICAgaWYoIWNpdGl6ZW4pIHRocm93IG5ldyBFcnJvcihcIngtY2l0aXplbiBoZWFkZXIgbm90IGRlZmluZWQuXCIpO1xyXG4gICAgaWYoIXB1YkRISldLX3NwYTJtX3N0cikgdGhyb3cgbmV3IEVycm9yKFwieC1wdWJkaGp3ay1zcGEybSBoZWFkZXIgbm90IGRlZmluZWQuXCIpO1xyXG4gICAgaWYoIXB1YlNKV0tfc3BhMm1fc3RyKSB0aHJvdyBuZXcgRXJyb3IoXCJ4LXB1YnNqd2stc3BhMm0gaGVhZGVyIG5vdCBkZWZpbmVkLlwiKTtcclxuICAgIGNvbnN0IGNpdGl6ZW5JZCA9IGF3YWl0IGNyZWF0ZVVzZXJJZChjaXRpemVuKTsgLy8gVE9ETzogV2hhdCBpZiBjaXRpemVuIGFscmVhZHkgZXhpc3RzP1xyXG4gICAgY29uc3QgcHViU0pXS19zcGEybSA9IEpTT04ucGFyc2UocHViU0pXS19zcGEybV9zdHIpO1xyXG4gICAgY29uc3QgcHViREhKV0tfc3BhMm0gPSBKU09OLnBhcnNlKHB1YkRISldLX3NwYTJtX3N0cik7XHJcbiAgICBzdG9yZUNyeXB0b0Fzc2V0KGNpdGl6ZW5JZCwgXCJwdWJTSldLX3NwYTJtXCIsIHB1YlNKV0tfc3BhMm0pO1xyXG4gICAgc3RvcmVDcnlwdG9Bc3NldChjaXRpemVuSWQsIFwicHViREhKV0tfc3BhMm1cIiwgcHViREhKV0tfc3BhMm0pO1xyXG5cclxuICAgIGNvbnN0IHB1YlNKV0tfbTJzcGEgPSBhd2FpdCBnZXRQdWJTSldLKGNpdGl6ZW5JZCk7IC8vIFNpZGUgRWZmZWN0cypcclxuICAgIGNvbnN0IHB1YkRISldLX20yc3BhID0gYXdhaXQgZ2V0UHViREhKV0soY2l0aXplbklkKTsgLy8gU2lkZSBFZmZlY3RzKlxyXG4gICAgY29uc3Qgc2hhcmVkU2FsdF9iNjQgPSBhd2FpdCBnZXRTaGFyZWRTYWx0KGNpdGl6ZW5JZCk7IC8vIFNpZGUgRWZmZWN0cypcclxuICAgIGF3YWl0IGRvdWJsZURlcml2ZWRTaGFyZWRTZWNyZXQoY2l0aXplbklkKTsgLy8gU2lkZSBFZmZlY3RzKlxyXG5cclxuICAgIGNvbnN0IG1lc3NhZ2VPYmo6IElTdGRSZXM8bnVsbD4gPSB7IC8vVE9ETzogT2YgbXNnIHR5cGU/XHJcbiAgICAgIFwibXNnXCI6IFwibW9kdWxlIDIgc3BhIGNoZWNrXCIsXHJcbiAgICAgIFwiZXJyb3JGbGFnXCI6IGZhbHNlLFxyXG4gICAgICBcImRhdGFcIiA6IG51bGxcclxuICAgIH1cclxuXHJcbiAgICBjb25zdCBtZXNzYWdlU3RyID0gSlNPTi5zdHJpbmdpZnkobWVzc2FnZU9iaik7XHJcblxyXG4gICAgY29uc3QgZW5jcnlwdGVkTXNnX2I2NCA9IGF3YWl0IHN5bW1ldHJpY0VuY3J5cHQoY2l0aXplbklkLCBtZXNzYWdlU3RyKTtcclxuXHJcbiAgICByZXMud3JpdGVIZWFkKDIwMCwge1xyXG4gICAgICBcIkNvbnRlbnQtVHlwZVwiIDogXCJhcHBsaWNhdGlvbi9qc29uXCIsXHJcbiAgICAgIFwieC1jaXRpemVuXCIgOiA8c3RyaW5nPmNpdGl6ZW4sXHJcbiAgICAgIFwieC1wdWJzandrLW0yc3BhXCIgOiA8c3RyaW5nPkpTT04uc3RyaW5naWZ5KHB1YlNKV0tfbTJzcGEpLFxyXG4gICAgICBcIngtcHViZGhqd2stbTJzcGFcIiA6IDxzdHJpbmc+SlNPTi5zdHJpbmdpZnkocHViREhKV0tfbTJzcGEpLFxyXG4gICAgICBcIngtc2hhcmVkc2FsdC1iNjRcIiA6IDxzdHJpbmc+c2hhcmVkU2FsdF9iNjRcclxuICAgIH0pO1xyXG5cclxuICAgIC8vIFRPRE86IE5vdGUgdGhhdCB0aGlzIGlzIE5PVCBhIHRydWUgSVNlYWxlZEVudmVsb3BlLiBUaGUgcmVhc29uIGlzIHRoYXQgYW4gYXR0YWNrZXIgd2hvIHN1cHBsaWVzIEJPVEggdGhlaXIgcHViU0pXSyBhbmQgdGhlaXIgc2lnbmF0dXJlIGNvdWxkIGJlIGFueW9uZS4gVGhlIExheWVyOCByZXZlcnNlIHByb3h5IHNob3VsZCBoYXZlIHRoZSBzdG9yZSBvZiBwdWJsaWMgc2lnbmluZyBrZXlzIGFuZCBzZXJ2ZSB0aGVtIHRvIHRoZSBTUEEuXHJcblxyXG4gICAgY29uc3QgYm9keSAvKklTZWFsZWRFbnZlbG9wZSovID0gSlNPTi5zdHJpbmdpZnkoe1xyXG4gICAgICBcImVycm9yRmxhZ1wiIDogZmFsc2UsXHJcbiAgICAgIFwibXNnXCI6IFwiU2VlIGVuY3J5cHRlZE1zZ19iNjQgZm9yIHRoZSBlbmNyeXB0ZWRcIixcclxuICAgICAgXCJlbmNyeXB0ZWREYXRhX2I2NFwiOiBlbmNyeXB0ZWRNc2dfYjY0LFxyXG4gICAgICBcImVuY3J5cHRlZERhdGFTaWduYXR1cmVfYjY0XCI6IG51bGxcclxuICAgIH0pXHJcblxyXG4gICAgcmVzLmVuZChib2R5KTtcclxuICAgIHJldHVybjtcclxuICB9IGNhdGNoKGVycikge1xyXG4gICAgY29uc29sZS5sb2coXCJbQ2F0Y2ggYmxvY2sgb2YgdGhlIE1vZHVsZSdzIEVDREggSW5pdCByb3V0ZS5dXCIsIGVycik7XHJcbiAgICByZXR1cm47XHJcbiAgfVxyXG59XHJcblxyXG5leHBvcnQgZGVmYXVsdCBMYXllcjg7XHJcblxyXG5hc3luYyBmdW5jdGlvbiByZXR1cm5FbmNyeXB0ZWREYXRhKHJlcTogTDhSZXF1ZXN0LCByZXM6IFJlc3BvbnNlLCBkYXRhOiBhbnkpe1xyXG4gIGNvbnNvbGUubG9nKFwiRnVuY3Rpb24gJ3JldHVybkVuY3J5cHRlZERhdGEnIGhhcyBiZWVuIGNhbGxlZCBvbjpcIiwgZGF0YS50aXRsZSk7XHJcblxyXG4gIGNvbnN0IGNpdGl6ZW5JZCA9IGF3YWl0IGNyZWF0ZVVzZXJJZChyZXFbJ2NpdGl6ZW4nXSk7IC8vIFRPRE86IHNob3VsZCBiZSAnY3JlYXRlQ2l0aXplbklkKCknXHJcbiAgY29uc3QgZW5jcnlwdGVkUmV0dXJuTXNnX2I2NCA9IGF3YWl0IHN5bW1ldHJpY0VuY3J5cHQoY2l0aXplbklkLCBKU09OLnN0cmluZ2lmeShkYXRhKSk7XHJcbiAgY29uc3Qgc2lnbmF0dXJlX2I2NF9tMnNwYSA9IGF3YWl0IHNpZ25TdHJpbmcoY2l0aXplbklkLCBlbmNyeXB0ZWRSZXR1cm5Nc2dfYjY0KTtcclxuICBcclxuICBjb25zdCBtc2dBbmRTaWduYXR1cmVfbTJzcGE6IElTZWFsZWRFbnZlbG9wZSA9IHtcclxuICAgIGVycm9yRmxhZzogZmFsc2UsXHJcbiAgICBtc2c6IFwidGhpcyBpcyBpdCBidWQuXCIsXHJcbiAgICBlbmNyeXB0ZWREYXRhX2I2NDogZW5jcnlwdGVkUmV0dXJuTXNnX2I2NCxcclxuICAgIGVuY3J5cHRlZERhdGFTaWduYXR1cmVfYjY0OiBzaWduYXR1cmVfYjY0X20yc3BhXHJcbiAgfTtcclxuXHJcbiAgcmVzLndyaXRlSGVhZCgyMDAsIHtcclxuICAgIFwiY29udGVudC10eXBlXCI6IFwiYXBwbGljYXRpb24vanNvblwiLFxyXG4gICAgXCJ4LWNpdGl6ZW5cIiA6IHJlcVsnY2l0aXplbiddLFxyXG4gIH0pO1xyXG5cclxuICByZXMuZW5kKEpTT04uc3RyaW5naWZ5KG1zZ0FuZFNpZ25hdHVyZV9tMnNwYSkpO1xyXG59XHJcblxyXG5cclxuZXhwb3J0IGNvbnN0IEw4ID0ge1xyXG4gIHJldHVybkVuY3J5cHRlZERhdGFcclxufSJdfQ==