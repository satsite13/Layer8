import http from "http";

export function ECDHInit(req_c, res_L8){
  console.log("FullJWT authenticated. Next: ECDH.");

  try{
    const citizen = req_c.headers["x-citizen"];
    const x_pubdhjwk_spa2m = req_c.headers["x-pubdhjwk-spa2m"];
    const x_pubsjwk_spa2m = req_c.headers["x-pubsjwk-spa2m"];

    const options = {
      port: 8080, // Module
      connection: 'keep-alive',
      host: "127.0.0.1",
      method: "GET",
      path: "/ecdh_init", // "path" here -> 'request.url' on server
      headers: {
        "content-type": "application/json",
        "x-citizen": citizen,
        "x-pubdhjwk-spa2m": x_pubdhjwk_spa2m,
        "x-pubsjwk-spa2m": x_pubsjwk_spa2m
      }
    }

    const proxyRequest = http.request(options, returnTrip);

    proxyRequest.end();
  } catch(err){
    console.log("[Error thrown in the ECDHInit contoller]", err);
  }

  //Return Trip
  function returnTrip(res_module){
    console.log("Proxied response through: 'ECDHInit'");

    res_L8.writeHead(200, {
      "content-type": res_module.headers['content-type'],
      "x-pubsjwk-m2spa": res_module.headers['x-pubsjwk-m2spa'],
      "x-pubdhjwk-m2spa": res_module.headers['x-pubdhjwk-m2spa'],
      "x-sharedsalt-b64": res_module.headers['x-sharedsalt-b64'],
    });
    
    res_module.pipe(res_L8);
  }
}

export function proxyController(req_spa, res_sp){
  // TODO: If the module records / sends an error, the proxy needs a standard 4xx response.
  console.log("Hit: proxyController");
  console.log("[proxy: req_c.body]", req_spa.body);

  try{
    const options = {
      port: 8080, // Module
      connection: 'keep-alive',
      host: "127.0.0.1",
      method: "POST", // This may eventually need to change?
      path: "/proxied", // "path" here -> 'request.url' on server
      headers: {
        "content-type": "application/json",
        "x-citizen": req_spa.headers["x-citizen"],
      }
    }

    const proxyRequest = http.request(options, proxiedReturnTrip);

    proxyRequest.end(JSON.stringify(req_spa.body));
  } catch (err) {
    console.log(err);
  }

  function proxiedReturnTrip(res_module){
    // TODO: If the module records / sends an error, the proxy needs a standard 4xx response.
    console.log("proxiedReturnTrip has run.");

    res_sp.writeHead(200, {
      "content-type": res_module.headers['content-type'],
    });

    res_module.pipe(res_sp);
  }
}
