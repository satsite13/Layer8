// IMPORTS
import http from "http";
import express from "express";
import bodyParser from "body-parser";
import { getSignup, postSignup } from "./controllers/signupControllers.js";
import { getLogin, postLogin, loginPrecheck, chooseIdentity } from "./controllers/loginControllers.js";
import { proxyController, ECDHInit } from "./controllers/proxyControllers.mjs";
import { authenticator } from "./authenticator/authenticator.js"
import { initServerKeys } from "./inMemoryKeyStore.mjs";

// INIT & CONFIG
initServerKeys();
const PORT = 3000;
const app = express();
app.set("view engine", "ejs");
app.set("views", "C:\\Users\\Raha Seyed-Mahmoud\\Desktop\\learning-computers\\Layer8\\Layer8\\ReverseProxy\\views");

// MIDLEWARE
app.use(express.static("C:\\Users\\Raha Seyed-Mahmoud\\Desktop\\learning-computers\\Layer8\\Layer8\\ReverseProxy\\public"));
app.use(bodyParser.json());

// ROUTES
// Signup Routes
app.route("/signup").get(getSignup);
app.route("/signup").post(postSignup);

// Login Routes *
app.route("/login").get(getLogin);
app.route("/login").post(postLogin);
app.route("/login/precheck").post(loginPrecheck);
app.route("/login/identity").post(chooseIdentity);

// Proxy Routes (note the use of midleware)
app.route("/ecdhinit").post(authenticator, ECDHInit)
app.route("/proxyme").post(authenticator, proxyController);

// SPA(s)
app.route("/cryptopoems").get((req_c, res_L8RP) => {
  res_L8RP.render("spa", {
    choice: "Null",
    title: "Poem Titles",
    author: "Poem Author",
    body: "Poem Body"
  });
});

// CDN Routes
app.route("/CDN/L8_module_v1").get((req, res) => {
  res.format({
    "application/javascript": () => {
      res.setHeader("Access-Control-Allow-Origin", "*");
      res.type("application/javascript")
      res.status(200).sendFile("L8_module_v1.js", {
        root: "C:\\Users\\Raha Seyed-Mahmoud\\Desktop\\learning-computers\\Layer8\\Layer8\\ReverseProxy\\CDN"
      });
    }
  })
});

app.route("/CDN/L8_module_v1.ts").get((req, res) => {
  res.format({
    "application/javascript": () => {
      res.setHeader("Access-Control-Allow-Origin", "*");
      res.type("application/javascript")
      res.status(200).sendFile("L8_module_v1.ts", {
        root: "C:\\Users\\Raha Seyed-Mahmoud\\Desktop\\learning-computers\\Layer8\\Layer8\\ReverseProxy\\CDN"
      });
    }
  })
});

app.route("/CDN/b64_utils.js").get((req, res) => {
  res.format({
    "application/javascript": () => {
      res.setHeader("Access-Control-Allow-Origin", "*");
      res.type("application/javascript")
      res.status(200).sendFile("b64_utils.js", {
        root: "C:\\Users\\Raha Seyed-Mahmoud\\Desktop\\learning-computers\\Layer8\\Layer8\\ReverseProxy\\CDN"
      });
    }
  })
});

// CATCH ALL / DEFAULT Route
app.route("/*").get((req_c, res_L8RP, next) => { // Content choices NOT encrypted.
  console.log("\n", "Proxied on route '/' (i.e., home/index).");
  const options = {
    port: 8080, // to hit the module
    connection: 'keep-alive',
    host: "127.0.0.1",
    method: req_c.method,
    path: req_c.url, //"path" here -> 'request.url' on server
    headers: {
      "content-type": "application/json",
      "x-citizen": false,
    }
  }
  const proxyRequest = http.request(options, (res_sp) => {
    res_L8RP.writeHead(200, {
      "content-type": res_sp.headers['content-type'],
      "x-citizen": "anonymous",
    })
    res_sp.pipe(res_L8RP);
  });
  proxyRequest.end(); // Needed to init the above http.request
});


// Launch
app.listen(PORT, ()=>{
  console.log("Aplication listening on port 3000");
})