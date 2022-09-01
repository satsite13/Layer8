// IMPORTS
import express from "express";
import bodyParser from "body-parser";
import Layer8, {L8} from './module/Module.js';
import {getPoem} from "./database/MockedDatabase.mjs";

// INIT
const PORT = 8080;
const app = express();

// MIDDLEWARE
app.use(bodyParser.json());
app.use(express.static("./public"));
app.set("view engine", "ejs");
app.set("views", "C:\\Users\\Ravi's Prof Corp PC\\Desktop\\learning_computers\\layer_8_v2\\service_provider\\views");

try {
  app.use(Layer8);
}catch(err){
  console.log("Error in Layer8 Module: ", err)
}


// ROUTES
app.route("/").get((req, res, next) => {
  res.render("home", {
    choice: "Null",
    title: "Poem Titles",
    author: "Poem Author",
    body: "Poem Body."
  });
});

app.route("/poem1").get((req, res) => {
  console.log("GET, './poem1'");
  const poem = getPoem(1);
  console.log("Citizen: ", req.citizen, "citizenId: ", req.citizenId);

  if ( req.citizenCheck === false ){
    res.render("home", {
      choice: `poem${poem.id}`,
      title: poem.title,
      author: poem.author,
      body: poem.body
    });
  } else if ( req.citizenCheck === true ){
    const data = {
      choice: `poem${poem.id}`,
      title: poem.title,
      author: poem.author,
      body: poem.body
    };
    L8.returnEncryptedData(req, res, data);
  } else {
    console.log("Top Level Error: app.route('/poem1') failed.");
  }
})

app.route("/poem2").get((req, res) => {
  console.log("GET, './poem2'");
  const poem = getPoem(2);
  console.log("Citizen: ", req.citizen, "citizenId: ", req.citizenId);

  if ( req.citizenCheck === false ){
    res.render("home", {
      choice: `poem${poem.id}`,
      title: poem.title,
      author: poem.author,
      body: poem.body
    });
  } else if ( req.citizenCheck === true ){
    const data = {
      choice: `poem${poem.id}`,
      title: poem.title,
      author: poem.author,
      body: poem.body
    };
    L8.returnEncryptedData(req, res, data);
  } else {
    console.log("Top Level Error: app.route('/poem1') failed.");
  }
})

app.route("/poem3").get((req, res) => {
  console.log("GET, './poem1'");
  const poem = getPoem(3);
  console.log("Citizen: ", req.citizen, "citizenId: ", req.citizenId);

  if ( req.citizenCheck === false ){
    res.render("home", {
      choice: `poem${poem.id}`,
      title: poem.title,
      author: poem.author,
      body: poem.body
    });
  } else if ( req.citizenCheck === true ){
    const data = {
      choice: `poem${poem.id}`,
      title: poem.title,
      author: poem.author,
      body: poem.body
    };
    L8.returnEncryptedData(req, res, data);
  } else {
    console.log("Top Level Error: app.route('/poem1') failed.");
  }
});

app.route("/proxied").post((req, res) => {
  console.log("you have entered the Service Provider's '/proxied' route.");

  console.log("req.headers: ", req.headers);
  console.log("req.body: ", req.body);
  console.log("req.L8: ", req.L8);

  const body = {msg: 'chillin'};

  res.writeHead(200, {
    "content-type": "application/json",
  })
  res.end(JSON.stringify(body));
})

// LAUNCH
app.listen(PORT, ()=>{
  console.log(`Backend launched on port ${PORT}`);
});
