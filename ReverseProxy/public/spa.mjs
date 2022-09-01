console.log("Connected to the SPA.");

// INIT
const L8 = window.L8;
L8.registerServiceProviderId("123RavisId");
try{
  L8.establishTunnel();
} catch(err) {
  console.log("L8 failed to esatblish an E2E encrypted tunnel.", err);
}

// DOM OBJECTS
const title_DN = document.querySelector("#main-body h1");
const author_DN = document.querySelector("#main-body h4");
const body_DN = document.querySelector("#main-body p");
const citizen = document.querySelector("#citizen");


// INIT THE PAGE

citizen.innerHTML = sessionStorage.getItem("citizen");

const poemSelection = document.querySelectorAll("#poemSelection a");
poemSelection.forEach( (poemLink, poemIdx) => {
  poemLink.addEventListener("click", async (e) => {
    e.preventDefault();
    const poemId = poemIdx + 1;
    const poemObject = await fetchAPoem(poemId);
    console.log("poemObject", poemObject);
    displayPoem(poemObject);
  })
})

// HELPER FUNCTIONS
function displayPoem(poemObject){
  title_DN.textContent = poemObject.title;
  author_DN.textContent = poemObject.author;
  body_DN.textContent = poemObject.body;
};

async function fetchAPoem(poemId){
  console.log("fetchAPoem", poemId);

  // TODO: Is it really appropriate for the SPA to add the 'init' data field?
  const data = {
    init: false,
    errorFlag: false,
    path: `poem${poemId}`,
    msg: "wooooh! so close :)",
    method: "GET",
    query: null,
    options: null,
    data: null
  }

  return await L8.proxy(data);

}



























