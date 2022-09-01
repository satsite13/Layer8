console.log("'login.mjs' connected");

// INIT
const L8 = window.L8;
L8.registerServiceProviderId("123RavisId"); // TODO: Currently no mechanism proposed or developed to validate a service provider -- if such a thing even necessary?

// DOM OBJECTS
const username = document.querySelector("#username");
const password = document.querySelector("#password");
const loginBtn = document.querySelector("#login");
const identityList = document.querySelector("#identityList");
const welcomeBanner = document.querySelector("#welcomeBanner");
const identitySection = document.querySelector("#identitySection");
const identityTableBody = document.querySelector("tbody");
const logoutBtn = document.querySelector("#logout");

// EVENT LISTENERS & HANDLERS
logoutBtn.addEventListener("click", (e) => {
  e.preventDefault();
  logoutBtnClick();
});

loginBtn.addEventListener("click", async (e) => {
  e.preventDefault();
  const _username = username.value;
  const _password = password.value;
  const validationCheck = validateLoginInput(_username, _password);
  if(validationCheck === false){ // Modify log this to the browser, no login attempt
    console.log("Invalid username or password.");
  } else { // Login input valid, attempt login.
    console.log("[username.value, password.value]: ", _username, _password);
    try{
      const layer8LoginResponse /*IStdRes<AvailableIdentities>*/ = await L8.attemptLogin(_username, _password);
      if(layer8LoginResponse.errorFlag === true){
        // Check error type. i.e., 'No Such User' || 'Wrong Passsword'
        console.log("[Login failure]: ", layer8LoginResponse);
      } else { // Login attempt succeeded
        //Modify the DOM with the available identities;
        console.log("[Login success]: ", layer8LoginResponse);
        displayUserIdentities(_username, layer8LoginResponse.data.availableIdentities);
      }
    } catch (err){
      console.log(err);
    }
  }
})



// FUNCTIONS
function logoutBtnClick(){
  // TODO:
  alert("TODO: Once the mechanism for managing the private keys is developed, this function should be built. Likely, just needs to clear the browser's data to remove any fullJWTs or halfJWTS and any private keys with them.")
}

/**
 * validateLoginInput !Side Effects!
 * Validates the username and password input for the login attempt.
 * @param {string} _username 
 * @param {string} _password 
 * @returns void
 */
function validateLoginInput(_username, _password){
  let flag = true;

  if(_username === ""){
    username.setAttribute("style", "border: red 1px solid");
    flag = false
  }

  if (_password === ""){
    password.setAttribute("style", "border: red 1px solid");
    flag = false;
  }

  if(_username != ""){
    username.removeAttribute("style", "border: red 1px solid");
  }

  if(_password != ""){
    password.removeAttribute("style", "border: red 1px solid")
  };
  return flag;
}

function displayUserIdentities(_username, identityList){
  for(let idx in identityList){
    const entry = document.createElement('tr');
    const identity = identityList[idx];
    entry.innerHTML = `<tr>
      <th>${idx+1}</th>
      <td>${identity}</td>
      <td><button id="id_${idx+1}_btn">Choose</button></td>
    </tr>`;
    identityTableBody.appendChild(entry);
    document
      .querySelector(`#id_${idx+1}_btn`)
      .addEventListener("click", async (e) => {
        e.preventDefault();
        console.log(`You chose ${identity}`, `#id_${idx+1}_btn`);
        
        try{
          const response /*IStdRes<void>*/ = await L8.chooseIdentity(_username, identity);
          if(response.errorFlag === true){
            console.log(response.errorMsg)
          } else {
            console.log(response.msg, " (Standby for redirection...)");
            // FullJWT secured so request the SPA.
            window.location.replace("http://localhost:3000/cryptopoems");
          }
        } catch(err){
          console.log(err);
        };
      }
    );
  }
}