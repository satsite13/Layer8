console.log("'proxy_signup_client' connected.");

// INIT
const L8 = window.L8;
L8.registerServiceProviderId("123RavisId");

// DOM OBJECTS
const username = document.querySelector("#username");
const password1 = document.querySelector("#password1");
const password2 = document.querySelector("#password2");
const signupBtn = document.querySelector("#signupBtn");
const identityTableBody = document.querySelector("tbody");

// EVENT LISTENERS
signupBtn.addEventListener("click", async (e) =>{
  e.preventDefault();
  // Validate Input
  if( validInput() === false ){ // Validation failed, update the DOM
    console.log("Check input values. Validation failed.");
  } else { // Validation passed, send POST to the API
    console.log("validation passed");
    let signupResponse /*IStdRes<SignupResponse>*/= await L8.trialSignup(username.value, password1.value);
    if( signupResponse.errorFlag === true ){ // Deal with error
      updateDOM_failedSignup();
    } else { // Signup succeeded, update the DOM
      updateDOM_successfulSignup(signupResponse);
    }
  }
});


/**
 * validInput !Side Effects!
 * Checks the username, password, and retyped password to ensure validity.
 * @returns {boolean}
 */
function validInput(){
  let validationState = {
    username: true,
    password1: true,
    password2: true,
    passwordEquivalence: true
  }

  if( username.value == "" ){
    validationState.username = false;
  }

  if( password1.value != password2.value ){
    validationState.passwordEquivalence = false;
  }

  if ( password1.value == "" ) {
    validationState.password1 = false
  }

  if ( password2.value == "" ){
    validationState.password2 = false
  }


  if(!validationState.username){
    username.setAttribute("style", "border: red 1px solid");
  } else {
    username.removeAttribute("style");
  }

  if(!validationState.password1){
    password1.setAttribute("style", "border: red 1px solid");
  } else {
    password1.removeAttribute("style");
  }

  if(!validationState.password2){
    password2.setAttribute("style", "border: red 1px solid");
  } else {
    password2.removeAttribute("style");
  }

  if(!validationState.passwordEquivalence){
    password1.setAttribute("style", "border: red 1px solid");
    password2.setAttribute("style", "border: red 1px solid");
  }

  if(
    !validationState.username ||
    !validationState.password1 ||
    !validationState.password2 ||
    !validationState.passwordEquivalence
  ){
    return false;
  } else {
    return true;
  }
};

/**
 * updateDOM_failedSignup
 * Shows an alert only. Should be expanded in the future.
 * @returns void
 */
function updateDOM_failedSignup(){
  alert("Singup Failed");
};

/**
 * updateDOM_successfulSignup !Side Effects!
 * @param {IStdRes<SignupData>} signupResponse 
 * @returns void
 */
function updateDOM_successfulSignup(signupResponse){
  username.toggleAttribute('disabled');
  password1.toggleAttribute('disabled');
  password2.toggleAttribute('disabled');
  signupBtn.toggleAttribute('disabled');
  signupResponse.data.assignedIdentities.forEach((identity, idx) => {
    let entry = document.createElement('tr');
    entry.innerHTML = `<tr>
          <th>${idx+1}</th>
          <td>${identity}</td>
        </tr>`;
    identityTableBody.appendChild(entry);
  });
  alert(signupResponse.msg);
  return;
}