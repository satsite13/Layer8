import {signupUser, getUserIdentities, checkUserExistence} from "../database/users.mjs"

// SIGNUP CONTROLLERS
export const getSignup = (req, res, next) => {
  // A simple response of rendering the signup page.
  console.log("Route 'getSignup' hit.");
  res.render("signup");
}

/**
 * In response to successful sign up attempt, the proxy returns the assigned identities.
 * @param {/*IStdRes<SignupData>} res 
 * @returns void
*/
export const postSignup = async (req, res, next) => {
  console.log("Client is attempting to sign up.");
  // type ISignupRequest {userId: string, requestedUsername: string, userSalt_b64: string, hashedPassword_b64}
  const wouldBeUser = req.body;
  try{ // To sign up the 'wouldBeUser'.
    const userExists = await checkUserExistence(wouldBeUser.userId);
    if(userExists){ // User already DOES exist so return this error message to the client
      const L8Response = JSON.stringify({
        msg: `User already exists or other database error.`,
        errorFlag: true,
        data: null
      })
      res.writeHead(400, {"content-type": "application/json"});
      res.end(L8Response);
    } else {
      const newUser = await signupUser(wouldBeUser);
      console.log(`\nNew user was registered: `, newUser, "\n");
      const assignedIdentities = await getUserIdentities(wouldBeUser.userId);
      const L8Response = JSON.stringify({
        msg: `User successfully added to the database.`,
        errorFlag: false,
        data: {
          assignedIdentities: assignedIdentities
        }
      })
      res.writeHead(200, {"content-type": "application/json"});
      res.end(L8Response);
    }
  } catch(err) { // Error while reading or writing to the database.
    console.log("Error occured while querying database for userId", err);
    const ServerErrorRes = JSON.stringify({
      msg: "This error's on us. Sincerely --The L8 Team",
      errorFlag: true,
      data: null
    })
    res.writeHead(500, {"content-type": "application/json"});
    res.end(ServerErrorRes);
  }
}
