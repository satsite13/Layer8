/* MOCKED DATABASE */
import fs from "fs/promises";

// POPULATE ADEJECTIVE AND ANIMAL LISTS;
let adjectives = [];
let animals = [];

(async function(){
  let data = await fs.readFile("./database/animals.txt", {encoding: "utf-8"});
  data.toString().split("\r\n").forEach(word=>{
    let firstWord = word.trim().match(/^([^\s]+)/); // sometimes returns null
    if(firstWord){
      let split = firstWord[0].split("");
      split[0] = split[0].toUpperCase();
      let animal = split.join("");
      animals.push(animal);
    }
  });
})();

(async function(){
  let data = await fs.readFile("./database/adjectives.txt");
  data.toString().split("\r\n").forEach( adjective => {
    if (adjective){
      let split = adjective.split("")
      split[0] = split[0].toUpperCase();
      adjectives.push(split.join(""))
    };
  });
  return adjectives;
})();

// INTERNAL UTILITIES
function getIdentities(numOfIdenitiesRequested){
  let identities = [];
  for(let n = 0; n < numOfIdenitiesRequested; n++){
    let adjective = adjectives[Math.round(Math.random() * adjectives.length)];
    let animal = animals[Math.round(Math.random() * animals.length)];
    identities.push(adjective + " " + animal);
  }
  return identities;
}

// EXPORT FUNCTIONS
export const mocked_db = new Map();

/**
 * Calls the mocked database to see if a user acutally exists.
 * @param {string} userId
 * @returns {Promise<boolean|Error>}
 */

export function checkUserExistence(userId){
  return new Promise((resolve, reject) => {
    try{
      mocked_db.get(userId)? resolve(true): resolve(false);
    } catch(err) {
      console.error(err);
      reject(err);
    }
  });
}

/**
 * Accepts an object that implements the IUser interface.
 * Asigns 5 random identities to the user.
 * @param {object} userObject
 * @returns {Promise<IUser|Error>} Did the add user succeed or fail?
 */

export function signupUser(userObject /*IWouldBeUser*/){
  return new Promise( async ( resolve, reject ) => {
    let identitiesAssigned = getIdentities(5);
    try{
      // In time this will be a real database that may throw an error.
      await mocked_db.set(userObject.userId, {
        userId: userObject.userId,
        hashedPassword_b64: userObject.hashedPassword_b64,
        username: userObject.requestedUsername,
        userSalt_b64: userObject.userSalt_b64,
        identities: identitiesAssigned
      });
      resolve(mocked_db.get(userObject.userId));
    } catch(err) {
      reject(err);
    }
  });
}


export async function getUserIdentities(userId){
  try {
    if(checkUserExistence(userId)){
      const identities = await mocked_db.get(userId).identities
      return identities;
    } else {
      return [];
    }
  } catch(err) {
    throw(err);
  }
}


/**
 * Returns a user object and should be desctructured upon extraction. Has the schema {userId, username, hashedPassword_b64, userSalt_b64, identities}.
 * @param {string} userId
 * @return {object} user: IUser
 */
export async function getUser(userId){
  const requestedUser = mocked_db.get(userId)
  console.log("[mocked_db.get(userId); './users.mjs']", requestedUser);
  return requestedUser;
}

/**
 * Checks the db for the userId of the correct citizen. At this time, all citizen names are to be unique. (Likely important going forward as well so that no one can mimic another?)
 * @param {string} citizenName
 * @return {Promise<string>} userId
 */
export async function getIdByCitizenship(citizenName){
  //Algo can be exemplified as needing improvement.
  if(citizenName === null || citizenName === undefined)throw new Error("Citizen's name was undefined | null.");

  let userId = null;

  mocked_db.forEach(user => {
    if(user.identities.includes(citizenName)){
      userId = user.userId;
    }
  })

  if(userId === null){
    throw new Error(`Citizen: "${citizenName}" was not found`);
  } else {
    return userId;
  }
}

// ADD USER "RAV", "ravster", "dee", "savi" AT EVEY INIT
mocked_db.set('12nDW',{
  userId: '12nDW',
  username: 'rav',
  hashedPassword_b64: "i3Z/Vb1AT8Kxp+6+HJoCCAcooRBT54fyRhP9w0GLVSE=",
  userSalt_b64: 'koYX+jJGj3/JE98C8kDpUg==',
  identities: [
    'Tragic English',
    'Downright Possum',
    'Constant Kingfisher',
    'Inconsequential Prawn',
    'Frozen Stingray'
  ]
});

mocked_db.set('5Ujc/',{
  userId: '5Ujc/',
  username: 'ravster',
  hashedPassword_b64: "dbwxPtmf5vyLT5XWpGmI98ZjC+ZuhtIcVcr+xy3DcSQ=",
  userSalt_b64: 'but8iYvxtAELKL9NpHlS2g==',
  identities: [
    'Wee Hawk',
    'Vivacious Flea',
    'Self-assured Marmoset',
    'Digital Giant',
    'Immediate Sugar'
  ]
});

mocked_db.set('54NAN',{
  userId: '54NAN',
  username: 'dee',
  hashedPassword_b64: "OrzzrAB0MWNwN8CYLCUH4OIBa7qJ/Lni+lD/Bj1FQQ4=",
  userSalt_b64: 'IyPJppjcIJIN233miWu/Tg==',
  identities: [
    'Yellow Ass',
    'Valuable Finch',
    'Jittery Rabbit',
    'Nervous Whitefish',
    'Attentive Donkey'
  ]
});








// TEST CODE
// mocked_db.set("abc", {
//   "username": "Ravster One",
//   "email": "ravster1@proxy.com",
//   "hashedPass": "1234"
// });

// mocked_db.set("xyz", {
//   "username": "Savi McGee",
//   "email": "savi_mcgee@proxy.com",
//   "hashedPass": "1234"
// });

// mocked_db.set("tts", {
//   "username": "Yeah Liked",
//   "email": "tts@proxy.com",
//   "hashedPass": "1234"
// });

// console.log('mocked_db.get("abc"): ', mocked_db.get("abc"));
// console.log('mocked_db.get("xyz"): ', mocked_db.get("xyz"));
// console.log('mocked_db.size: ', mocked_db.size);
// mocked_db.delete("tts");
// console.log('mocked_db.size: ', mocked_db.size);



