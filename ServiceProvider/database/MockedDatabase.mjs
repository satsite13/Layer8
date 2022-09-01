// USERS

const mockedUserDb = new Map();

/**
 * setCitizenId
 * @param {string} citizen
 * @param {string} userId
 * @returns 
 */
export async function setCitizenId(citizen, citizenId){
  try{
    mockedUserDb.set(citizen, citizenId);
    return true;
  } catch(err){
    console.log(err);
    return false;
  }
}


/**
 * getCitizenId
 * Retrieves the citizen's id  from the mocked user database.
 * @param {string} citizen
 * @returns {Promise<string>} citizenId
 */
export async function getCitizenId(citizen){
  try{
    return mockedUserDb.get(citizen);
  } catch(err){
    console.log(err)
    throw new Error(err);
  }
}


// POEMS
const inMemDb = [
  {
    id: 1,
    title: "Harlem",
    author: "Langston Hughes",
    body: "Does it dry up like a raisin in the sun? Or fester like a sore— And then run? Does it stink like rotten meat? Or crust and sugar over—like a syrupy sweet? Maybe it just sags like a heavy load. Or does it explode?"
  },
  {
    id: 2,
    title: "Still I Rise",
    author: "Maya Angelou",
    body: "You may write me down in history With your bitter, twisted lies, You may trod me in the very dirt But still, like dust, I'll rise. Does my sassiness upset you? Why are you beset with gloom? 'Cause I walk like I've got oil wells Pumping in my living room. Just like moons and like suns, With the certainty of tides, Just like hopes springing high, Still I'll rise."
  },
  {
    id: 3,
    title: "To a Mouse",
    author: "Robert Burns",
    body: "Wee, sleeket, cowran, tim'rous beastie, O, what a panic's in thy breastie! Thou need na start awa sae hasty, Wi' bickerin brattle! I wad be laith to rin an' chase thee Wi' murd'ring pattle!"
  },
]

export function getPoem(id){
  return inMemDb.filter((poem)=>poem.id == id)[0];
};

export function getTitles(){
  const titles = [];
  for (let title of inMemDb ){
    titles.push(title);
  }
  return titles;
}