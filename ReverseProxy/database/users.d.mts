/**
 * Calls the mocked database to see if a user acutally exists.
 * @param {string} userId
 * @returns {Promise<boolean|Error>}
 */
export function checkUserExistence(userId: string): Promise<boolean | Error>;
/**
 * Accepts an object that implements the IUser interface.
 * Asigns 5 random identities to the user.
 * @param {object} userObject
 * @returns {Promise<IUser|Error>} Did the add user succeed or fail?
 */
export function signupUser(userObject: object): Promise<IUser | Error>;
export function getUserIdentities(userId: any): Promise<any>;
/**
 * Returns a user object and should be desctructured upon extraction. Has the schema {userId, username, hashedPassword_b64, userSalt_b64, identities}.
 * @param {string} userId
 * @return {object} user: IUser
 */
export function getUser(userId: string): object;
/**
 * Checks the db for the userId of the correct citizen. At this time, all citizen names are to be unique. (Likely important going forward as well so that no one can mimic another?)
 * @param {string} citizenName
 * @return {Promise<string>} userId
 */
export function getIdByCitizenship(citizenName: string): Promise<string>;
export const mocked_db: Map<any, any>;
