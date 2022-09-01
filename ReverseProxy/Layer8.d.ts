
// INTERFACES
export interface IPayload {
  username: string,
  userId: string,
  expiry: number,
  chosenIdentity: string | null;
}

export interface IUser {
  username: string,
  hashedPassword_b64: string,
  userSalt_b64: string,
  identities: string[],
}

export interface JWK {}