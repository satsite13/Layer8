/**
 * setCitizenId
 * @param {string} citizen
 * @param {string} userId
 * @returns
 */
export function setCitizenId(citizen: string, citizenId: any): Promise<boolean>;
/**
 * getCitizenId
 * Retrieves the citizen's id  from the mocked user database.
 * @param {string} citizen
 * @returns {Promise<string>} citizenId
 */
export function getCitizenId(citizen: string): Promise<string>;
export function getPoem(id: any): {
    id: number;
    title: string;
    author: string;
    body: string;
};
export function getTitles(): {
    id: number;
    title: string;
    author: string;
    body: string;
}[];
