import { Request, Response, NextFunction } from "express";
export interface IPayload {
    username: string;
    userId: string;
    expiry: number;
    chosenIdentity: string | null;
}
export declare function authenticator(req_c: Request, res_rp: Response, next: NextFunction): Promise<void>;
export default authenticator;
