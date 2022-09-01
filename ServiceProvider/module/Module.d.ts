import { Request, Response, NextFunction } from "express";
interface L8Request extends Request {
    citizen: string;
    citizenId: string;
    citizenCheck: boolean;
    L8: any;
}
declare function Layer8(req: L8Request, res: Response, next: NextFunction): void;
export default Layer8;
declare function returnEncryptedData(req: L8Request, res: Response, data: any): Promise<void>;
export declare const L8: {
    returnEncryptedData: typeof returnEncryptedData;
};
