export declare function hashPassword(userId: string, identifierName: string, plainTextPassword: string, state?: Map<string, any>): Promise<string>;
export declare function verifyPassword(hash: string, userId: string, identifierName: string, plainTextPassword: string, state?: Map<string, any>): Promise<boolean>;
