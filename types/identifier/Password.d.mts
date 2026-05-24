import { Identifier } from '@lionrockjs/mod-auth';
export default class IdentifierPassword extends Identifier {
    static Model: typeof import("@lionrockjs/central").Model;
    static isPostDataContainsIdentifierField(postData: any): boolean;
    static getName(postData: any): Promise<any>;
    static registerFilter(identifier: any, postData: any, state: any): Promise<{
        hash: string;
    }>;
    static loginFilter(identifier: any, postData: any, state: any): Promise<{}>;
    static matchRetypePassword(password: string, retypePassword?: string): void;
    static hash(userId: string, identifierName: string, plainTextPassword: string, state?: Map<string, any>): Promise<string>;
}
