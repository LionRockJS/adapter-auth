import { ORM } from '@lionrockjs/central';
import { Identifier } from '@lionrockjs/mod-auth';
import DefaultModelIdentifierPassword from '../model/IdentifierPassword.mjs';
const ModelIdentifierPassword = await ORM.import('IdentifierPassword', DefaultModelIdentifierPassword);
import { hashPassword, verifyPassword } from '../helper/PasswordHash.mjs';
export default class IdentifierPassword extends Identifier {
    static Model = ModelIdentifierPassword;
    static isPostDataContainsIdentifierField(postData) {
        return !!postData.password;
    }
    static async getName(postData) {
        return postData.username;
    }
    static async registerFilter(identifier, postData, state) {
        IdentifierPassword.matchRetypePassword(postData.password, postData['retype-password']);
        const hash = await IdentifierPassword.hash(identifier.user_id, identifier.name, postData.password, state);
        return {
            hash,
        };
    }
    static async loginFilter(identifier, postData, state) {
        const plainTextPassword = postData.password;
        if (await verifyPassword(identifier.hash, identifier.user_id, identifier.name, plainTextPassword, state) === false)
            throw new Error('Password Mismatch');
        return {};
    }
    static matchRetypePassword(password, retypePassword) {
        if (retypePassword === undefined)
            return;
        if (retypePassword !== password) {
            throw new Error('Retype password mismatch');
        }
    }
    static async hash(userId, identifierName, plainTextPassword, state) {
        return hashPassword(userId, identifierName, plainTextPassword, state);
    }
}
