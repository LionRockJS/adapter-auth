import { Central, ORM } from '@lionrockjs/central';
import { Identifier } from '@lionrockjs/mod-auth';
import DefaultModelIdentifierPassword from '../model/IdentifierPassword.mjs';
const ModelIdentifierPassword = await ORM.import('IdentifierPassword', DefaultModelIdentifierPassword);
import argon2 from 'argon2';
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
        const hash = await IdentifierPassword.hash(identifier.user_id, identifier.name, postData.password);
        return {
            hash,
        };
    }
    static async loginFilter(identifier, postData, state) {
        const salt = Central.adapter.process().env.AUTH_SALT;
        const plainTextPassword = postData.password;
        const text = identifier.user_id + identifier.name + plainTextPassword + salt;
        if (await argon2.verify(identifier.hash, text) === false)
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
    static async hash(userId, identifierName, plainTextPassword) {
        const salt = Central.adapter.process().env.AUTH_SALT;
        const digest = await argon2.hash(userId + identifierName + plainTextPassword + salt);
        return `${digest}`;
    }
}
