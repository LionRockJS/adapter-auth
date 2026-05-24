import { Central } from '@lionrockjs/central';
import { argon2id, argon2Verify } from 'hash-wasm';
const ARGON2_OPTIONS = {
    memorySize: 19456,
    iterations: 2,
    parallelism: 1,
    hashLength: 32,
    outputType: 'encoded',
};
function getAuthSalt(state) {
    const request = state?.get?.('request');
    const requestSalt = request?.env?.AUTH_SALT;
    if (requestSalt !== undefined)
        return `${requestSalt}`;
    const processEnv = Central.runtime?.process?.()?.env;
    if (processEnv?.AUTH_SALT !== undefined)
        return `${processEnv.AUTH_SALT}`;
    return '';
}
function passwordText(userId, identifierName, plainTextPassword, state) {
    return `${userId}${identifierName}${plainTextPassword}${getAuthSalt(state)}`;
}
function randomSalt(length = 16) {
    const salt = new Uint8Array(length);
    const cryptoApi = globalThis.crypto;
    if (!cryptoApi?.getRandomValues) {
        throw new Error('Password hashing requires crypto.getRandomValues');
    }
    cryptoApi.getRandomValues(salt);
    return salt;
}
export async function hashPassword(userId, identifierName, plainTextPassword, state) {
    return argon2id({
        ...ARGON2_OPTIONS,
        password: passwordText(userId, identifierName, plainTextPassword, state),
        salt: randomSalt(),
    });
}
export async function verifyPassword(hash, userId, identifierName, plainTextPassword, state) {
    return argon2Verify({
        hash,
        password: passwordText(userId, identifierName, plainTextPassword, state),
    });
}
