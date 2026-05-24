import { Central } from '@lionrockjs/central';
import { argon2id } from '@noble/hashes/argon2.js';
const ARGON2_OPTIONS = {
    memorySize: 19456,
    iterations: 2,
    parallelism: 1,
    hashLength: 32,
};
const MAX_SUPPORTED_MEMORY_SIZE = 262144;
const ARGON2_VERSION = 19;
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
function bytesToBase64(bytes) {
    const buffer = globalThis.Buffer;
    if (buffer)
        return buffer.from(bytes).toString('base64').replace(/=+$/g, '');
    let binary = '';
    const chunkSize = 8192;
    for (let i = 0; i < bytes.length; i += chunkSize) {
        binary += String.fromCharCode(...bytes.subarray(i, i + chunkSize));
    }
    if (typeof btoa !== 'function')
        throw new Error('Base64 encoding is unavailable');
    return btoa(binary).replace(/=+$/g, '');
}
function base64ToBytes(value) {
    const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
    const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, '=');
    const buffer = globalThis.Buffer;
    if (buffer)
        return new Uint8Array(buffer.from(padded, 'base64'));
    if (typeof atob !== 'function')
        throw new Error('Base64 decoding is unavailable');
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
}
function assertSupportedParameter(name, value) {
    if (!Number.isInteger(value) || value < 1) {
        throw new Error(`Invalid Argon2id ${name} parameter`);
    }
}
function parseHash(hash) {
    const parts = hash.split('$');
    if (parts.length !== 6 || parts[0] !== '' || parts[1] !== 'argon2id') {
        throw new Error('Invalid Argon2id hash format');
    }
    const version = Number(parts[2].replace(/^v=/, ''));
    if (version !== ARGON2_VERSION)
        throw new Error('Unsupported Argon2id hash version');
    const params = Object.fromEntries(parts[3].split(',').map((entry) => entry.split('=')));
    const memorySize = Number(params.m);
    const iterations = Number(params.t);
    const parallelism = Number(params.p);
    assertSupportedParameter('memory', memorySize);
    assertSupportedParameter('iterations', iterations);
    assertSupportedParameter('parallelism', parallelism);
    if (memorySize > MAX_SUPPORTED_MEMORY_SIZE)
        throw new Error('Argon2id memory parameter is too high');
    return {
        memorySize,
        iterations,
        parallelism,
        salt: base64ToBytes(parts[4]),
        digest: base64ToBytes(parts[5]),
    };
}
function encodeHash(params = ARGON2_OPTIONS, salt, digest) {
    return `$argon2id$v=${ARGON2_VERSION}$m=${params.memorySize},t=${params.iterations},p=${params.parallelism}$${bytesToBase64(salt)}$${bytesToBase64(digest)}`;
}
function constantTimeEqual(a, b) {
    if (a.length !== b.length)
        return false;
    let diff = 0;
    for (let i = 0; i < a.length; i += 1) {
        diff |= a[i] ^ b[i];
    }
    return diff === 0;
}
function derivePassword(text, salt, params = ARGON2_OPTIONS) {
    return argon2id(text, salt, {
        t: params.iterations,
        m: params.memorySize,
        p: params.parallelism,
        dkLen: params.hashLength,
        maxmem: Math.max(params.memorySize * 1024 + 1024 * 1024, 32 * 1024 * 1024),
    });
}
export async function hashPassword(userId, identifierName, plainTextPassword, state) {
    const salt = randomSalt();
    const digest = derivePassword(passwordText(userId, identifierName, plainTextPassword, state), salt);
    return encodeHash(ARGON2_OPTIONS, salt, digest);
}
export async function verifyPassword(hash, userId, identifierName, plainTextPassword, state) {
    try {
        const parsed = parseHash(hash);
        const digest = derivePassword(passwordText(userId, identifierName, plainTextPassword, state), parsed.salt, {
            memorySize: parsed.memorySize,
            iterations: parsed.iterations,
            parallelism: parsed.parallelism,
            hashLength: parsed.digest.length,
        });
        return constantTimeEqual(parsed.digest, digest);
    }
    catch {
        return false;
    }
}
