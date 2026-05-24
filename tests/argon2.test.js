import IdentifierPassword from "../dist/identifier/Password.mjs";

describe('test argon2', ()=>{
  test('hash', async()=>{
    const hash = await IdentifierPassword.hash('1', 'alice', 'hello world');
    expect(hash).toBeDefined();
    expect(typeof hash).toBe('string');
    expect(hash.startsWith('$argon2id$v=19$m=19456,t=2,p=1$')).toBe(true);
  })

  test('verify', async()=>{
    const hash = await IdentifierPassword.hash('1', 'alice', 'hello world');
    const identifier = { hash, user_id: '1', name: 'alice' };

    await expect(IdentifierPassword.loginFilter(identifier, {password: 'hello world'})).resolves.toEqual({});
    await expect(IdentifierPassword.loginFilter(identifier, {password: 'goodbye'})).rejects.toThrow('Password Mismatch');
  })
})
