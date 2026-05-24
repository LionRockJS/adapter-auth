import { argon2id, argon2Verify } from 'hash-wasm';

describe('test argon2', ()=>{
  test('hash', async()=>{
    const text = "hello world";
    const hash = await argon2id({
      password: text,
      salt: crypto.getRandomValues(new Uint8Array(16)),
      parallelism: 1,
      iterations: 2,
      memorySize: 19456,
      hashLength: 32,
      outputType: 'encoded',
    });
    expect(hash).toBeDefined();
    expect(typeof hash).toBe('string');
  })

  test('verify', async()=>{
    const text = "hello world";
    const hash = await argon2id({
      password: text,
      salt: crypto.getRandomValues(new Uint8Array(16)),
      parallelism: 1,
      iterations: 2,
      memorySize: 19456,
      hashLength: 32,
      outputType: 'encoded',
    });

    const result = await argon2Verify({hash, password: text});
    expect(result).toBe(true);
  })
})
