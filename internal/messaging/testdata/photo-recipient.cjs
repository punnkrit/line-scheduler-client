// Independent recipient using the public Chrome 3.7.2 decryption semantics.
// All input is generated synthetic data. No LINE traffic or copied client source.
const {webcrypto}=require('node:crypto');
const assert=require('node:assert/strict');
(async()=>{
 let input='';for await(const part of process.stdin)input+=part;
 const fixture=JSON.parse(input),crypto=webcrypto.subtle;
 const material=await crypto.importKey('raw',Buffer.from(fixture.key,'base64'),'HKDF',false,['deriveBits']);
 const derived=new Uint8Array(await crypto.deriveBits({name:'HKDF',hash:'SHA-256',salt:new Uint8Array(),info:new TextEncoder().encode('FileEncryption')},material,608));
 const key=await crypto.importKey('raw',derived.slice(0,32),'AES-CTR',false,['decrypt']);
 const mac=await crypto.importKey('raw',derived.slice(32,64),{name:'HMAC',hash:'SHA-256'},false,['verify']);
 const counter=new Uint8Array(16);counter.set(derived.slice(64));
 for(const field of ['full','preview']){
  const blob=Buffer.from(fixture[field],'base64'),body=blob.subarray(0,-32),tag=blob.subarray(-32);
  assert(await crypto.verify('HMAC',mac,tag,body));
  const plain=Buffer.from(await crypto.decrypt({name:'AES-CTR',counter,length:32},key,body));
  assert.deepEqual(plain,Buffer.from(fixture.expected,'base64'));
  const tampered=Buffer.from(body);tampered[0]^=1;
  assert.equal(await crypto.verify('HMAC',mac,tag,tampered),false);
 }
})().catch(()=>{process.stderr.write('recipient authentication/decryption mismatch\n');process.exitCode=1;});
