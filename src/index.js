import BN from 'bn.js';
import {eddsa as EdDSA} from 'elliptic';
import crypto from 'crypto';
import keccakHash from 'keccak';
const ec = new EdDSA('ed25519');


const p = new BN(random256Number());
const P = ec.g.mul(p);
console.log(p);

//I = p*Hp(P);
let I = H(P.encode('hex'));
I = ec.keyFromPublic(I,'hex').pub();
I = I.mul(p);




// const n = 2; // number of other users addresses in ring
// const _KeyPairA = ec.keyFromSecret(random256Number());
// const _KeyPairB = ec.keyFromSecret(random256Number());






function H(input){
  return keccakHash('keccak256').update(input).digest('hex');
}

function random256Number(){
  return crypto.randomBytes(32).toString('hex');
}
