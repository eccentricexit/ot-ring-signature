import BN from 'bn.js';
import {eddsa as EdDSA} from 'elliptic';
import crypto from 'crypto';
import keccakHash from 'keccak';
import * as cri from 'crypto-random-int';
const cryptoRandomInt = cri;
const ec = new EdDSA('ed25519');


const pKeys = ec.keyFromSecret(random256Number());

//I = p*Hp(P);
let I = H(pKeys.pub().encode('hex'));
I = ec.keyFromPublic(I,'hex').pub();
I = I.mul(pKeys.priv());







function H(input){
  return keccakHash('keccak256').update(input).digest('hex');
}

function random256Number(){
  return crypto.randomBytes(15).toString('hex');
}
