import keccakHash from 'keccak';
import BN from 'bn.js';
import {eddsa as EdDSA} from 'elliptic';

export default class Hasher{
  constructor(){
    this.ec = new EdDSA('ed25519');
  }

  get G(){
    return this.ec.g;
  }

  get l(){
    return this.ec.curve.n;
  }

  hash(message){
    let msgHash = keccakHash('keccak256').update(message).digest('hex');
    msgHash = new BN(hash.toString(),16);
    msgHash = hash.mod(this.l());

    return msgHash;
  }

  hash_point(point){
    return this.G().mul(hash_array(point));
  }

  hash_array(array){
    
  }
}
