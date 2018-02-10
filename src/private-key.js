import PublicKey from './public-key.js';
import Signature from './signature.js';
import BN from 'bn.js';

export default class PrivateKey{
  constructor(value,hasher){
    this.value = new BN(value.toString(),16);
    this.hasher = hasher;
    this.public_key = new PublicKey(this.hasher.G.mul(this.value),this.hasher);
    this.key_image = this.hasher.hash_point(this.point).mul(this.value); //I = x*Hp(P)
  }

  get point(){
    return this.public_key;
  }  

  sign(message,foreign_keys){
    let key_image = '';
    let c_array = '';
    let r_array = '';
    let public_keys = [];

    return new Signature(key_image,c_array,r_array,public_keys,this.hasher)
  }

}
