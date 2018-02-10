import BN from 'bn.js';

export default class Signature{
  constructor(key_image,c_array,r_array,public_keys,hasher){
    this.key_image = key_image;
    this.c_array = c_array;
    this.r_array = r_array;
    this.hasher = hasher;
    this.public_keys = public_keys;
  }

  verify(message,public_keys){
    console.log('signature.verify() not implemented');
    return false;
  }

}
