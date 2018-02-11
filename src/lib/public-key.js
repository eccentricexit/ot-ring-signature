import BN from 'bn.js';

export default class PublicKey{
  constructor(point,hasher){
    this.point = point;
    this.hasher = hasher;
  }  
}
