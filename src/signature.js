import BN from 'bn.js';
import keccakHash from 'keccak';

export default class Signature{
  constructor(keyImage,c,r,ringKeys,G,l){
    this.keyImage = keyImage;
    this.c = c;
    this.r = r;
    this.ringKeys = ringKeys;
    this.G = G;
    this.l = l;
  }

  verify(msg,publicKeys){
    let ll_array = [];
    let rr_array = [];

    for(let i=0;i<publicKeys.length;i++){
      let li = this.G.mul(this.r[i]);
      li = li.add(publicKeys[1].mul(this.c[i]));
      ll_array.push(li);
    }

    let c_sum = this.c.reduce((acc,val) => {return acc = acc.add(val);},new BN(0,16));
    c_sum = c_sum.umod(this.l);

    let msgHash = this.H(msg);

    let challenge = this.H(msgHash + ll_array + rr_array);
    console.log(c_sum);
    console.log(challenge);

    return c_sum === challenge;
  }

  H(input){
    return keccakHash('keccak256').update(input).digest('hex');
  }
}
