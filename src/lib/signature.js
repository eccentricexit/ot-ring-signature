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
    let ll_array = [];
    let rr_array = [];

    for(let i=0;i<public_keys.length;i++){
      ll_array.push(this.hasher.G.mul(new BN(this.r_array[i])).add(public_keys[i].point.mul(new BN(this.c_array[i]))));
      rr_array.push(this.hasher.hash_point(public_keys[i].point.mul(new BN(this.r_array[i])).add(this.key_image.mul(new BN(this.c_array[i])))));
    }

    const c_sum = this.c_array.reduce((acc,val) => {return acc = acc.add(new BN(val));},new BN(0)).mod(this.hasher.l).toString('hex');

    const message_digest = this.hasher.hash_string(message);
    let challenge_arr = [message_digest];
    challenge_arr = challenge_arr.concat(ll_array);
    challenge_arr = challenge_arr.concat(rr_array);
    const challenge = this.hasher.hash_array(challenge_arr);

    console.log(challenge);
    console.log(c_sum);

    return challenge === c_sum;
  }

}
