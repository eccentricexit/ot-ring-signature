import BN from 'bn.js';

export default class Signature{
  constructor(key_image,c_array,r_array,public_keys,hasher){
    this.key_image = key_image;
    this.c_array = c_array;
    this.r_array = r_array;
    this.hasher = hasher;
    this.public_keys = public_keys;
  }

  //perhaps the problem is on BN instantiation. Try using .toString on val or 16 as second arg
  verify(message,public_keys){
    let ll_array_ = [];
    let rr_array_ = [];

    ll_array_ = this.generate_ll_(public_keys,this.c_array,this.r_array,this.hasher);
    rr_array_ = this.generate_rr_(public_keys,this.c_array,this.r_array,this.hasher,this.key_image);

    const c_sum = this.c_summation(this.c_array,this.hasher).mod(this.hasher.l).toString('hex');

    const message_digest = this.hasher.hash_string(message);
    let challenge_arr = [message_digest];
    challenge_arr = challenge_arr.concat(ll_array_);
    challenge_arr = challenge_arr.concat(rr_array_);
    let challenge = this.hasher.hash_array(challenge_arr);
    challenge = new BN(challenge,16).mod(this.hasher.l).toString('hex');

    console.log(challenge);
    console.log(c_sum);

    return challenge === c_sum;
  }

  //correct (acording to ruby impl.)
  c_summation(c_array,hasher){
    let summation = new BN(0,16);

    for(let i=0;i<c_array.length;i++){
      summation = summation.add(c_array[i]);
    }

    return summation; // whitepaper doesn't take modulo
  }

  //correct
  generate_ll_(public_keys,c_array,r_array,hasher){
    let ll_array_ = [];
    for(let i=0;i<public_keys.length;i++){
      let rG = hasher.G.mul(new BN(r_array[i],16));
      let cP = public_keys[i].point.mul(new BN(c_array[i],16));
      ll_array_.push(rG.add(cP)); //L' = rG + cP
    }
    return ll_array_;
  }

  //correct
  generate_rr_(public_keys,c_array,r_array,hasher,key_image){
    let rr_array_ = [];

    for(let i=0;i<public_keys.length;i++){
      let cI = key_image.mul(new BN(c_array[i],16));
      let HpP = hasher.hash_point(public_keys[i].point);
      let rHp = HpP.mul(new BN(r_array[i],16));
      rr_array_.push(cI.add(rHp));
    }

    return rr_array_;
  }

}
