import PublicKey from './public-key.js';
import Signature from './signature.js';
import BN from 'bn.js';
import shuffle from 'shuffle-array';

export default class PrivateKey{
  constructor(value,hasher){
    this.value = new BN(value.toString(),16);
    this.hasher = hasher;
    this.public_key = new PublicKey(this.hasher.G.mul(this.value),this.hasher);
    this.key_image = this.hasher.hash_point(this.public_key.point).mul(this.value); //I = x*Hp(P)
  }

  get point(){
    return this.public_key.point;
  }

  sign(message,foreign_keys){
    const message_digest = this.hasher.hash_string(message);
    const seed = this.hasher.hash_array([this.value,message_digest]);

    let all_keys = foreign_keys.slice();
    all_keys.push(this);
    shuffle(all_keys);

    const q_array = this.generate_q(all_keys,seed); // hex numbers
    const w_array = this.generate_w(all_keys,seed); // hex number + 1 BN

    const ll_array = this.generate_ll(all_keys,q_array,w_array); //points
    const rr_array = this.generate_rr(all_keys,q_array,w_array); //points

    let challenge_arr = [message_digest];
    challenge_arr = challenge_arr.concat(ll_array);
    challenge_arr = challenge_arr.concat(rr_array);
    const challenge = this.hasher.hash_array(challenge_arr);

    const c_array = this.generate_c(all_keys,q_array,w_array,challenge);
    const r_array = this.generate_r(all_keys,q_array,w_array,c_array,challenge);

    let public_keys = foreign_keys;
    public_keys.push(this.public_key);    

    return new Signature(this.key_image,c_array,r_array,public_keys,this.hasher);
  }

  generate_r(all_keys,q_array,w_array,c_array,challenge){
    let r_array = [];
    for(let i=0;i<all_keys.length;i++){
      if(all_keys[i] instanceof PublicKey){
        r_array.push(q_array[i]);
      }else{
        let ri = new BN(q_array[i],16).sub(all_keys[i].value.mul(c_array[i]));
        ri = ri.mod(this.hasher.l);
        r_array.push(ri);
      }
    }
    return r_array;
  }

  generate_c(all_keys,q_array,w_array,challenge){
    let c_array = [];
    for(let i=0;i<all_keys.length;i++){
      if(all_keys[i] instanceof PublicKey){
        c_array.push(w_array[i]);
      }else{
        let chNum = new BN(challenge,16);
        let wSum = w_array.reduce((acc,val) => {return acc = acc.add(new BN(val));},new BN(0));
        let ci = chNum.sub(wSum);
        ci = ci.mod(this.hasher.l);
        c_array.push(ci);
      }
    }
    return c_array;
  }

  generate_rr(all_keys,q_array,w_array){
    let rr_array = [];

    for(let i=0;i<all_keys.length;i++){
      let rri = this.hasher.hash_point(all_keys[i].point);
      rr_array.push(rri);
      if(all_keys[i] instanceof PublicKey){
        rr_array[i] = rr_array[i].add(this.key_image.mul(new BN(w_array[i],16)));
      }
    }
    return rr_array;
  }

  generate_ll(all_keys,q_array,w_array){
    let ll_array = [];
    for(let i=0;i<all_keys.length;i++){
      let lli = this.hasher.G.mul(new BN(q_array[i],16));
      ll_array.push(lli);
      if(all_keys[i] instanceof PublicKey){
        ll_array[i] = ll_array[i].add(all_keys[i].point.mul(new BN(w_array[i],16)));
      }
    }
    return ll_array;
  }

  generate_w(all_keys,seed){
    let w_array = [];
    for(let i=0;i<all_keys.length;i++){
      if(all_keys[i] instanceof PublicKey){
        w_array.push(this.hasher.hash_array(['w',seed,i]));
      }else{
        w_array.push(new BN(0));
      }
    }
    return w_array;
  }

  generate_q(all_keys,seed){
    let q_array = [];
    for(let i=0;i<all_keys.length;i++){
      let qi = this.hasher.hash_array(['q',seed,i]);
      q_array.push(qi);
    }
    return q_array;
  }

}
