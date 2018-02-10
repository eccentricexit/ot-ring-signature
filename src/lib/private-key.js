import PublicKey from './public-key.js';
import Signature from './signature.js';
import BN from 'bn.js';
import shuffle from 'shuffle-array';

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
    const message_digest = this.hasher.hash_string(message);
    const seed = this.hasher.hash_array([this.value,message_digest]);

    let all_keys = foreign_keys.slice();
    all_keys.push(this);
    shuffle(all_keys);

    let q_array = this.generate_q(all_keys,seed);
    let w_array = this.generate_w(all_keys,seed);

    // ll_array, rr_array = generate_ll_rr(all_keys, q_array, w_array)
    // challenge = hasher.hash_array([message_digest] + ll_array + rr_array)
    // c_array, r_array = generate_c_r(all_keys, q_array, w_array, challenge)
    //
    // public_keys = all_keys.map(&:public_key)
    // signature = Signature.new(key_image, c_array, r_array, hasher)
    //
    // [signature, public_keys]

    let key_image = '';
    let c_array = '';
    let r_array = '';
    let public_keys = [];

    return new Signature(this.key_image,c_array,r_array,public_keys,this.hasher)
  }

  generate_w(all_keys,seed){
    let w_array = [];
    for(let i=0;i<all_keys.lenght;i++){
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
    for(let i=0;i<all_keys.lenght;i++){
      q_array.push(this.hasher.hash_array(['q',seed,i]));
    }
    return q_array;
  }

}
