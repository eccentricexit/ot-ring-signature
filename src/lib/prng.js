import {XorShift128Plus} from 'xorshift.js';
import crypto from 'crypto';

export default class Prng{
  constructor(){
    this.seed = crypto.randomBytes(16).toString('hex');
    this.prng = new XorShift128Plus(this.seed);
  }

  get random(){
    return this.prng.randomBytes(32).toString('hex');
  }
}
