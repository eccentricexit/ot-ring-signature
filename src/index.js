import BN from 'bn.js';
import {eddsa as EdDSA} from 'elliptic';
import crypto from 'crypto';
import keccakHash from 'keccak';
import * as cri from 'crypto-random-int';
import shuffle from 'shuffle-array';
import {XorShift128Plus} from 'xorshift.js';

const cryptoRandomInt = cri;
const ec = new EdDSA('ed25519');
const seed = crypto.randomBytes(16).toString('hex');
const prng = new XorShift128Plus(seed);


//P = x*G
const x = new BN(randomNum(prng),16);
const P = ec.g.mul(x);

//I = x*Hp(P);
let I = Hp(P).mul(x);



let s1 = new BN(randomNum(prng),16);
let S1 = ec.g.mul(s1);

let s2 = new BN(randomNum(prng),16);
let S2 = ec.g.mul(s1);

const s = 0;
const ringKeys = [[x,P],[s1,S1],[s2,S2]];
const n = ringKeys.length;

let q = genQ(n,prng);
let w = genW(n,s,prng);

let L = genL(q,w,s,ringKeys);
let R = genR(q,w,s,ringKeys);

console.log(s);

function genR(q,w,s,ringKeys){
  let R = []
  for(let i=0;i<ringKeys.length;i++){
    let ri = Hp(ringKeys[i][1]).mul(q[i]);
    if(i!==s){
      ri = ri.add(I.mul(w[i]));
    }
    R.push(ri);
  }

  return R;
}

function genL(q,w,s,ringKeys){
  let L = []
  for(let i=0;i<ringKeys.length;i++){
    let li = ec.g.mul(q[i]); //Li = qi*G for i==s;
    if(i!==s){
      let Pi = ringKeys[i][1];
      let W = Pi.mul(w[i]);
      li = li.add(W); //Li = qi*G + wi*Pi
    }
    L.push(li);
  }

  return L;
}

function genW(n,s,prng){
  let w = [];
  for(let i=0;i<n;i++){
    if(i!==s){
      w.push(new BN(randomNum(prng),16));
    }else{
      w.push(new BN(0));
    }
  }
  return q;
}

function genQ(n,prng){
  let q = [];
  for(let i=0;i<n;i++){
    q.push(new BN(randomNum(prng),16));
  }
  return q;
}

function Hp(point){
  return new BN(H(point.encode('hex')).toString(),16).mul(new BN(8));
}

function H(input){
  return keccakHash('keccak256').update(input).digest('hex');
}

function randomNum(prng){
  return prng.randomBytes(32).toString('hex'); //should probably use a bigger space. e.g. 32B
}
