import BN from 'bn.js';
import {eddsa as EdDSA} from 'elliptic';
import crypto from 'crypto';
import keccakHash from 'keccak';
import * as cri from 'crypto-random-int';
import shuffle from 'shuffle-array';
import {XorShift128Plus} from 'xorshift.js';
import Signature from './signature.js';

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


let ringKeys = [[s1,S1],[s2,S2]];
let signerKeys = [x,P];

let msg = 'one ring to rule the all';
let signature = sign(msg, ringKeys, signerKeys);
console.log(signature.verify(msg,signerKeys));

function sign(msg, ringKeys, signerKeys){
  ringKeys.push(signerKeys);
  const n = ringKeys.length;
  const s = 2;

  let q = genQ(n,prng);
  let w = genW(n,s,prng);

  let L = genL(q,w,s,ringKeys);
  let R = genR(q,w,s,ringKeys,I);

  //getting the non interactive challenge...
  let msgHash = H(msg);
  let challenge = H(msg+L+R);

  //computing the response
  let c = genCC(challenge,w,n,s);
  let r = genRR(challenge,signerKeys,q,c,n,s);

  let signature = new Signature(I,c,r,ringKeys,ec.g,ec.curve.n);
  return signature;
}

function genRR(challenge,signerKeys,q,c,n,s){
  let r = []

  for(let i=0;i<n;i++){
    if(i!==s){
      r.push(q[i]);
    }else{
      //(q_array[i] - c_array[i] * k.value) % hasher.group.order
      let ri = q[i].sub(c[i]);
      ri = ri.mul(signerKeys[0]);
      ri = ri.umod(ec.curve.n);

      r.push(ri);
    }
  }

  return r;
}

function genCC(challenge,w,n,s){
  let c = []

  for(let i=0;i<n;i++){
    if(i!==s){
      c.push(w[i]);
    }else{
      //(challenge - w_array.inject{|a, b| a + b}) % hasher.group.order
      let ci = new BN(challenge.toString(),16);
      let wAcc = w.reduce((acc,val) => {return acc = acc.add(val);},new BN(0,16));
      ci = ci.sub(wAcc);
      ci = ci.umod(ec.curve.n);

      c.push(ci);
    }
  }

  return c;
}

function genR(q,w,s,ringKeys,I){
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
  return w;
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
