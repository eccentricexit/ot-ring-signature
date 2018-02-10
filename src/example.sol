pragma solidity ^0.4.17;

contract RingSignature {
    //Debug Code
    address owner;
    function RingSignature() public {
        owner = msg.sender;

        G1[0] = 0x1;
        G1[1] = 0x2;
    }

    function Kill() public {
        if (msg.sender != owner) revert();

        selfdestruct(msg.sender);
    }

    //alt_bn128 constants
    uint256[2] public G1;
    uint256 constant public N = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;
    uint256 constant public P = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47;

    //Used for Point Compression/Decompression
    uint256 constant public ECSignMask = 0x8000000000000000000000000000000000000000000000000000000000000000;
    uint256 constant public a = 0xc19139cb84c680a6e14116da060561765e05aa45a1c72a34f082305b61f3f52; // (p+1)/4

    mapping (uint256 => bool) public KeyImageUsed;

    //Base EC Functions
    function ecAdd(uint256[2] p0, uint256[2] p1)
        public constant returns (uint256[2] p2)
    {
        assembly {
            //Get Free Memory Pointer
            let p := mload(0x40)

            //Store Data for ECAdd Call
            mstore(p, mload(p0))
            mstore(add(p, 0x20), mload(add(p0, 0x20)))
            mstore(add(p, 0x40), mload(p1))
            mstore(add(p, 0x60), mload(add(p1, 0x20)))

            //Call ECAdd
            let success := call(sub(gas, 2000), 0x06, 0, p, 0x80, p, 0x40)

            // Use "invalid" to make gas estimation work
 			switch success case 0 { revert(p, 0x80) }

 			//Store Return Data
 			mstore(p2, mload(p))
 			mstore(add(p2, 0x20), mload(add(p,0x20)))
        }
    }

    function ecMul(uint256[2] p0, uint256 s)
        public constant returns (uint256[2] p1)
    {
        assembly {
            //Get Free Memory Pointer
            let p := mload(0x40)

            //Store Data for ECMul Call
            mstore(p, mload(p0))
            mstore(add(p, 0x20), mload(add(p0, 0x20)))
            mstore(add(p, 0x40), s)

            //Call ECAdd
            let success := call(sub(gas, 2000), 0x07, 0, p, 0x60, p, 0x40)

            // Use "invalid" to make gas estimation work
 			switch success case 0 { revert(p, 0x80) }

 			//Store Return Data
 			mstore(p1, mload(p))
 			mstore(add(p1, 0x20), mload(add(p,0x20)))
        }
    }

    function CompressPoint(uint256[2] Pin)
        public pure returns (uint256 Pout)
    {
        //Store x value
        Pout = Pin[0];

        //Determine Sign
        if ((Pin[1] & 0x1) == 0x1) {
            Pout |= ECSignMask;
        }
    }

    function ExpandPoint(uint256 Pin)
        public constant returns (uint256[2] Pout)
    {
        //Get x value (mask out sign bit)
        Pout[0] = Pin & (~ECSignMask);

        //Get y value
        uint256 y_squared = mulmod(Pout[0], Pout[0], P);
        y_squared = mulmod(y_squared, Pout[0], P);
        y_squared = addmod(y_squared, 3, P);

        uint256 p_local = P;
        uint256 a_local = a;
        uint256 y;

        assembly {
            //Get Free Memory Pointer
            let p := mload(0x40)

            //Store Data for Big Int Mod Exp Call
            mstore(p, 0x20)                 //Length of Base
            mstore(add(p, 0x20), 0x20)      //Length of Exponent
            mstore(add(p, 0x40), 0x20)      //Length of Modulus
            mstore(add(p, 0x60), y_squared) //Base
            mstore(add(p, 0x80), a_local)   //Exponent
            mstore(add(p, 0xA0), p_local)   //Modulus

            //Call Big Int Mod Exp
            let success := call(sub(gas, 2000), 0x05, 0, p, 0xC0, p, 0x20)

            // Use "invalid" to make gas estimation work
 			switch success case 0 { revert(p, 0xC0) }

 			//Store Return Data
 			y := mload(p)
        }

        //Use Positive Y
        if ((Pin & ECSignMask) != 0) {
            if ((y & 0x1) == 0x1) {
                Pout[1] = y;
            } else {
                Pout[1] = P - y;
            }
        }
        //Use Negative Y
        else {
            if ((y & 0x1) == 0x1) {
                Pout[1] = P - y;
            } else {
                Pout[1] = y;
            }
        }
    }

    //Ring Signature Functions
    function HashFunction(string message, uint256[2] left, uint256[2] right)
        internal pure returns (uint256 h)
    {
        return (uint256(keccak256(message, left[0], left[1], right[0], right[1])) % N);
    }

    //Return H = keccak256(p)*G1
    function HashPoint(uint256[2] p)
        internal constant returns (uint256[2] h)
    {
        h[0] = uint256(keccak256(p[0], p[1])) % N;
        h = ecMul(G1, h[0]);
    }

    function KeyImage(uint256 xk, uint256[2] Pk)
        internal constant returns (uint256[2] Ix)
    {
        //Ix = xk * HashPoint(Pk)
        Ix = HashPoint(Pk);
        Ix = ecMul(Ix, xk);
    }

    function RingStartingSegment(string message, uint256 alpha, uint256[2] P0)
        internal constant returns (uint256 c0)
    {
        //Memory Registers
        uint256[2] memory left;
        uint256[2] memory right;

        right = HashPoint(P0);
        right = ecMul(right, alpha);
        left = ecMul(G1, alpha);

        c0 = HashFunction(message, left, right);
    }

    function RingSegment(string message, uint256 c0, uint256 s0, uint256[2] P0, uint256[2] Ix)
        internal constant returns (uint256 c1)
    {
        //Memory Registers
        uint256[2] memory temp;
        uint256[2] memory left;
        uint256[2] memory right;

        //Deserialize Point
        (left[0], left[1]) = (P0[0], P0[1]);
        right = HashPoint(left);

        //Calculate left = c*P0 + s0*G1)
        left = ecMul(left, c0);
        temp = ecMul(G1, s0);
        left = ecAdd(left, temp);

        //Calculate right = s0*H(P0) + c*Ix
        right = ecMul(right, s0);
        temp = ecMul(Ix, c0);
        right = ecAdd(right, temp);

        c1 = HashFunction(message, left, right);
    }

    function SubMul(uint256 alpha, uint256 c, uint256 xk)
        internal pure returns (uint256 s)
    {
        s = mulmod(c, xk, N);
        s = N - s;
        s = addmod(alpha, s, N);
    }

    //Ring Signature Functions
    function RingSignatureN(string message, uint256[] random, uint8 k, uint256 xk, uint256[] PubKeys)
        public constant returns (uint256[10] c, uint256[10] s, uint256 Ix)
    {
        //Check Array Lengths
        require( random.length < 10 ); //Bounded by s[10]
        require( random.length > 1 ); //need alpha (c0), and sk for each k
        require( PubKeys.length == random.length ); //one less for c0
        require( k < random.length );

        //Memory Registers
        uint256[2] memory pubkey;
        uint256[2] memory keyimage;

        //Setup Indices
        uint i = (k + 1) % random.length;

        //Calculate Key Image
        pubkey = ExpandPoint(PubKeys[k]);
        keyimage = KeyImage(xk, pubkey);
        Ix = CompressPoint(keyimage);

        //Calculate Starting c = hash( message, alpha*G1, alpha*HashPoint(Pk) )
        c[i] = RingStartingSegment(message, random[k], pubkey);

        for (; i != k;) {
            //Pick s value
            s[i] = random[i];

            //Deserialize Point and calculate next Ring Segment
            pubkey = ExpandPoint(PubKeys[i]);
            c[(i+1) % random.length] = RingSegment(message, c[i], s[i], pubkey, keyimage);

            //Increment Counters
            i = i + 1;

            // Roll counters over
            if (i == random.length) {
                i = 0;
            }
        }

        //Calculate s1 s.t. alpha*G1 = c1*P1 + s1*G1 = (c1*x1 + s1) * G1
        //s1 = alpha - c1*x1
        s[k] = SubMul(random[k], c[k], xk);
    }

    //Gas Cost: N == 2 ->  506837
    //Gas Cost: N == 3 ->  736868
    //Gas Cost: N == 5 ->  1197198
    //Note: there is 10% gas overhead when using compressed points
    function RingVerifyN(string message, uint256 c0, uint256[] s, uint256[] PubKeys, uint256 Ix)
        public constant returns (bool success)
    {
        //Check Array Lengths
        require( s.length > 1 );
        require( PubKeys.length == s.length );

        //Memory Registers
        uint256[2] memory temp;
        uint256[2] memory keyimage;
        uint256 c = c0;

        //Expand Key Image
        keyimage = ExpandPoint(Ix);

        //Verify Ring
        uint i = 0;
        for (; i < s.length;) {
            //Deserialize Point and calculate next Ring Segment
            temp = ExpandPoint(PubKeys[i]);
            c = RingSegment(message, c, s[i], temp, keyimage);

            //Increment Counters
            i = i + 1;
        }

        success = (c == c0);

        if (c == c0 && !KeyImageUsed[Ix]) {
            //KeyImageUsed[Ix] = true;
            return true;
        } else {
            return false;
        }
    }

    function RingVerifyN_GasTest(string message, uint256 c0, uint256[] s, uint256[] PubKeys, uint256 Ix)
        public returns (bool success)
    {
        return RingVerifyN(message, c0, s, PubKeys, Ix);
    }
}
