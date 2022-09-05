pragma circom 2.0.0;

template multiply(lambda) {
    signal input a;
    signal input b;
    signal c;
    signal csq;
    signal output out;

    c <== a * b;
    csq <== c * c;
    
    out <== lambda * csq;
}

component main = multiply(7);

