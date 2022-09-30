pragma circom 2.0.0;

template multiply() {
    signal input a;
    signal input b;
    signal c;
    signal csq;
    signal output out;

    c <== a * b;
    csq <== c * c;
    
    out <== 5 * csq;
}

component main = multiply();

