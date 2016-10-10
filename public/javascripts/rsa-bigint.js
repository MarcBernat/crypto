/**
 * Created by irkalla on 29.09.16.
 */
rsa2 = {
    publicKey: function (bits, n, e) {
        this.bits = bits;
        this.n = n;
        this.e = e;
    },
    privateKey: function (p, q, d, publicKey) {
        this.p = p;
        this.q = q;
        this.d = d;
        this.publicKey = publicKey;
    },
    generateKeys: function(bitlength) {

        var p, q, n, phi, e, d, keys = {};
        this.bitlength = bitlength || 2048;
        console.log("Generating RSA keys of", this.bitlength, "bits");
        p = bigInt.prime(this.bitlength / 2);
        do {
            q = bigInt.prime(this.bitlength / 2);
        } while (q.compare(p) === 0);
        n = p.multiply(q);

        phi = p.subtract(1).multiply(q.subtract(1));

        e = bigInt(65537);
        d = bigInt.modInverse(e, phi);

        keys.publicKey = new rsa2.publicKey(this.bitlength, n, e);
        keys.privateKey = new rsa2.privateKey(p, q, d, keys.publicKey);
        return keys;
    }
};


rsa2.publicKey.prototype = {
    encrypt: function(m) {
        return m.modPow(this.e, this.n);
    },
    decrypt: function(c) {
        return c.modPow(this.d, this.n);
    }
};

rsa2.privateKey.prototype = {
    encrypt: function(m) {
        return m.modPow(this.d, this.publicKey.n);
    },

    decrypt: function(c) {
        return c.modPow(this.d, this.publicKey.n);
    }
};