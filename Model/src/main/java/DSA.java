import java.math.BigInteger;
import java.lang.Math;
import java.util.Random;

/**
 * @see <a href="https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf">Digital Signature Standard</a>
 */
public class DSA implements Signature {

    /*
     * In accordance to the DSS standard, the (L, N) pair shall be one of the following:
     *      (1024, 160), (2048, 224), (2048, 256), (3072, 256)
     */
    private int L;          // Length of the parameter p in bits
    private int N;          // Length of the parameter q in bits

    private BigInteger x;   // Private key
                            // 0 < x < q
    private BigInteger y;   // Public key
                            // y = g^x mod p

    /* Domain parameters */
    private BigInteger p;   // Prime number
                            // 2^(L-1) < p < 2^L

    private BigInteger q;   // Prime factor
                            // q | (p-1) and 2^(N-1) < q < 2^N

    private BigInteger g;   // Generator
                            // 1 < g < p

    private long seed;      // Seed used for generation of domain parameters
    private int counter;    // The counter value that results from the domain parameter generation process when the
                            // domain parameter seed is used to generate DSA domain parameters.

    private BigInteger d;   // Private signature exponent of a private key
    private BigInteger k;   // Per-message secret number. Shall be generated prior to the generation of each digital
                            // signature for use during the signature generation process.
                            // 0 < k < q

    private final Hash hash;    // Object providing hashing functionality used for generation of message digest

    public DSA(Hash hash) {
        L = 1024;
        N = 160;
        this.hash = hash;
    }

    @Override
    public void generateKeys() {
        int n = (int) (Math.ceil((double) L / N) - 1);
        int b = L - 1 - (n * N);

        // Generate seed
        seed = new Random().nextInt();

        // Calculate q
        // q = 2^(N-1) + U + 1 - (U mod 2)
        BigInteger qMin = BigInteger.TWO.pow(N - 1);
        BigInteger U = new BigInteger(1, hash.getDigest(longToByteArray(seed))).mod(qMin);
        q = qMin.add(U).add(BigInteger.ONE).subtract(U.mod(BigInteger.TWO));

        int offset = 1;
        for (counter = 0; counter < 4*L; ++counter) {
            BigInteger[] V = new BigInteger[n + 1];
            for (int j = 0; j <= n; ++j) {
                // V_j = hash((seed + offset + j) mod 2^32
                V[j] = new BigInteger(1, hash.getDigest(new BigInteger(longToByteArray(seed + offset + j))
                        .mod(BigInteger.TWO.pow(32))
                        .toByteArray()
                ));
            }

            // W = V_0 + (V_1 * 2^N) + ... + (V_(n-1) * 2^((n-1) * N)) + ((V_n mod 2^b) * 2^(n * N))
            BigInteger W = new BigInteger(1, V[0].toByteArray());
            for (int i = 1; i < n; ++i) {
                W = W.add(V[i].multiply(BigInteger.TWO.pow(i * N)));
            }
            W = W.add(V[n].mod(BigInteger.TWO.pow(b)).multiply(BigInteger.TWO.pow(n * N)));

            BigInteger X = W.add(BigInteger.TWO.pow(L - 1));
            BigInteger c = X.mod(BigInteger.TWO.multiply(q));

            // Calculate p
            p = X.subtract(c.subtract(BigInteger.ONE));

            if (p.isProbablePrime(2)) {
                break;
            }

            offset += n + 1;
        }

        // Calculate g
        BigInteger e = new BigInteger(1, p.subtract(BigInteger.ONE).toByteArray()).divide(q);
        do {
            // h needs to be in range [1, (p - 1)]. We can ensure this by setting the length in bits to be 2 less than
            // the length of p and adding one to the result of random generation.
            BigInteger h = new BigInteger(L - 2, new Random(seed)).add(BigInteger.ONE);
            g = h.modPow(e, p);
        } while ( g.compareTo(BigInteger.ONE) == 0);

        // Calculate key pair (see section B.1.2 of DSS)
        BigInteger c;
        do {
            c = new BigInteger(N, new Random());
        } while (c.compareTo(q.subtract(BigInteger.TWO)) > 0);
        x = c.add(BigInteger.ONE);
        y = g.modPow(x, p);
    }

    @Override
    public byte[] getPublicKey() {
        return (y != null) ? removeLeadingZeroByte(y.toByteArray()) : null;
    }

    @Override
    public byte[] getPrivateKey() {
        return (x != null) ? removeLeadingZeroByte(x.toByteArray()) : null;
    }

    @Override
    public void setKeys(byte[] publicKey, byte[] privateKey) {
        if (p == null || q == null || g == null) {
            throw new RuntimeException("Failed to set keys - The domain parameters are not set");
        }
        BigInteger yBig = new BigInteger(1, publicKey);
        BigInteger xBig = new BigInteger(1, privateKey);
        if (! yBig.equals(g.modPow(xBig, p))) {
            throw new RuntimeException("Failed to set keys - The keys are not related");
        }
        y = yBig;
        x = xBig;
    }

    /**
     * Steps:
     *  1. Compute domain parameters p, q, and g
     *  2. Compute private and public keys
     *  3. Generate new secret random number k
     *  4. Generate message digest
     *  5. Generate signature (r, s)
     *
     * @see "Section 4.6 of DSS"
     */
    @Override
    public byte[] sign(byte[] message) {
        return new byte[0];
    }

    /**
     * @see "Section 4.7 of DSS"
     */
    @Override
    public boolean verify(byte[] message, byte[] sign) {
        return false;
    }

    public void setDomainParameters(byte[] p, byte[] q, byte[] g) {
        setDomainParameters(p, q, g, 0, 0);
    }

    public void setDomainParameters(byte[] p, byte[] q, byte[] g, long seed, int counter) {
        BigInteger pBig = new BigInteger(1, p);
        BigInteger qBig = new BigInteger(1, q);
        BigInteger gBig = new BigInteger(1, g);

        if (! pBig.isProbablePrime(2)) {
            throw new RuntimeException("Invalid value of the p domain parameter - not a prime");
        }
        if (! pBig.subtract(BigInteger.ONE).mod(qBig).equals(BigInteger.ZERO)) {
            throw new RuntimeException("Invalid value of the q domain parameter - not a divisor of (p - 1)");
        }
        if (gBig.compareTo(BigInteger.ONE) <= 0 || gBig.compareTo(pBig) >= 0) {
            throw new RuntimeException("Invalid value of the g domain parameter");
        }

        this.p = pBig;
        this.q = qBig;
        this.g = gBig;
        this.seed = seed;
        this.counter = counter;
    }

    public byte[] getP() {
        return (p != null) ? removeLeadingZeroByte(p.toByteArray()) : null;
    }

    public byte[] getQ() {
        return (q != null) ? removeLeadingZeroByte(q.toByteArray()) : null;
    }

    public byte[] getG() {
        return (g != null) ? removeLeadingZeroByte(g.toByteArray()) : null;
    }

    private static byte[] longToByteArray(long value) {
        return new byte[] {
                (byte)(value >>> 56),
                (byte)(value >>> 48),
                (byte)(value >>> 40),
                (byte)(value >>> 32),
                (byte)(value >>> 24),
                (byte)(value >>> 16),
                (byte)(value >>> 8),
                (byte)value
        };
    }

    private static byte[] removeLeadingZeroByte(byte[] bytes) {
        if (bytes[0] == 0) {
            byte[] tmp = new byte[bytes.length - 1];
            System.arraycopy(bytes, 1, tmp, 0, tmp.length);
            bytes = tmp;
        }
        return bytes;
    }
}
