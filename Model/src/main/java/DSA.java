import java.math.BigInteger;

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
    private BigInteger y;   // Public key

    /* Domain parameters */
    private BigInteger p;   // Prime number
    private BigInteger q;   // Prime factor
    private BigInteger g;   // Generator
    private long seed;      // Seed used for generation of domain parameters
    private int counter;    // The counter value that results from the domain parameter generation process when the
                            // domain parameter seed is used to generate DSA domain parameters.

    private BigInteger d;   // Private signature exponent of a private key
    private BigInteger k;   // Per-message secret number. Shall be generated prior to the generation of each digital
                            // signature for use during the signature generation process.

    private Hash hash;      // Object providing hashing functionality used for generation of message digest

    public DSA() {
        L = 1024;
        N = 160;
    }

    @Override
    public void generateKeys() {

    }

    @Override
    public byte[] getPublicKey() {
        return (y != null) ? y.toByteArray() : null;
    }

    @Override
    public byte[] getPrivateKey() {
        return (x != null) ? x.toByteArray() : null;
    }

    @Override
    public void setKeys(byte[] publicKey, byte[] privateKey) {
        y = new BigInteger(publicKey);
        x = new BigInteger(privateKey);
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
}
