import java.math.BigInteger;
import java.util.Arrays;

/**
 * @see <a href="https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf">Secure Hash Standard</a>
 */
public class SHA1 implements Hash {
    public static final int WORD_SIZE_IN_BITS = 32;
    public static final int BLOCK_SIZE_IN_BITS = 512;

    @Override
    public byte[] getDigest(byte[] message) {
        return new byte[0];
    }

    public byte[] addPadding(byte[] message) {
        if (message.length == 0) {
            return new byte[0];
        }

        // Calculate the size of the padded message
        int outputSize = 0;
        while (outputSize <= message.length + (2* WORD_SIZE_IN_BITS / Byte.SIZE) + 1) {
            outputSize += BLOCK_SIZE_IN_BITS / Byte.SIZE;
        }

        byte[] padded = Arrays.copyOf(message, outputSize);

        // Append the bit "1" at the end of the input message
        padded[message.length] = (byte) (1 << 7);

        // Set the last two words to the size of the input message
        byte[] tmp = new BigInteger(String.valueOf(message.length*Byte.SIZE)).toByteArray();
        for (int i = 1; i <= tmp.length; ++i) {
            padded[padded.length - i] = tmp[tmp.length - i];
        }

        return padded;
    }

    public byte[][] splitIntoBlocks(byte[] message) throws RuntimeException {
        if (message.length % (BLOCK_SIZE_IN_BITS / Byte.SIZE) != 0) {
            throw new RuntimeException("Message is not padded");
        }

        byte[][] blocks = new byte[message.length / (BLOCK_SIZE_IN_BITS / Byte.SIZE)][];
        for (int i = 0, j = 0; i < message.length; i += (BLOCK_SIZE_IN_BITS / Byte.SIZE), ++j) {
            blocks[j] = Arrays.copyOfRange(message, i, i + (BLOCK_SIZE_IN_BITS / Byte.SIZE));
        }

        return blocks;
    }
}
