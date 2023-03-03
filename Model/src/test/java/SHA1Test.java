import static org.junit.jupiter.api.Assertions.assertEquals;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.math.BigInteger;

public class SHA1Test {
    private SHA1 hash;

    @BeforeEach
    void setUp() {
        hash = new SHA1();
    }

    @Test
    void TestAddPaddingIfEmptyMessageThenTheMessageStaysEmpty() {
        assertEquals(0, hash.addPadding(new byte[0]).length);
    }

    @Test
    void TestAddPaddingIfMessageSizeIsLessThanOneBlockThenTheMessageIsExtendedToOneBlock() {
        assertEquals(SHA1.BLOCK_SIZE_IN_BITS / Byte.SIZE,
                hash.addPadding(new byte[] { 0xC, 0x0, 0xF, 0xF, 0xE, 0xE }).length);
    }

    /*
        The message after padding has to be of size being a multiple of block size. An input message whose size is
        already a multiple of the block size must be changed anyway, because the bit "1" must be appended to the end of
        the input message and the last two words of the output message must contain the size of the input message.
     */
    @Test
    void TestAddPaddingIfMessageSizeEqualsTheBlockSizeThenTheMessageIsExtendedToTwoBlocks() {
        byte[] message = new byte[SHA1.BLOCK_SIZE_IN_BITS / Byte.SIZE];
        Arrays.fill(message, (byte) 0x2);
        assertEquals(2 * (SHA1.BLOCK_SIZE_IN_BITS / Byte.SIZE), hash.addPadding(message).length);
    }

    @Test
    void TestAddPaddingIfMessageSizeIsLessThanOneBlockThenTheMessageIsPaddedWithZeros() {
        byte[] message = new byte[] { 0x1, 0x2, 0x3, 0x4 };
        byte[] ret = hash.addPadding(message);
        for (int i = message.length + 1; i < (ret.length - 1) - (2*SHA1.WORD_SIZE_IN_BITS / Byte.SIZE); ++i) {
            assertEquals(0, ret[i]);
        }
    }

    @Test
    void TestAddPaddingIfNonEmptyMessageThenTheBit1IsAppended() {
        assertEquals((1 << 7), hash.addPadding(new byte[] { 0x2 })[1] & (1 << 7));
    }

    @Test
    void TestAddPaddingIfNonEmptyMessageThenTheLastTwoWordsReturnedContainsTheSizeOfTheMessage() {
        byte[] message = new byte[1337];
        Arrays.fill(message, (byte) 0x2);
        byte[] ret = hash.addPadding(message);
        BigInteger expected = new BigInteger(String.valueOf(1337*Byte.SIZE));
        BigInteger actual = new BigInteger(Arrays.copyOfRange(ret, ret.length - 8, ret.length));
        assertEquals(expected, actual);
    }
}
