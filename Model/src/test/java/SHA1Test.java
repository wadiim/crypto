import static org.junit.jupiter.api.Assertions.*;
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

    @Test
    void TestSplitIntoBlocksIfTheMessageSizeIsNotMultipleOfTheBlockSizeThenThrowsException() {
        assertThrows(RuntimeException.class, () -> hash.splitIntoBlocks(new byte[SHA1.BLOCK_SIZE_IN_BITS - 1]));
    }

    @Test
    void TestSplitIntoBlocksIfTheMessageHasSizeOfOneBlockThenReturnsArrayOfSizeOne() {
        assertEquals(1, hash.splitIntoBlocks(new byte[SHA1.BLOCK_SIZE_IN_BITS / Byte.SIZE]).length);
    }

    @Test
    void TestSplitIntoBlocksIfTheMessageHasSizeOfOneBlockThenTheFirstElementHasCorrectSize() {
        assertEquals(SHA1.BLOCK_SIZE_IN_BITS / Byte.SIZE,
                hash.splitIntoBlocks(new byte[SHA1.BLOCK_SIZE_IN_BITS / Byte.SIZE])[0].length);
    }

    @Test
    void TestSplitIntoBlocksIfTheMessageHasSizeOfOneBlockThenTheFirstElementIsEqualToThatBlock() {
        byte[] message = new byte[] { 0xC, 0x0, 0xF, 0xF, 0xE, 0xE };
        byte[] block = hash.addPadding(message);
        assertArrayEquals(block, hash.splitIntoBlocks(block)[0]);
    }

    @Test
    void TestSplitIntoBlocksIfTheMessageHasSizeOfOneBlockThenTheFirstElementIsACopyOfTheMessage() {
        byte[] message = new byte[] { 0xC, 0x0, 0xF, 0xF, 0xE, 0xE };
        byte[][] blocks = hash.splitIntoBlocks(hash.addPadding(message));
        message[0] = 0x2;
        assertNotEquals(message[0], blocks[0][0]);
    }

    @Test
    void TestSplitIntoBlocksIfTheMessageHasSizeOfMultipleBlocksThenReturnsCorrectNumberOfBlocks() {
        assertEquals(4, hash.splitIntoBlocks(new byte[4 * (SHA1.BLOCK_SIZE_IN_BITS / Byte.SIZE)]).length);
    }

    @Test
    void TestSplitIntoBlocksIfTheMessageHasSizeOfMultipleBlocksThenReturnsElementsOfCorrectSizes() {
        for (byte[] block : hash.splitIntoBlocks(new byte[4 * (SHA1.BLOCK_SIZE_IN_BITS / Byte.SIZE)])) {
            assertEquals(SHA1.BLOCK_SIZE_IN_BITS / Byte.SIZE, block.length);
        }
    }

    @Test
    void TestSplitIntoBlocksIfTheMessageHasSizeOfMultipleBlocksThenReturnsElementsEqualToThatBlocks() {
        final int BLOCK_SIZE_IN_BYTES = (SHA1.BLOCK_SIZE_IN_BITS / Byte.SIZE);
        byte[] message = new byte[2 * BLOCK_SIZE_IN_BYTES];
        for (int i = 0; i < BLOCK_SIZE_IN_BYTES; ++i) {
            message[i] = 0x2;
        }
        for (int i = BLOCK_SIZE_IN_BYTES; i < message.length; ++i) {
            message[i] = 0x4;
        }

        byte[] padded = hash.addPadding(message);
        byte[][] blocks = hash.splitIntoBlocks(padded);

        // Test the first block
        for (byte b : blocks[0]) {
            assertEquals(0x2, b);
        }

        // Test the second block
        for (byte b : blocks[1]) {
            assertEquals(0x4, b);
        }

        // Test the last block
        assertEquals((byte) (1 << 7), blocks[2][0]);
        assertEquals((2 * SHA1.BLOCK_SIZE_IN_BITS) & 0xFF, blocks[2][blocks[2].length - 1]);
        assertEquals((((2 * SHA1.BLOCK_SIZE_IN_BITS) & (0xFF << 8)) >> 8), blocks[2][blocks[2].length - 2]);
    }
}
