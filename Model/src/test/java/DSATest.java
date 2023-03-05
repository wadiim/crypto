import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class DSATest {
    private DSA dsa;
    private byte[] publicKey;
    private byte[] privateKey;

    @BeforeEach
    void setUp() {
        dsa = new DSA();
        publicKey = new byte[] {
                (byte) 0x91, (byte) 0xe8, (byte) 0x25, (byte) 0xf6, (byte) 0xe6, (byte) 0x87, (byte) 0x94, (byte) 0xa7,
                (byte) 0x0e, (byte) 0xa5, (byte) 0xed, (byte) 0xfa, (byte) 0x8e, (byte) 0x9f, (byte) 0x6e, (byte) 0x5f,
                (byte) 0xb9, (byte) 0x8a, (byte) 0x19, (byte) 0x9e, (byte) 0x5e, (byte) 0xaf, (byte) 0x4b, (byte) 0x0c,
                (byte) 0x68, (byte) 0xd9, (byte) 0x3c, (byte) 0x65, (byte) 0x3d, (byte) 0x6a, (byte) 0x0d, (byte) 0xe8,
                (byte) 0x91, (byte) 0x66, (byte) 0xa6, (byte) 0x25, (byte) 0xd4, (byte) 0x4a, (byte) 0xac, (byte) 0xf2,
                (byte) 0x23, (byte) 0x1f, (byte) 0xcd, (byte) 0xac, (byte) 0x4d, (byte) 0xe2, (byte) 0xb8, (byte) 0x34,
                (byte) 0x5c, (byte) 0x3d, (byte) 0x99, (byte) 0xe1, (byte) 0x4a, (byte) 0xf8, (byte) 0x42, (byte) 0x02,
                (byte) 0xbb, (byte) 0x4d, (byte) 0xa7, (byte) 0xb9, (byte) 0x59, (byte) 0xdd, (byte) 0xce, (byte) 0xef
        };
        privateKey = new byte[] {
                (byte) 0x3b, (byte) 0xc3, (byte) 0x5d, (byte) 0xf9, (byte) 0xdf, (byte) 0xfb, (byte) 0xea, (byte) 0xf3,
                (byte) 0xf4, (byte) 0x50, (byte) 0x3b, (byte) 0x66, (byte) 0xa6, (byte) 0x4b, (byte) 0xad, (byte) 0x1f,
                (byte) 0x92, (byte) 0xa7, (byte) 0x0e, (byte) 0x48
        };
    }

    @Test
    void TestGetPublicKeyIfKeyWasNotSetThenReturnsNull() {
        assertNull(dsa.getPublicKey());
    }

    @Test
    void TestGetPrivateKeyIfKeyWasNotSetThenReturnsNull() {
        assertNull(dsa.getPrivateKey());
    }

    @Test
    void TestSetKeysIfValidKeysThenSetsTheKeys() {
        dsa.setKeys(publicKey, privateKey);
        assertArrayEquals(publicKey, dsa.getPublicKey());
        assertArrayEquals(privateKey, dsa.getPrivateKey());
    }

    @Test
    void TestSetKeysIfParametersAreModifiedAfterCallThenTheKeysAreNotAltered() {
        byte[] tmpPublicKey = publicKey.clone();
        byte[] tmpPrivateKey = privateKey.clone();
        dsa.setKeys(tmpPublicKey, tmpPrivateKey);

        tmpPublicKey[0]--;
        tmpPrivateKey[0]--;

        assertArrayEquals(publicKey, dsa.getPublicKey());
        assertArrayEquals(privateKey, dsa.getPrivateKey());
    }
}
