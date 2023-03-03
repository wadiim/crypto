import java.lang.reflect.Array;
import java.util.Arrays;

public class AES implements Cipher {

    private byte[] key;

    public AES() {

    }

    @Override
    public byte[] decrypt(byte[] message) {
        return new byte[0];
    }

    @Override
    public byte[] encrypt(byte[] message) {
        return new byte[0];
    }

    public byte[] getKey() {
        return key;
    }

    public void setKey(byte[] key) {
        this.key = Arrays.copyOf(key,  key.length);
    }
}
