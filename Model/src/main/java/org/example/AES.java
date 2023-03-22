package org.example;

public class AES implements Cipher {

    public byte[] key;
    public byte[][] roundKeys;
    public AES(byte[] key) {
        this.key = key;
        expandKey();
    }
    public void expandKey() {
        this.roundKeys = extendKey(this.key);
    }

    @Override
    public byte[] decrypt(byte[] message) {
        byte[] message2 = new byte[message.length];
        System.arraycopy(message,0, message2,0,message.length);

        byte[] clearText3 = new byte[message.length];
        for(int i = 0; i<message.length;)
        {
            byte[] decodingBlocks = new byte[16];
            System.arraycopy(message2,i, decodingBlocks,0,16);
            i += 16;
            decodingBlocks = invCipher(decodingBlocks);
            System.arraycopy(decodingBlocks, 0, clearText3, i - 16, 16);
        }

        int endZero = 0;
        for (int i = 1; i < 16; i++) {
            if (clearText3[clearText3.length - (i+1)] == '\0') {
                endZero++;
            } else {
                break;
            }
        }

        byte[] clearText4 = new byte[message.length - endZero - 1];
        System.arraycopy(clearText3, 0, clearText4, 0, message.length - endZero - 1);

        return clearText4;
    }

    @Override
    public byte[] encrypt(byte[] message) {
        int howManyCharacters = (message.length + 15) / 16 * 16;

        byte[] clearText2 = new byte[howManyCharacters];
        System.arraycopy(message,0, clearText2,0,message.length);
        for (int i = message.length; i < howManyCharacters; i++) {
            clearText2[i] = 0;
        }

        byte[] clearText3 = new byte[howManyCharacters];
        int i = 0;
        while (i < clearText2.length) {
            byte[] encryptionBlocks = new byte[16];
            System.arraycopy(clearText2,i,encryptionBlocks,0,16);
            i += 16;
            encryptionBlocks = cipher(encryptionBlocks);
            System.arraycopy(encryptionBlocks, 0, clearText3, i - 16, encryptionBlocks.length);
        }
        return clearText3;
    }
    public byte[] cipher(byte[] data) {
        byte[] dataBlock = new byte[data.length];
        System.arraycopy(data,0,dataBlock,0,data.length);
        // Round 0
        dataBlock = addRoundKey(dataBlock, 0);
        // Round 1-9
        for (int i = 1; i < 10; i++) {
            dataBlock = subBytes(dataBlock);
            dataBlock = shiftRows(dataBlock);
            dataBlock = mixColumns(dataBlock);
            dataBlock = addRoundKey(dataBlock, i);
        }
        // Round 10
        dataBlock = subBytes(dataBlock);
        dataBlock = shiftRows(dataBlock);
        dataBlock = addRoundKey(dataBlock, 10);
        return dataBlock;
    }

    public byte[] invCipher(byte[] dataBlock) {
        byte[] temporaryDataBlock = new byte[dataBlock.length];
        System.arraycopy(dataBlock,0,temporaryDataBlock,0,dataBlock.length);
        // Round 10
        temporaryDataBlock = addRoundKey(temporaryDataBlock, 10);
        temporaryDataBlock = invShiftRows(temporaryDataBlock);
        temporaryDataBlock = invSubBytes(temporaryDataBlock);
        // Round 9-1
        for (int i = 9; i > 0; i--) {
            temporaryDataBlock = addRoundKey(temporaryDataBlock, i);
            temporaryDataBlock = invMixColumns(temporaryDataBlock);
            temporaryDataBlock = invShiftRows(temporaryDataBlock);
            temporaryDataBlock = invSubBytes(temporaryDataBlock);
        }
        // Round 0
        temporaryDataBlock = addRoundKey(temporaryDataBlock, 0);
        return temporaryDataBlock;
    }

    /*
        Transformation in the org.example.Cipher that takes all of the columns
        of the State and mixes their data (independently of one another)
        to produce new columns.
    */
    public byte[] mixColumns(byte[] dataBlock) {

        /*
            Assigning a data block to a matrix
         */
        byte[][] matrix = new byte[4][4];
        int a = 0;
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                matrix[i][j] = dataBlock[a];
                a++;
            }
        }

        /*
            Performing appropriate multiplications
         */
        byte[][] matrix2 = new byte[4][4];
        matrix2[0][0] = XORFourBytes(GF28((byte) 0b00000010, matrix[0][0]), GF28((byte) 0b00000011, matrix[0][1]), matrix[0][2], matrix[0][3]);
        matrix2[0][1] = XORFourBytes(matrix[0][0], GF28((byte) 0b00000010, matrix[0][1]), GF28((byte) 0b00000011, matrix[0][2]), matrix[0][3]);
        matrix2[0][2] = XORFourBytes(matrix[0][0], matrix[0][1], GF28((byte) 0b00000010, matrix[0][2]), GF28((byte) 0b00000011, matrix[0][3]));
        matrix2[0][3] = XORFourBytes(GF28((byte) 0b00000011, matrix[0][0]), matrix[0][1], matrix[0][2], GF28((byte) 0b00000010, matrix[0][3]));
        matrix2[1][0] = XORFourBytes(GF28((byte) 0b00000010, matrix[1][0]), GF28((byte) 0b00000011, matrix[1][1]), matrix[1][2], matrix[1][3]);
        matrix2[1][1] = XORFourBytes(matrix[1][0], GF28((byte) 0b00000010, matrix[1][1]), GF28((byte) 0b00000011, matrix[1][2]), matrix[1][3]);
        matrix2[1][2] = XORFourBytes(matrix[1][0], matrix[1][1], GF28((byte) 0b00000010, matrix[1][2]), GF28((byte) 0b00000011, matrix[1][3]));
        matrix2[1][3] = XORFourBytes(GF28((byte) 0b00000011, matrix[1][0]), matrix[1][1], matrix[1][2], GF28((byte) 0b00000010, matrix[1][3]));
        matrix2[2][0] = XORFourBytes(GF28((byte) 0b00000010, matrix[2][0]), GF28((byte) 0b00000011, matrix[2][1]), matrix[2][2], matrix[2][3]);
        matrix2[2][1] = XORFourBytes(matrix[2][0], GF28((byte) 0b00000010, matrix[2][1]), GF28((byte) 0b00000011, matrix[2][2]), matrix[2][3]);
        matrix2[2][2] = XORFourBytes(matrix[2][0], matrix[2][1], GF28((byte) 0b00000010, matrix[2][2]), GF28((byte) 0b00000011, matrix[2][3]));
        matrix2[2][3] = XORFourBytes(GF28((byte) 0b00000011, matrix[2][0]), matrix[2][1], matrix[2][2], GF28((byte) 0b00000010, matrix[2][3]));
        matrix2[3][0] = XORFourBytes(GF28((byte) 0b00000010, matrix[3][0]), GF28((byte) 0b00000011, matrix[3][1]), matrix[3][2], matrix[3][3]);
        matrix2[3][1] = XORFourBytes(matrix[3][0], GF28((byte) 0b00000010, matrix[3][1]), GF28((byte) 0b00000011, matrix[3][2]), matrix[3][3]);
        matrix2[3][2] = XORFourBytes(matrix[3][0], matrix[3][1], GF28((byte) 0b00000010, matrix[3][2]), GF28((byte) 0b00000011, matrix[3][3]));
        matrix2[3][3] = XORFourBytes(GF28((byte) 0b00000011, matrix[3][0]), matrix[3][1], matrix[3][2], GF28((byte) 0b00000010, matrix[3][3]));

        /*
            Converting a matrix to a constant
         */
        byte[] outputDataBlock = new byte[16];
        a = 0;
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                outputDataBlock[a] = matrix2[i][j];
                a++;
            }
        }
        return outputDataBlock;

    }

    /*
        Transformation in the Inverse org.example.Cipher that is the inverse of MixColumns().
     */
    public byte[] invMixColumns(byte[] dataBlock) {
        byte[][] matrix = new byte[4][4];
        int a = 0;
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                matrix[i][j] = dataBlock[a];
                a++;
            }
        }
        byte[][] matrix2 = new byte[4][4];
        matrix2[0][0] = XORFourBytes(GF28((byte) 0b00001110, matrix[0][0]), GF28((byte) 0b00001011, matrix[0][1]), GF28((byte) 0b00001101, matrix[0][2]), GF28((byte) 0b00001001, matrix[0][3]));
        matrix2[0][1] = XORFourBytes(GF28((byte) 0b00001001, matrix[0][0]), GF28((byte) 0b00001110, matrix[0][1]), GF28((byte) 0b00001011, matrix[0][2]), GF28((byte) 0b00001101, matrix[0][3]));
        matrix2[0][2] = XORFourBytes(GF28((byte) 0b00001101, matrix[0][0]), GF28((byte) 0b00001001, matrix[0][1]), GF28((byte) 0b00001110, matrix[0][2]), GF28((byte) 0b00001011, matrix[0][3]));
        matrix2[0][3] = XORFourBytes(GF28((byte) 0b00001011, matrix[0][0]), GF28((byte) 0b00001101, matrix[0][1]), GF28((byte) 0b00001001, matrix[0][2]), GF28((byte) 0b00001110, matrix[0][3]));
        matrix2[1][0] = XORFourBytes(GF28((byte) 0b00001110, matrix[1][0]), GF28((byte) 0b00001011, matrix[1][1]), GF28((byte) 0b00001101, matrix[1][2]), GF28((byte) 0b00001001, matrix[1][3]));
        matrix2[1][1] = XORFourBytes(GF28((byte) 0b00001001, matrix[1][0]), GF28((byte) 0b00001110, matrix[1][1]), GF28((byte) 0b00001011, matrix[1][2]), GF28((byte) 0b00001101, matrix[1][3]));
        matrix2[1][2] = XORFourBytes(GF28((byte) 0b00001101, matrix[1][0]), GF28((byte) 0b00001001, matrix[1][1]), GF28((byte) 0b00001110, matrix[1][2]), GF28((byte) 0b00001011, matrix[1][3]));
        matrix2[1][3] = XORFourBytes(GF28((byte) 0b00001011, matrix[1][0]), GF28((byte) 0b00001101, matrix[1][1]), GF28((byte) 0b00001001, matrix[1][2]), GF28((byte) 0b00001110, matrix[1][3]));
        matrix2[2][0] = XORFourBytes(GF28((byte) 0b00001110, matrix[2][0]), GF28((byte) 0b00001011, matrix[2][1]), GF28((byte) 0b00001101, matrix[2][2]), GF28((byte) 0b00001001, matrix[2][3]));
        matrix2[2][1] = XORFourBytes(GF28((byte) 0b00001001, matrix[2][0]), GF28((byte) 0b00001110, matrix[2][1]), GF28((byte) 0b00001011, matrix[2][2]), GF28((byte) 0b00001101, matrix[2][3]));
        matrix2[2][2] = XORFourBytes(GF28((byte) 0b00001101, matrix[2][0]), GF28((byte) 0b00001001, matrix[2][1]), GF28((byte) 0b00001110, matrix[2][2]), GF28((byte) 0b00001011, matrix[2][3]));
        matrix2[2][3] = XORFourBytes(GF28((byte) 0b00001011, matrix[2][0]), GF28((byte) 0b00001101, matrix[2][1]), GF28((byte) 0b00001001, matrix[2][2]), GF28((byte) 0b00001110, matrix[2][3]));
        matrix2[3][0] = XORFourBytes(GF28((byte) 0b00001110, matrix[3][0]), GF28((byte) 0b00001011, matrix[3][1]), GF28((byte) 0b00001101, matrix[3][2]), GF28((byte) 0b00001001, matrix[3][3]));
        matrix2[3][1] = XORFourBytes(GF28((byte) 0b00001001, matrix[3][0]), GF28((byte) 0b00001110, matrix[3][1]), GF28((byte) 0b00001011, matrix[3][2]), GF28((byte) 0b00001101, matrix[3][3]));
        matrix2[3][2] = XORFourBytes(GF28((byte) 0b00001101, matrix[3][0]), GF28((byte) 0b00001001, matrix[3][1]), GF28((byte) 0b00001110, matrix[3][2]), GF28((byte) 0b00001011, matrix[3][3]));
        matrix2[3][3] = XORFourBytes(GF28((byte) 0b00001011, matrix[3][0]), GF28((byte) 0b00001101, matrix[3][1]), GF28((byte) 0b00001001, matrix[3][2]), GF28((byte) 0b00001110, matrix[3][3]));
        byte[] outputDataBlock = new byte[16];
        a = 0;
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                outputDataBlock[a] = matrix2[i][j];
                a++;
            }
        }
        return outputDataBlock;

    }

    /*
        Transformation in the org.example.Cipher that processes the State by cyclically
        shifting the last three rows of the State by different offsets.
     */
    public byte[] shiftRows(byte dataBlock[]) {

        byte dataMatrix[][] = createColumnMatrix(dataBlock);
        byte newDataMatrix[][] = new byte[4][4];

        newDataMatrix[0] = dataMatrix[0];
        for (int wiersz = 1; wiersz < dataMatrix.length; wiersz++)
            for (int kolumna = 0; kolumna < dataMatrix[wiersz].length; kolumna++)
                newDataMatrix[wiersz][kolumna] = dataMatrix[wiersz][(kolumna + wiersz) % 4];

        return oneDimensionalArray(newDataMatrix);
    }

    /*
        Transformation in the Inverse org.example.Cipher that is the inverse of shiftRows().
     */
    public byte[] invShiftRows(byte[] dataBlock) {

        byte[][] dataMatrix = createColumnMatrix(dataBlock);
        byte newDataMatrix[][] = new byte[4][4];

        newDataMatrix[0] = dataMatrix[0];
        for (int rows = 1; rows < dataMatrix.length; rows++)
            for (int column = 0; column < dataMatrix[rows].length; column++)
                newDataMatrix[rows][(column + rows) % 4] = dataMatrix[rows][column];

        return oneDimensionalArray(newDataMatrix);
    }

    /*
        Transformation in the org.example.Cipher that processes the State using a nonlinear byte
        substitution table (S-box) that operates on each of the State bytes independently.
     */
    private byte[] subBytes(byte[] dataBlock) {
        byte[] clearText = new byte[16];
        for (int i = 0; i < 16; i++) {
            clearText[i] = changeSBox(dataBlock[i]);
        }
        return clearText;
    }

    /*
        Transformation in the Inverse org.example.Cipher that is the inverse of SubBytes()
     */
    public byte[] invSubBytes(byte[] dataBlock) {
        byte[] clearText = new byte[16];
        for (int i = 0; i < 16; i++) {
            clearText[i] = invChangeSBox(dataBlock[i]);
        }
        return clearText;
    }

    /*
         Transformation in the org.example.Cipher and Inverse org.example.Cipher in which a Round
         Key is added to the State using an XOR operation.
     */
    public byte[] addRoundKey(byte[] dataBlock, int runda) {
        byte[] temporaryDataBlock = new byte[16];

        int a = 0;
        while((a/4)<4) {
            for(int j = 0; j<4;j++) {
                temporaryDataBlock[a] = (byte) (dataBlock[a] ^ roundKeys[(runda*4)+(a/4)][j]);
                a++;
            }
        }
        return temporaryDataBlock;
    }


    public byte XORFourBytes(byte b1, byte b2, byte b3, byte b4) {
        byte bResult = 0;
        bResult ^= b1;
        bResult ^= b2;
        bResult ^= b3;
        bResult ^= b4;
        return bResult;
    }

    /*
        Galois Fields(2^8)
     */
    public byte GF28(byte firstByte, byte secondByte) {
        int result = 0;
        int firstByteIthByte;
        int secondByteIthByte;
        // Multiplying each of the coefficients of the first polynomial with the coefficient of the second polynomial.
        for (int i = 0; i < 8; i++)
            for (int j = 0; j < 8; j++)
            {
                firstByteIthByte = firstByte & (1 << i); // Picking the ith coefficient from the first number
                secondByteIthByte = secondByte & (1 << j); // Picking the jth coefficient from the second number
                if (firstByteIthByte != 0 && secondByteIthByte != 0) // Multiplying coefficients together. Result 1 if both are different from 0
                {
                    result ^= (1 << (i + j)); // Adds one of degree j+i. It is of degree j+i because when you multiply x^firstByte*x^secondByte you get x^(firstByte+secondByte). We use the xor operation because it is an addition in the field 2^8
                }
            }

        // Long division. We check as long as the number is not in GF(2^8), i.e. it is not between 0 and 255 (a total of 256 values)
        while (result > 0b11111111) {
            int firstOnePosition = 0; // Where is the first execution bit on 1, which is where we could subtract the whole irreducible polynomial
            for (int i = 0; i < 32; i++) { // Finding the position of the first bit.
                if ((result & (1 << i))!= 0) {
                    firstOnePosition = i;
                }
            }
            firstOnePosition -=  8; // We subtract 8, which is the "length" of the irreducible polynomial
            result = result ^ (0b100011011 << firstOnePosition); // We set the irreducible polynomial to this position and subtract it from the given number. Since we are still operating in GF(2^8) subtraction (as well as addition) is XOR
        }
        return (byte) result;
    }


    private byte[] oneDimensionalArray(byte[][] newDataMatrix) {
        byte[] clearText = new byte[16];
        int z = 0;
        for(int i = 0;i < 4; i++) {
            for( int j = 0;j < 4; j++) {
                clearText[z] = newDataMatrix[j][i];
                z++;
            }
        }
        return clearText;
    }

    private byte[][] createColumnMatrix(byte[] dataBlock) {
        byte[][] clearText = new byte[4][4];
        int z = 0;
        for(int i = 0;i < 4; i++) {
            for(int j = 0;j < 4; j++) {
                clearText[j][i] = dataBlock[z];
                z++;
            }
        }
        return clearText;
    }

    byte changeSBox(byte b) {
        byte higherFourBytes = 0, lowerFourBytes = 0;
        higherFourBytes = (byte) ((byte) (b >> 4) & 0x0f);
        lowerFourBytes = (byte) (b & 0x0f);
        return (byte) SBox[higherFourBytes][lowerFourBytes];
    }

    byte invChangeSBox(byte b) {
        byte higherFourBytes = 0, lowerFourBytes = 0;
        higherFourBytes = (byte) ((byte) (b >> 4) & 0x0f);
        lowerFourBytes = (byte) (b & 0x0f);
        return (byte) invSBox[higherFourBytes][lowerFourBytes];
    }

    public byte[][] extendKey(byte[] primaryKey) {
        byte[][] extendKey = new byte[44][4];
        int a = 0;
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                extendKey[i][j] = primaryKey[a];
            }
        }
        // Create keys for all 10 rounds
        for(int i = 4; i<=43;i++)
        {
            if(i%4==0) {
                byte[] secondParametr = functionG(extendKey[i-1], i/4);
                extendKey[i] = XOROperation(extendKey[i-4],secondParametr);
            }
            else
                extendKey[i] = XOROperation(extendKey[i-1], extendKey[i-4]);
        }
        return extendKey;
    }

    /*
        The G function, which is ShiftRow,SwapByte and XOR with the round constant Rcon.
     */
    public byte[] functionG(byte[] word, int round) {
        byte first = word[0];
        for (int i = 1; i < 4; i++) {
            word[i-1] = word[i];
        }
        word[3] = first;
        for (int i = 0; i < 4; i++) {
            word[i] = changeSBox(word[i]);
        }
        int Rcon = (byte)Math.pow(2, round-1);
        while (Rcon > 0b11111111) {
            int firstOnePosition = 0;
            for (int i = 0; i < 32; i++) {
                if ((Rcon & (1 << i))!= 0) {
                    firstOnePosition = i;
                }
            }
            firstOnePosition -=  8;
            Rcon = Rcon ^ (0b100011011 << firstOnePosition);
        }
        word[0] ^= (byte) Rcon;

        return word;
    }

    public byte[] XOROperation(byte[] word1, byte[] word2) {
        byte[] resultWord = new byte[4];
        for (int i = 0; i < 4; i++) {
            resultWord[i] = (byte) (word1[i] ^ word2[i]);
        }
        return resultWord;
    }

    /*
        Non-linear substitution table used in several byte substitution
        transformations and in the Key Expansion routine to perform a onefor-one substitution of a byte value.
     */
    public int[][] SBox = {
            {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},
            {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},
            {0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
            {0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},
            {0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
            {0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
            {0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
            {0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
            {0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
            {0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
            {0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
            {0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
            {0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
            {0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
            {0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
            {0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}};

    public int[][] invSBox = new int[][]{
            {0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb},
            {0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb},
            {0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e},
            {0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25},
            {0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92},
            {0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84},
            {0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06},
            {0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b},
            {0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73},
            {0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e},
            {0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b},
            {0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4},
            {0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f},
            {0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef},
            {0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61},
            {0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d}
    };
}
