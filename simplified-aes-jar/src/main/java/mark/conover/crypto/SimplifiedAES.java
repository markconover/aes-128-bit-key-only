package mark.conover.crypto;

public class SimplifiedAES {

    private static final int[] KEY = {0, 1, 1, 1, 1, 1, 1, 1, 0, 1};
    
    public static void main(String[] args) {
        int[] plainText = { 1, 0, 1, 0, 1, 0, 0, 1 };
        
        String ciphertext = SAES_Encrypt(plainText, KEY);
        
        System.out.println("The ciphertext is: " + ciphertext);
    }
    
    private static final String generateStringFromIntArray(int[] tempArray) {
        StringBuilder sb = new StringBuilder();
        sb.append("{");
        for (int i = 0; i < tempArray.length; i++) {
            sb.append(String.valueOf(tempArray[i]));
            if (i != tempArray.length - 1) {
                sb.append(",");
            }
        }
        sb.append("}");
        return sb.toString();
    }
    
    /**
     * Performs a SAES encryption on a single plaintext block.
     * @param plaintext  plain text as bit array.
     * @param key  key as bit array.
     * @return cipher text for the given plain text.
     */
    public static String SAES_Encrypt(int[] plaintext, int[] key) {
        
        // get the key schedule
        
//        (K0, K1, K2) = 
        SAES_KeyExpansion(generateStringFromIntArray(key));
//        
//        state_matrix0 = SAES_ToStateMatrix(plaintext);
//        state_matrix1 = SAES_AddRoundKey(state_matrix0, K0);
//        state_matrix2 = SAES_NibbleSubstitution (state_matrix1);
//        state_matrix3 = SAES_ShiftRow(state_matrix2);
//        state_matrix4 = SAES_MixColumns(state_matrix3);
//        state_matrix5 = SAES_AddRoundKey(state_matrix4, K1);
//        state_matrix6 = SAES_NibbleSubstitution (state_matrix5);
//        state_matrix7 = SAES_ShiftRow(state_matrix6);
//        state_matrix8 = SAES_AddRoundKey(state_matrix7, K2);
//        
//        output = SAES_FromStateMatrix(state_matrix8);
//        
//        return output;
        return null;
    }
    
    /**
     *The keyScheduling algorithm to expand a short key into a number of separate round keys.
     *
     * @param key the key in which key expansion will be computed upon.
     * @return the fully computed expanded key for the AES encryption/decryption.
     */
    public static int[][] SAES_KeyExpansion(String key)
    {

        int binkeysize = key.length() * 4;
        int colsize = binkeysize + 48 - (32 * ((binkeysize / 64) - 2)); //size of key scheduling will be based on the binary size of the key.
        int[][] keyMatrix = new int[4][colsize / 4]; //creates the matrix for key scheduling
        int rconpointer = 1;
        int[] t = new int[4];
        final int keycounter = binkeysize / 32;
        int k;

        for (int i = 0; i < keycounter; i++) //the first 1 (128-bit key) or 2 (256-bit key) set(s) of 4x4 matrices are filled with the key.
        {
            for (int j = 0; j < 4; j++) {
                keyMatrix[j][i] = Integer.parseInt(key.substring((8 * i) + (2 * j), (8 * i) + (2 * j + 2)), 16);
            }
        }
        int keypoint = keycounter;
        while (keypoint < (colsize / 4)) {
            int temp = keypoint % keycounter;
            if (temp == 0) {
                for (k = 0; k < 4; k++) {
                    t[k] = keyMatrix[k][keypoint - 1];
                }
                t = schedule_core(t, rconpointer++);
                for (k = 0; k < 4; k++) {
                    keyMatrix[k][keypoint] = t[k] ^ keyMatrix[k][keypoint - keycounter];
                }
                keypoint++;
            } else if (temp == 4) {
                for (k = 0; k < 4; k++) {
                    int hex = keyMatrix[k][keypoint - 1];
                    keyMatrix[k][keypoint] = sbox[hex / 16][hex % 16] ^ keyMatrix[k][keypoint - keycounter];
                }
                keypoint++;
            } else {
                int ktemp = keypoint + 3;
                while (keypoint < ktemp) {
                    for (k = 0; k < 4; k++) {
                        keyMatrix[k][keypoint] = keyMatrix[k][keypoint - 1] ^ keyMatrix[k][keypoint - keycounter];
                    }
                    keypoint++;
                }
            }
        }
        return keyMatrix;
    }

    // #
    // # These structures are the underlying
    // # Galois Field and corresponding Vector Space
    // # of the field used in the SAES algorithm
    // # These structures allow us to easily compute with these fields.
    // #
    // F = GF(2);
    // L.<a> = GF(2^4);
    // V = L.vector_space();
    // VF8 = VectorSpace(F, 8);
    // ︡49943701-d374-4fad-bbdc-c4bd25cf5155︡︡
    // ︠5b5bec16-a8bb-4873-8242-de4309c7448a︠
    // #
    // # The MixColumns and its Inverse matrices are stored
    // # as 2x2 matrices with elements in GF(2^4) (as are state matrices.)
    // # The MixColumns operation (and its inverse) are performed by
    // # matrix multiplication.
    // #
    // MixColumns_matrix = Matrix(L, [[1,a^2],[a^2,1]]);
    //
    // InverseMixColumns_matrix = MixColumns_matrix.inverse();
    //
    // SBox_matrix = Matrix(L, [ [1 + a^3, a^2, a + a^3, 1 + a + a^3],
    // [1 + a^2 + a^3, 1, a^3, 1 + a^2],
    // [a + a^2, 0, a, 1 + a],
    // [a^2 + a^3, a + a^2 + a^3, 1 + a + a^2 + a^3, 1 + a + a^2] ]);
    // InverseSBox_matrix = Matrix(L, [ [a + a^3, 1 + a^2, 1 + a^3, 1 + a +
    // a^3],
    // [1, 1 + a + a^2, a^3, 1 + a + a^2 + a^3],
    // [a + a^2, 0, a, 1 + a],
    // [a^2 + a^3, a^2, 1 + a^2 + a^3, a + a^2 + a^3] ]);
    // RCON = [ VF8([F(0), F(0), F(0), F(0), F(0), F(0), F(0), F(1)]),
    // VF8([F(0), F(0), F(0), F(0), F(1), F(1), F(0), F(0)]) ];
    // ︡47aa598e-96c6-471f-9c3c-6cd34ec20cd0︡︡
    // ︠3e395858-eb2e-480d-aa5d-85baf115b7b3︠
    // def SAES_ToStateMatrix(block):
    // r"""
    // Converts a bit list into an SAES state matrix.
    // """
    // B = block;
    // # form the plaintext block into a matrix of GF(2^n) elements
    // S00 = L(V([B[0], B[1], B[2], B[3]]));
    // S01 = L(V([B[4], B[5], B[6], B[7]]));
    // S10 = L(V([B[8], B[9], B[10], B[11]]));
    // S11 = L(V([B[12], B[13], B[14], B[15]]));
    // state_matrix = Matrix(L, [[S00,S01],[S10,S11]]);
    // return state_matrix;
    // ︡daa77ca9-fd07-427c-a8da-5261e98aa90f︡︡
    // ︠ba0269a0-30c8-4590-a25a-525c8ce14a69︠
    // def SAES_FromStateMatrix(state_matrix):
    // r"""
    // Converts an SAES State Matrix to a bit list.
    // """
    // output = [];
    // # convert state_matrix back into bit list
    // for r in xrange(2):
    // for c in xrange(2):
    // v = V(state_matrix[r,c]);
    // for j in xrange(4):
    // output.append(Integer(v[j]));
    // return output;
    // ︡7053a251-ba91-4f53-91e9-cba130405b09︡︡
    // ︠32434b3b-838a-49b1-a9fd-0b61b84a43e1︠
    // def SAES_AddRoundKey(state_matrix, K):
    // r"""
    // Adds a round key to an SAES state matrix.
    // """
    // K_matrix = SAES_ToStateMatrix(K);
    // next_state_matrix = K_matrix + state_matrix;
    // return next_state_matrix;
    // ︡3d0b45b2-4d4e-4700-9b07-f202c99bdda5︡︡
    // ︠5f640399-753b-46ee-b109-21e00ba32179︠
    // def SAES_MixColumns(state_matrix):
    // r"""
    // Performs the Mix Columns operation.
    // """
    // next_state_matrix = MixColumns_matrix*state_matrix;
    // return next_state_matrix;
    // ︡1b6267ab-a961-4a9c-af1e-2682bba2db99︡︡
    // ︠08bf0b69-fc8f-4806-a920-8ca67e0175a1︠
    // def SAES_InverseMixColumns(state_matrix):
    // r"""
    // Performs the Inverse Mix Columns operation.
    // """
    // next_state_matrix = InverseMixColumns_matrix*state_matrix;
    // return next_state_matrix;
    // ︡3106db20-8045-48af-a99d-89bc500632ac︡︡
    // ︠c612255d-0a81-4aa6-8168-1ca11e702140︠
    // def SAES_ShiftRow(state_matrix):
    // r"""
    // Performs the Shift Row operation.
    // """
    // M = state_matrix;
    // next_state_matrix = Matrix(L, [ [M[0,0], M[0,1]], [M[1,1], M[1,0]] ]);
    // return next_state_matrix;
    // ︡b65f2926-5d42-4355-8a64-2f990c5e9411︡︡
    // ︠75d96df7-c53b-4ea1-bf03-49772e56c4fa︠
    // def SAES_SBox(nibble):
    // r"""
    // Performs the SAES SBox look up in the SBox matrix (lookup table.)
    // """
    // v = nibble._vector_();
    // c = Integer(v[0]) + 2*Integer(v[1]);
    // r = Integer(v[2]) + 2*Integer(v[3]);
    // return SBox_matrix[r,c];
    // ︡f04355d5-6cb8-465d-961e-f3d2a09e6d1a︡︡
    // ︠69db0e48-7417-419b-840f-4336e8c720b4︠
    // def SAES_NibbleSubstitution(state_matrix):
    // r"""
    // Performs the SAES SBox on each element of an SAES state matrix.
    // """
    // M = state_matrix;
    // next_state_matrix = Matrix(L, [ [SAES_SBox(M[0,0]), SAES_SBox(M[0,1])],
    // [SAES_SBox(M[1,0]), SAES_SBox(M[1,1])] ]);
    // return next_state_matrix;
    // ︡077046a7-f117-4b8a-b551-14fa44f0490a︡︡
    // ︠69237521-7f8e-4bfd-919a-817a8f8b0d5a︠
    // def SAES_InvSBox(nibble):
    // r"""
    // Performs the SAES Inverse SBox look up in the SBox matrix (lookup table.)
    // """
    // v = nibble._vector_();
    // c = Integer(v[0]) + 2*Integer(v[1]);
    // r = Integer(v[2]) + 2*Integer(v[3]);
    // return InverseSBox_matrix[r,c];
    // ︡0cc64f02-14b1-4b38-99d2-c75d184a42f7︡︡
    // ︠94d25f1e-57ab-45c8-b4ce-99bdd10d2b9f︠
    // def SAES_InvNibbleSub(state_matrix):
    // r"""
    // Performs the SAES Inverse SBox on each element of an SAES state matrix.
    // """
    // M = state_matrix;
    // next_state_matrix = Matrix(L, [ [SAES_InvSBox(M[0,0]),
    // SAES_InvSBox(M[0,1])],
    // [SAES_InvSBox(M[1,0]), SAES_InvSBox(M[1,1])] ]);
    // return next_state_matrix;
    // ︡b605a928-0d76-4097-ae00-74dacfa896fa︡︡
    // ︠908a169c-ef18-4a1e-b1c1-3a12f54698b6︠
    // def RotNib(w):
    // r"""
    // Splits an 8 bit list into two elements of GF(2^4)
    // """
    // N_0 = L(V([w[j] for j in xrange(4)]));
    // N_1 = L(V([w[j] for j in xrange(4,8)]));
    // return (N_1, N_0);
    // ︡a18eaa5a-1d1e-406e-bafb-d1536786dcc4︡︡
    // ︠e885e7f8-5cf3-4e32-8320-fcbb316b09e2︠
    // def SAES_g(w, i):
    // r"""
    // Performs the SAES g function on the 8 bit list w.
    // """
    // (N0, N1) = RotNib(w);
    // N0 = V(SAES_SBox(N0));
    // N1 = V(SAES_SBox(N1));
    // temp1 = VF8( [ N0[0], N0[1], N0[2], N0[3], N1[0], N1[1], N1[2], N1[3] ]
    // );
    // output = temp1 + RCON[i];
    // return output;
    // ︡d0a9481b-996c-4149-9498-c4b329230b44︡︡
    // ︠10c09db7-c784-43d8-abc3-17e48975de9b︠
    // def SAES_KeyExpansion(K):
    // r"""
    // Expands an SAES key into two round keys.
    // """
    // w0 = VF8([K[j] for j in xrange(8)]);
    // w1 = VF8([K[j] for j in xrange(8,16)]);
    // w2 = w0 + SAES_g(w1, 0); w3 = w1 + w2;
    // w4 = w2 + SAES_g(w3, 1); w5 = w3 + w4;
    //
    // K0 = [w0[j] for j in xrange(8)];
    // K0.extend([w1[j] for j in xrange(8)]);
    //
    // K1 = [w2[j] for j in xrange(8)];
    // K1.extend([w3[j] for j in xrange(8)]);
    //
    // K2 = [w4[j] for j in xrange(8)];
    // K2.extend([w4[j] for j in xrange(8)]);
    // return (K0, K1, K2);
    // ︡7ebc71f6-447b-4189-8235-d4590000a269︡︡
    // ︠318da01a-d283-4bd0-a717-a641e39184b5︠
    // #
    // # Encrypts one plaintext block with key K
    // #
    // def SAES_Encrypt(plaintext, K):
    // r"""
    // Performs a SAES encryption on a single plaintext block. (Both block and
    // key passed as bit lists.)
    // """
    //
    // # get the key schedule
    // (K0, K1, K2) = SAES_KeyExpansion(K);
    //
    // state_matrix0 = SAES_ToStateMatrix(plaintext);
    // state_matrix1 = SAES_AddRoundKey(state_matrix0, K0);
    // state_matrix2 = SAES_NibbleSubstitution (state_matrix1);
    // state_matrix3 = SAES_ShiftRow(state_matrix2);
    // state_matrix4 = SAES_MixColumns(state_matrix3);
    // state_matrix5 = SAES_AddRoundKey(state_matrix4, K1);
    // state_matrix6 = SAES_NibbleSubstitution (state_matrix5);
    // state_matrix7 = SAES_ShiftRow(state_matrix6);
    // state_matrix8 = SAES_AddRoundKey(state_matrix7, K2);
    //
    // output = SAES_FromStateMatrix(state_matrix8);
    //
    // return output;
    // ︡3c1d032f-ab51-453a-9732-fe5568fc8d22︡︡
    // ︠45aaf45b-7988-4482-9680-73ace88302d6︠
    // #
    // # Decrypts one ciphertext block with key K
    // #
    // def SAES_Decrypt(ciphertext, K):
    // r"""
    // Performs a single SAES decryption operation on a ciphertext block.
    // (Both block and key passed as bit lists.)
    // """
    //
    // # perform key expansion
    // (K0, K1, K2) = SAES_KeyExpansion(K);
    //
    // # form the ciphertext block into a matrix of GF(2^n) elements
    // state_matrix0 = SAES_ToStateMatrix(ciphertext);
    // state_matrix1 = SAES_AddRoundKey(state_matrix0, K2);
    // state_matrix2 = SAES_ShiftRow(state_matrix1);
    // state_matrix3 = SAES_InvNibbleSub(state_matrix2);
    // state_matrix4 = SAES_AddRoundKey(state_matrix3, K1);
    // state_matrix5 = SAES_InverseMixColumns (state_matrix4);
    // state_matrix6 = SAES_ShiftRow(state_matrix5);
    // state_matrix7 = SAES_InvNibbleSub(state_matrix6);
    // state_matrix8 = SAES_AddRoundKey(state_matrix7, K0);
    //
    // output = SAES_FromStateMatrix(state_matrix8);
    //
    // return output;
}
