package xyz.kmahyyg.htb_mr3m;

//
// htb_mr3m_decoder
// Copyright (C) 2019  kmahyyg
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
//

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.generators.*;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.crypto.engines.*;
import org.bouncycastle.crypto.modes.*;

import java.nio.charset.Charset;
import java.util.Arrays;

public class Main {

    private static int KeyBitSize = 128;
    private static int SaltBitSize = 128;
    private static int NonceBitSize = 128;

    private static int MacBitSize = 128;
    private static int KeyDerivationIters = 1000;
    private static int Pkcs5S2KeyBitSize = 256;

    private static String DefaultPassword = "mR3m";

    public static void main(String[] args) {
        String encrypted_b64 = "";
        String decrypt_password = "";
        try {
            encrypted_b64 = args[0];
            System.out.println("User Input: " + encrypted_b64);
        }
        catch (Exception e){
            e.printStackTrace();
            System.out.println("Encrypted string not found. Exit.");
            System.out.println("Usage: htb_mr3m.jar <Base64-Encoded AES-128-GCM String Here> [Password user defined]");
            System.exit(1);
        }
        try {
            decrypt_password = args[1];
        } catch (ArrayIndexOutOfBoundsException e){
            decrypt_password = DefaultPassword;
            System.out.println("Use default password for cracking...");
        }

        byte[] encrypted = Base64.decodeBase64(encrypted_b64);
        byte[] b_salt = Arrays.copyOfRange(encrypted, 0,16);
        byte[] b_associatedText = Arrays.copyOfRange(encrypted, 0,16);
        byte[] b_nonce = Arrays.copyOfRange(encrypted,16,32);
        byte[] b_ciphertext = Arrays.copyOfRange(encrypted,32, encrypted.length);

        byte[] b_password = dvKeyGen(decrypt_password, b_salt);
        byte[] b_decrypted = decryptAEADgcm(b_password, b_nonce, b_ciphertext, b_associatedText);

        String sfPlain = "";
        sfPlain = new String(b_decrypted, Charset.forName("UTF-8"));
        System.out.println("Decrypted Output: " + sfPlain);
    }

    public static byte[] dvKeyGen(String password, byte[] salt){
        byte[] b_pwd = password.getBytes(Charset.forName("UTF-8"));
        // PBKDF2-SHA1-HMAC
        PKCS5S2ParametersGenerator pbkdf2gen = new PKCS5S2ParametersGenerator();
        pbkdf2gen.init(b_pwd, salt, KeyDerivationIters);
        byte[] derivedKey = ((KeyParameter) pbkdf2gen.generateDerivedMacParameters(Pkcs5S2KeyBitSize)).getKey();
        return derivedKey;
    }

    public static byte[] decryptAEADgcm(byte[] password, byte[] nonce, byte[] cipherText, byte[]associatedText){
        KeyParameter pwdparam = new KeyParameter(password);
        AEADParameters aeadpm = new AEADParameters(pwdparam, MacBitSize, nonce, associatedText);
        GCMBlockCipher gcmcipher = new GCMBlockCipher(new AESEngine());
        gcmcipher.init(false, aeadpm);
        byte[] plainBytes = new byte[gcmcipher.getOutputSize(cipherText.length)];
        int retLen = gcmcipher.processBytes(cipherText, 0, cipherText.length, plainBytes,0);
        try {
            gcmcipher.doFinal(plainBytes, retLen);
        } catch (InvalidCipherTextException e) {
            e.printStackTrace();
            System.out.println("\n Error Occured While Trying to Decrypt the AES-128-GCM. \n");
            System.exit(2);
        }
        return plainBytes;
    }
}
