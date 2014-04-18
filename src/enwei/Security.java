package enwei;

import java.nio.ByteBuffer;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;

public class Security {
	private Cipher cipher;

	private ByteBuffer byteBuffer;
	private byte[] byteArray, keyPlainText, keyCipherText, msgPlainText,
			msgCipherText;

	public Security() throws IllegalArgumentException {
		try {
			cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		} catch (Exception e) {
			e.printStackTrace();
			System.err.println("RSA Cipher setup error");
			System.exit(0);
		}
		
	}

	public void encrypt(byte[] plaintext) {
		if (algorithm == "RSA") {

		} else if (algorithm == "DES") {

		}

	}

	public void decrypt(byte[] ciphertext) {
		if (algorithm == "RSA") {

		} else if (algorithm == "DES") {

		}

	}
}
