package enwei;

import java.security.InvalidKeyException;
import java.security.Key;

import javax.crypto.Cipher;

public class Security {
	private Cipher RSAcipher;
	private Cipher DEScipher;

	public Security() throws IllegalArgumentException {
		try {
			RSAcipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		} catch (Exception e) {
			e.printStackTrace();
			System.err.println("RSA Cipher setup error");
			System.exit(0);
		}
		try {
			DEScipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
		} catch (Exception e) {
			e.printStackTrace();
			System.err.println("DES Cipher setup error");
			System.exit(0);
		}
		
	}

	public byte[] encrypt(byte[] plaintext, Key k, String format) throws IllegalArgumentException {
		byte[] ciphertext = null;
		if (format == "RSA"){
			try {
				RSAcipher.init(Cipher.ENCRYPT_MODE, k);
			} catch (InvalidKeyException e) {
				e.printStackTrace();
				System.err.println("RSA key invalid.");
			}
			try {
				ciphertext = RSAcipher.doFinal(plaintext);
			} catch (Exception e) {
				e.printStackTrace();
				System.err.println("Unable to encrypt.");
			}
		}
		else if (format == "DES"){
			try {
				DEScipher.init(Cipher.ENCRYPT_MODE, k);
			} catch (InvalidKeyException e) {
				e.printStackTrace();
				System.err.println("DES key invalid.");
			}
			try {
				ciphertext = DEScipher.doFinal(plaintext);
			} catch (Exception e) {
				e.printStackTrace();
				System.err.println("Unable to encrypt.");
			}
		}
		else{
			throw new IllegalArgumentException();
		}
		return ciphertext;
	}

	public byte[] decrypt(byte[] ciphertext, Key k, String format) throws IllegalArgumentException {
		byte[] plaintext = null;
		if (format == "RSA"){
			try {
				RSAcipher.init(Cipher.DECRYPT_MODE, k);
			} catch (InvalidKeyException e) {
				e.printStackTrace();
				System.err.println("RSA key invalid.");
			}
			try {
				plaintext = RSAcipher.doFinal(ciphertext);
			} catch (Exception e) {
				e.printStackTrace();
				System.err.println("Unable to decrypt.");
			}
		}
		else if (format == "DES"){
			try {
				DEScipher.init(Cipher.DECRYPT_MODE, k);
			} catch (InvalidKeyException e) {
				e.printStackTrace();
				System.err.println("DES key invalid.");
			}
			try {
				plaintext = DEScipher.doFinal(ciphertext);
			} catch (Exception e) {
				e.printStackTrace();
				System.err.println("Unable to decrypt.");
			}
		}
		else{
			throw new IllegalArgumentException();
		}
		return plaintext;
	}
}
