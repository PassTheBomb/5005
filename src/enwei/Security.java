package enwei;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;

/**
 * A class containing RSA and DES ciphers, and methods that uses these ciphers
 * to encrypt and decrypt byte arrays
 * 
 */
public class Security {
	private Cipher RSAcipher;
	private Cipher DEScipher;
	private MessageDigest messageDigest;

	/**
	 * Instantiates the Security class with the RSA and DES ciphers
	 */
	public Security() {
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
		try {
			messageDigest = MessageDigest.getInstance("MD5");
		} catch (NoSuchAlgorithmException e) {
			System.err.println("MD5 message digest setup error");
			e.printStackTrace();
			System.exit(0);
		}

	}

	/**
	 * encrypts an input plaintext byte array into a ciphertext using key k with
	 * either RSA or DES format
	 * 
	 * @param plaintext
	 *            input plaintext byte array
	 * @param k
	 *            the key to be used
	 * @param format
	 *            either "RSA" or "DES". The algorithm chosen must match the key
	 *            used
	 * @return
	 * @throws IllegalArgumentException
	 *             if the format input is not "RSA" or "DES"
	 */
	public byte[] encrypt(byte[] plaintext, Key k, String format)
			throws IllegalArgumentException {
		byte[] ciphertext = null;
		if (format == "RSA") {
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
		} else if (format == "DES") {
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
		} else {
			throw new IllegalArgumentException();
		}
		return ciphertext;
	}

	/**
	 * decrypts an input ciphertext byte array into a plaintext using key k with
	 * either RSA or DES format
	 * 
	 * @param cipher
	 *            input plaintext byte array
	 * @param k
	 *            the key to be used
	 * @param format
	 *            either "RSA" or "DES". The algorithm chosen must match the key
	 *            used
	 * @return
	 * @throws IllegalArgumentException
	 *             if the format input is not "RSA" or "DES"
	 */
	public byte[] decrypt(byte[] ciphertext, Key k, String format)
			throws IllegalArgumentException {
		byte[] plaintext = null;
		if (format == "RSA") {
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
		} else if (format == "DES") {
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
		} else {
			throw new IllegalArgumentException();
		}
		return plaintext;
	}

	/**
	 * Creates a MD5 digest of the input byte-code
	 * 
	 * @param byteArrayInput
	 *            input byte-code to apply the MD5 digest on
	 * @return the byte-code format MD5 digest of the input byte-code
	 */
	public byte[] MD5Digest(byte[] byteArrayInput) {
		return messageDigest.digest(byteArrayInput);
	}
}
