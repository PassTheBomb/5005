package enwei;

import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;

public class Keys {
	private final int RSAKeySize = 1024;
	private KeyPairGenerator RSAKeyGen;
	private KeyGenerator DESkeyGen;
	
	private KeyPair serverKeyPair;
	private PublicKey serverPubKey;
	private PrivateKey serverPrivKey;
	private Key DESkey;

	private KeyFactory kf;
	private X509EncodedKeySpec ks;
	
	private final SecureRandom random = new SecureRandom();

	public Keys() {
		try {
			RSAKeyGen = KeyPairGenerator.getInstance("RSA");
		} catch (Exception e) {
			e.printStackTrace();
			System.err.println("RSAKeyGen setup error");
			System.exit(0);
		}
		try {
			DESkeyGen = KeyGenerator.getInstance("DES");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			System.err.println("DESKeyGen setup error.");
			System.exit(0);
		}
		try {
			kf = KeyFactory.getInstance("RSA");
		} catch (Exception e) {
			e.printStackTrace();
			System.err.println("Unable to setup Key Factory");
			System.exit(0);
		}
	}

	public void generateRSAKeyPair() {
		RSAKeyGen.initialize(RSAKeySize, random);
		serverKeyPair = RSAKeyGen.generateKeyPair();
		serverPubKey = serverKeyPair.getPublic();
		serverPrivKey = serverKeyPair.getPrivate();
	}

	public void generateDESKeyPair() {
		DESkeyGen.init(56, random);
		DESkey = DESkeyGen.generateKey();
	}
	
	public void setRSAKeyPair(KeyPair kp) {
		this.serverKeyPair=kp;
		serverPubKey = serverKeyPair.getPublic();
		serverPrivKey = serverKeyPair.getPrivate();
	}

	public void setDESKey(Key k) {
		this.DESkey = k;
	}
	

	public PublicKey getRSAPubKey() {
		return serverPubKey;
	}

	public PrivateKey getRSAPrivKey() {
		return serverPrivKey;
	}

	public Key getDESKey() {
		return DESkey;
	}
	
	public PublicKey PublicKeyFromByteCode(byte[] encodedKey) throws InvalidKeySpecException{
		ks = new X509EncodedKeySpec(encodedKey);
		return kf.generatePublic(ks);
	}
	
	public Key DESKeyFromByteCode(byte[] encodedKey){
		return new SecretKeySpec(encodedKey, 0, encodedKey.length, "DES");
	}
}
