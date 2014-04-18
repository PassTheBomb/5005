package weilong;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.InetAddress;
import java.net.Socket; //creating socket
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
import java.util.Random;

import javax.crypto.Cipher;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

public class TestClient {

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		// set variables for port, socket
		final int port = 3344;
		Socket sock = null;
		// set variables for RSAKeySize, public key, private key
		final int RSAKeySize = 1024;
		PublicKey pubKey = null;
		PrivateKey priKey = null;
		Key serverPubKey = null;
		
		String text = "password";
		byte[] plainText = text.getBytes();
		byte[] nonce = generateNonce();
		byte[] serverNonce = null;
		byte[] firtHalf;
		byte[] secondHalf;
		
		ObjectOutputStream obOut = null;
		ObjectInputStream obIn = null;
		
		//Connecting
		try {
			System.out.println("Client is now establishing connection.");
			sock = new Socket(InetAddress.getLocalHost(), port);
			obOut = new ObjectOutputStream(
					sock.getOutputStream());
			obIn = new ObjectInputStream(sock.getInputStream());
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		
		try {
			//Send nonce to server
			obOut.writeObject(new String(nonce));
			obOut.flush();
			
			//Receive nonce from server
			String nonceString= (String)obIn.readObject();
			serverNonce = nonceString.getBytes();
			
		} catch (IOException e1) {
			e1.printStackTrace();
		} catch (ClassNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		
		//Generate public key
		try {
			System.out.println("Start generating RSA key:");
			KeyPairGenerator RSAKeyGen = KeyPairGenerator.getInstance("RSA");
			SecureRandom random = new SecureRandom();
			RSAKeyGen.initialize(RSAKeySize, random);
			KeyPair pair = RSAKeyGen.generateKeyPair();
			pubKey = pair.getPublic();
			priKey = pair.getPrivate();
			System.out.println("Finish generating RSA key");
		} catch (Exception e) {
			e.printStackTrace();
		}

		
		try {
			//Send public key to server
			System.out.println("Send client public key to server:\n");
			ByteBuffer bb = ByteBuffer.allocate(4);
			bb.putInt(pubKey.getEncoded().length);
			sock.getOutputStream().write(bb.array());
			sock.getOutputStream().write(pubKey.getEncoded());
			sock.getOutputStream().flush();
			
			//Get server's public key
			byte[] lenb = new byte[4];
			sock.getInputStream().read(lenb, 0, 4);
			ByteBuffer inbb = ByteBuffer.wrap(lenb);
			int len = inbb.getInt();
			System.out.println("Length of the public key: " + len);
			
			byte[] cPubKeyBytes = new byte[len];
			sock.getInputStream().read(cPubKeyBytes);
			System.out.println("Public Key:\n");

			X509EncodedKeySpec ks = new X509EncodedKeySpec(cPubKeyBytes);
			KeyFactory kf = KeyFactory.getInstance("RSA");
			serverPubKey = kf.generatePublic(ks);
			System.out.println("Encoded Public Key:\n");
			
			//combine nonce and password and break in between
			byte[] newText = combineNonce(serverNonce, plainText);
			String newString = new String(newText);
			firtHalf = newString.substring(0, newString.length()/2).getBytes();
			secondHalf = newString.substring(newString.length()/2).getBytes();
			
			
			//Encrypt the message
			System.out.println("Start Encryption for plainText");

			Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			cipher.init(Cipher.ENCRYPT_MODE, serverPubKey);
			byte[] cipherFirst = cipher.doFinal(firtHalf);
			byte[] cipherSecond = cipher.doFinal(secondHalf);

			System.out.println("Finish Encryption to cipherText:\n"); 
			
			BASE64Encoder base64 = new BASE64Encoder();
			String encryptedFirst = base64.encode(cipherFirst);
			String encryptedSecond = base64.encode(cipherSecond);
			System.out.println("Base64 Encoded:\n"); // + encryptedValue);
			
			//Send the first half encrypted message
			obOut.writeObject(encryptedFirst);
			obOut.flush();
			
			//receive the first half from server
			String first = (String)obIn.readObject();
			
			//Send the second half
			obOut.writeObject(encryptedSecond);
			obOut.flush();

			//Receive message from servers
			String second = (String)obIn.readObject();
			System.out.println("Receive from server:\n");

			//String received = first+second;
			
			//Decode message from server
			byte[] decoFirst = new BASE64Decoder().decodeBuffer(first);
			byte[] decoSec = new BASE64Decoder().decodeBuffer(second);

			System.out.println("Start decryption");
			Cipher priCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			priCipher.init(Cipher.DECRYPT_MODE, priKey);
			byte[] newPlainTextFirst = priCipher.doFinal(decoFirst);
			byte[] newPlainTextSec = priCipher.doFinal(decoSec);
			
			String finalDeco = new String(newPlainTextFirst) + new String(newPlainTextSec);
			
			System.out.println("Finish decryption:\n" + finalDeco);
			
			if (finalDeco.toLowerCase().contains(text.toLowerCase())) {
				verificationSucceed();
			} else {
				verificationFail();
			}
			
			sock.close();

		} catch (Exception e) {
			e.printStackTrace();
		}

	}
	

	public static void verificationSucceed() {
		System.out.println("Server succeed");
	}
	
	public static void verificationFail() {
		System.out.println("Server fail");
	}
	
	public static byte[] generateNonce() {
		byte[] nonce = new byte[16];
		Random rand;
		try {
			rand = SecureRandom.getInstance("SHA1PRNG");
			rand.nextBytes(nonce);
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return nonce; 
	}
	
	public static byte[] combineNonce(byte[] nonce, byte[] plainText) throws IOException {
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
		outputStream.write( nonce );
		outputStream.write( plainText );
		byte combineText[] = outputStream.toByteArray( );
		return combineText;
	}
	
	

}
