package weilong;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer; //Byte Buffer
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
//convert data type of public key
//Base64 encoding

public class TestServer {

	public static void main(String[] args) throws Exception {
		final int port = 3344;
		ServerSocket server = null;
		Socket client = null;

		final int RSAKeySize = 1024;
		PublicKey pubKey = null;
		PrivateKey priKey = null;
		Key clientPubKey = null;

		String serverText = "password";
		byte[] plainText = serverText.getBytes("UTF8");
		byte[] nonce = generateNonce();
		byte[] clientNonce;
		byte[] firtHalf;
		byte[] secondHalf;
		
		ObjectOutputStream obOut = null;
		ObjectInputStream obIn = null;

		//Connection
		try {

			server = new ServerSocket(port);
			System.out.println("Server is waiting for client on port "
					+ server.getLocalPort());
			client = server.accept();
			obOut = new ObjectOutputStream(
					client.getOutputStream());
			obIn = new ObjectInputStream(client.getInputStream());
			System.out.println("TCP connection is established now");

		} catch (Exception e) {
			e.printStackTrace();
		}

		//Generation of public key
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
		
		//Send nonce to client
		obOut.writeObject(new String(nonce));
		obOut.flush();
		
		//Receive nonce from client
		String nonceString= (String)obIn.readObject();
		clientNonce = nonceString.getBytes();
		
		//send public key to client
		try {
			System.out.println("Send public key to client:\n"); 
			ByteBuffer bb = ByteBuffer.allocate(4);
			bb.putInt(pubKey.getEncoded().length);
			client.getOutputStream().write(bb.array());
			client.getOutputStream().write(pubKey.getEncoded());
			client.getOutputStream().flush();
		} catch (Exception e) {
			e.printStackTrace();
		}

		// Get public key from client
		try {

			byte[] lenb = new byte[4];
			client.getInputStream().read(lenb, 0, 4);
			ByteBuffer bb = ByteBuffer.wrap(lenb);
			int len = bb.getInt();
			System.out.println("Length of the public key: " + len);

			byte[] cPubKeyBytes = new byte[len];
			client.getInputStream().read(cPubKeyBytes);

			X509EncodedKeySpec ks = new X509EncodedKeySpec(cPubKeyBytes);
			KeyFactory kf = KeyFactory.getInstance("RSA");
			clientPubKey = kf.generatePublic(ks);

		} catch (Exception e) {
			e.printStackTrace();
		}

		//combine nonce and password and break in between
		byte[] newText = combineNonce(clientNonce, plainText);
		String newString = new String(newText);
		firtHalf = newString.substring(0, newString.length()/2).getBytes();
		secondHalf = newString.substring(newString.length()/2).getBytes();
		
		
		//Encrypt the message
		System.out.println("Start Encryption for plainText");

		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.ENCRYPT_MODE, clientPubKey);
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

		//Decode message from server
		byte[] decoFirst = new BASE64Decoder().decodeBuffer(first);
		byte[] decoSec = new BASE64Decoder().decodeBuffer(second);
		//System.out.println("Base64 Decoded:\n" + new String(deco, "UTF8"));

		System.out.println("Start decryption");
		Cipher priCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		priCipher.init(Cipher.DECRYPT_MODE, priKey);
		byte[] newPlainTextFirst = priCipher.doFinal(decoFirst);
		byte[] newPlainTextSec = priCipher.doFinal(decoSec);
		
		String finalDeco = new String(newPlainTextFirst, "UTF8") + new String(newPlainTextSec, "UTF8");
		if (finalDeco.contains(serverText)) {
			verificationSucceed();
		} else {
			verificationFail();
		}
		
		System.out.println("Finish decryption:\n" + new String(newPlainTextFirst, "UTF8") + new String(newPlainTextSec, "UTF8"));

		client.close();
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
