package enwei;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
//creating socket
//Byte Buffer
//Base64 decoding
//convert data type of public key

public class EncryptionTestClient {
	private static Socket sock;
	private final static int port = 3344;
	private final static String hostIP = "localhost";

	private static OutputStream out;
	private static InputStream in;

	private final static SecureRandom random = new SecureRandom();
	private static Cipher cipher;

	private final static int RSAKeySize = 1024;
	private static KeyPairGenerator RSAKeyGen;
	private static KeyPair clientKeyPair;
	private static PublicKey serverPubKey, clientPubKey;
	private static PrivateKey clientPrivKey;
	private static Key DESkey;
	private static KeyFactory kf;
	private static X509EncodedKeySpec ks;

	private static ByteBuffer byteBuffer;
	private static byte[] byteArray, keyPlainText, keyCipherText, msgPlainText,
			msgCipherText;
	private static int bufferLen;

	public static void main(String[] args) {
		try {
			cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		} catch (Exception e) {
			e.printStackTrace();
			System.err.println("RSA Cipher setup error");
			System.exit(0);
		}
		try {
			RSAKeyGen = KeyPairGenerator.getInstance("RSA");
		} catch (Exception e) {
			e.printStackTrace();
			System.err.println("RSAKeyGen setup error");
			System.exit(0);
		}
		// Step A1: Generate RSA Keypair
		RSAKeyGen.initialize(RSAKeySize, random);
		clientKeyPair = RSAKeyGen.generateKeyPair();
		clientPubKey = clientKeyPair.getPublic();
		clientPrivKey = clientKeyPair.getPrivate();

		// Step A2: Connect to server
		try {
			sock = new Socket(hostIP, port);
		} catch (UnknownHostException e) {
			e.printStackTrace();
			System.err.println("Host " + hostIP + " not found.");
			System.exit(0);
		} catch (IOException e) {
			e.printStackTrace();
			System.err.println("Unable to connect to port " + port
					+ " on host " + hostIP + ".");
			System.exit(0);
		}
		try {
			in = sock.getInputStream();
			out = sock.getOutputStream();
		} catch (IOException e) {
			e.printStackTrace();
			System.err.println("Unable to setup IO.");
			System.exit(0);
		}

		// Step A3: Acquire RSA pubkey from server
		byteArray = new byte[4];
		try {
			in.read(byteArray, 0, 4);
		} catch (IOException e) {
			e.printStackTrace();
			System.err.println("No key length provided");
			System.exit(0);
		}
		bufferLen = ByteBuffer.wrap(byteArray).getInt();
		byteArray = new byte[bufferLen];
		try {
			in.read(byteArray);
		} catch (IOException e) {
			e.printStackTrace();
			System.err.println("No public key provided");
			System.exit(0);
		}
		ks = new X509EncodedKeySpec(byteArray);
		try {
			kf = KeyFactory.getInstance("RSA");
		} catch (Exception e) {
			e.printStackTrace();
			System.err.println("Unable to setup Key Factory");
			System.exit(0);
		}
		try {
			serverPubKey = kf.generatePublic(ks);
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
			System.err.println("Key provided is invalid");
			System.exit(0);
		}

		// Step A4: Send RSA pubkey to server
		byteArray = clientPubKey.getEncoded();
		byteBuffer = ByteBuffer.allocate(4 + serverPubKey.getEncoded().length);
		byteBuffer.putInt(serverPubKey.getEncoded().length);
		byteBuffer.put(byteArray);
		try {
			out.write(byteBuffer.array());
			out.flush();
		} catch (IOException e) {
			e.printStackTrace();
			System.err.println("Unable to send  public key");
		}
		byteBuffer.clear();

		// --------------------------------------------------------------------
		// -Base Condition Established, P and G owns each other's RSA a priori-
		// --------------------------------------------------------------------
		// Step B1: Wait for ciphertext from server, split into ciphertext for
		// msg and key
		byteArray = new byte[4];
		try {
			in.read(byteArray);
		} catch (IOException e) {
			e.printStackTrace();
			System.err.println("No encrypted verification msg length provided");
			System.exit(0);
		}
		bufferLen = ByteBuffer.wrap(byteArray).getInt();
		msgCipherText = new byte[bufferLen];
		try {
			in.read(msgCipherText);
		} catch (IOException e) {
			e.printStackTrace();
			System.err.println("No verification msg provided");
			System.exit(0);
		}
		try {
			in.read(byteArray);
		} catch (IOException e) {
			e.printStackTrace();
			System.err.println("No encrypted symmetric key length provided");
			System.exit(0);
		}
		bufferLen = ByteBuffer.wrap(byteArray).getInt();
		keyCipherText = new byte[bufferLen];
		try {
			in.read(keyCipherText);
		} catch (IOException e) {
			e.printStackTrace();
			System.err.println("No symmetric key provided");
			System.exit(0);
		}

		// Step B2: decrypt ciphertext using client privkey
		// K_pr_g(v) = K_pr_c(K_pu_c(K_pr_g(v))) (authenticity, integrity,
		// confidentiality)
		try {
			cipher.init(Cipher.DECRYPT_MODE, clientPrivKey);
		} catch (InvalidKeyException e) {
			e.printStackTrace();
			System.err
					.println("Invalid key for decryption of symmetric key ciphertext.");
			System.exit(0);
		}
		try {
			keyPlainText = cipher.doFinal(keyCipherText);
		} catch (Exception e) {
			e.printStackTrace();
			System.err.println("Unable to Decrypt.");
			System.exit(0);
		}
		DESkey = new SecretKeySpec(keyPlainText, 0, keyPlainText.length, "DES");

		// Step B3: Decrypt verification message v using symmetric key =
		// K_pu_g(K_pr_g(v)) (authenticity)
		try {
			cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
		} catch (Exception e) {
			e.printStackTrace();
			System.err.println("DES Cipher setup error");
			System.exit(0);
		}
		try {
			cipher.init(Cipher.DECRYPT_MODE, DESkey);
		} catch (InvalidKeyException e) {
			e.printStackTrace();
			System.err
					.println("Invalid symmetric key for decryption of verification msg.");
			System.exit(0);
		}
		try {
			msgPlainText = cipher.doFinal(msgCipherText);
		} catch (Exception e) {
			e.printStackTrace();
			System.err.println("Unable to Decrypt.");
			System.exit(0);
		}

		// Step B4: Decrypt verification message v using server pubkey =
		// K_pu_g(K_pr_g(v)) (authenticity)
		msgCipherText = msgPlainText;
		try {
			cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		} catch (Exception e) {
			e.printStackTrace();
			System.err.println("RSA Cipher setup error");
			System.exit(0);
		}
		try {
			cipher.init(Cipher.DECRYPT_MODE, serverPubKey);
		} catch (InvalidKeyException e) {
			e.printStackTrace();
			System.err
					.println("Invalid symmetric key for decryption of verification msg.");
			System.exit(0);
		}
		try {
			msgPlainText = cipher.doFinal(msgCipherText);
		} catch (Exception e) {
			e.printStackTrace();
			System.err.println("Unable to Decrypt.");
			System.exit(0);
		}
		// Step B6: Encrypt verification message using client private key
		try {
			cipher.init(Cipher.ENCRYPT_MODE, clientPrivKey);
		} catch (InvalidKeyException e) {
			e.printStackTrace();
			System.err
					.println("Invalid key for encryption of verification msg.");
			System.exit(0);
		}
		try {
			msgCipherText = cipher.doFinal(msgPlainText);
		} catch (Exception e) {
			e.printStackTrace();
			System.err.println("Unable to Encrypt.");
			System.exit(0);
		}

		// Step B7: Send ciphertext to server
		byteBuffer = ByteBuffer.allocate(4 + msgCipherText.length);
		byteBuffer.putInt(msgCipherText.length);
		byteBuffer.put(msgCipherText);
		try {
			out.write(byteBuffer.array());
			out.flush();
		} catch (IOException e2) {
			e2.getStackTrace();
			System.err.println("Unable to send ciphertext");
		}
		byteBuffer.clear();

		// -------All messages will be encrypted using K_s from now on---------
		// Step C1: Receive the ciphertext from server
		byteArray = new byte[4];
		try {
			in.read(byteArray);
		} catch (IOException e) {
			e.printStackTrace();
			System.err.println("No encrypted msg length provided");
			System.exit(0);
		}
		bufferLen = ByteBuffer.wrap(byteArray).getInt();
		msgCipherText = new byte[bufferLen];
		try {
			in.read(msgCipherText);
		} catch (IOException e) {
			e.printStackTrace();
			System.err.println("No msg provided");
			System.exit(0);
		}
		
		// Step C2: Decrypt ciphertext from server using symmetric key r =
		// K_s(K_s(r))
		try {
			cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
		} catch (Exception e1) {
			e1.getStackTrace();
			System.err.println("DES Cipher setup error.");
		}
		try {
			cipher.init(Cipher.DECRYPT_MODE, DESkey);
		} catch (InvalidKeyException e) {
			e.printStackTrace();
			System.err.println("Invalid symmetric key for decryption of msg.");
			System.exit(0);
		}
		try {
			msgPlainText = cipher.doFinal(msgCipherText);
		} catch (Exception e) {
			e.printStackTrace();
			System.err.println("Unable to Decrypt.");
			System.exit(0);
		}
		try {
			System.out.println(new String(msgPlainText, "UTF8"));
		} catch (UnsupportedEncodingException e1) {
			System.err.println("UTF-8 format unsupported");
		}
		
		// Step C3: Encrypt sent message s using symmetric key K_s(s)
		
		msgPlainText = "Send Message".getBytes();
		try {
			cipher.init(Cipher.ENCRYPT_MODE, DESkey);
		} catch (InvalidKeyException e) {
			e.printStackTrace();
			System.err.println("DES key invalid.");
			System.exit(0);
		}
		try {
			msgCipherText = cipher.doFinal(msgPlainText);
		} catch (Exception e) {
			e.printStackTrace();
			System.err.println("Unable to encrypt.");
			System.exit(0);
		}
		
		// Step C4: Send the ciphertext to server
		byteBuffer = ByteBuffer.allocate(4 + msgCipherText.length);
		byteBuffer.putInt(msgCipherText.length);
		byteBuffer.put(msgCipherText);
		try {
			out.write(byteBuffer.array());
			out.flush();
		} catch (IOException e2) {
			e2.getStackTrace();
			System.err.println("Unable to send ciphertext");
		}
		byteBuffer.clear();
	}
}
/*
 * //set variables for port, socket final int port = 3344; Socket sock = null;
 * //set variables for RSAKeySize, public key, private key final int RSAKeySize
 * = 1024; PublicKey pubKey = null; PrivateKey priKey = null;
 * 
 * //-----------Part 1 : setup connection by creating socket----------- try{
 * System.out.println("Client is now establishing connection."); sock = new
 * Socket(InetAddress.getLocalHost(),port); }catch(Exception e){
 * e.printStackTrace(); }
 * 
 * //-----------Part 2 : generating RSA key pair for client-------------- try {
 * 
 * 
 * System.out.println("Start generating RSA key");
 * 
 * uses KeyPairGenerator class to return an object with RSA algorithminitialize
 * object with RSA key size and source of random seeduses generateKeyPair method
 * to generate the keysget public key and private key for client
 * 
 * System.out.println("Finish generating RSA key");
 * 
 * 
 * System.out.println("Start generating RSA key"); KeyPairGenerator RSAKeyGen =
 * KeyPairGenerator.getInstance("RSA"); SecureRandom random = new
 * SecureRandom(); RSAKeyGen.initialize(RSAKeySize, random); KeyPair pair =
 * RSAKeyGen.generateKeyPair(); pubKey = pair.getPublic(); priKey =
 * pair.getPrivate(); System.out.println("Finish generating RSA key");
 * 
 * 
 * }catch (Exception e){ e.printStackTrace(); }
 * 
 * //-----------Part 3 : send client public key to server-------------- try{
 * 
 * 
 * prints its public key in string format in a representation of HexBinary
 * System.out.println("Send client public key to server:\n" +
 * DatatypeConverter.printHexBinary(pubKey.getEncoded()));
 * 
 * creates a ByteBuffer by allocating the capacity with 4 bytesstores the length
 * of public key into the bufferuses array method to return a byte array that
 * backs this bufferuses getOutputStream method to return an output stream for
 * writing byte arrayand encoded public key to this socket
 * 
 * flush the OutputStream
 * 
 * 
 * 
 * System.out.println("Send client public key to server");
 * System.out.println(DatatypeConverter.printHexBinary(pubKey.getEncoded()));
 * ByteBuffer bb = ByteBuffer.allocate(4);
 * bb.putInt(pubKey.getEncoded().length);
 * sock.getOutputStream().write(bb.array());
 * sock.getOutputStream().write(pubKey.getEncoded());
 * sock.getOutputStream().flush();
 * 
 * 
 * 
 * //-----------Part 4 : receive message from server-------------------
 * 
 * 
 * use getInputStream method to return an input stream for reading bytes from
 * this socket
 * 
 * reads an object RECEIVE_MESSAGE from the input stream
 * System.out.println("Received from server:\n" + RECEIVE_MESSAGE);
 * 
 * 
 * ObjectInputStream obIn = new ObjectInputStream(sock.getInputStream()); Object
 * obj = obIn.readObject(); System.out.println("Received from server:\n" + obj);
 * 
 * 
 * //----Part 5 : Base64-decoding and Decryption for received message----
 * 
 * 
 * 
 * the RECEIVE_MESSAGE is in format of Base64, decode it into ciphertext
 * 
 * System.out.println("Start decryption");get an RSA cipher objectinitializes
 * the cipher object into decrypt mode and uses private keydecrypts the
 * ciphertextSystem.out.println("Finish decryption:\n" + new
 * String(DECRYPTED_MESSAGE,"UTF8"));
 * 
 * 
 * 
 * byte[] deco = new BASE64Decoder().decodeBuffer((String) obj);
 * System.out.println("Base64 Decoded:\n" + new String(deco,"UTF8"));
 * 
 * System.out.println("Start decryption"); Cipher cipher =
 * Cipher.getInstance("RSA/ECB/PKCS1Padding"); cipher.init(Cipher.DECRYPT_MODE,
 * priKey); byte[] newPlainText = cipher.doFinal(deco);
 * System.out.println("Finish decryption:\n" + new String(newPlainText,"UTF8"));
 * //-----------Part 6 : Close the connection---------------------------
 * sock.close();
 * 
 * }catch(Exception e){ e.printStackTrace(); }
 * 
 * }
 * 
 * }
 */