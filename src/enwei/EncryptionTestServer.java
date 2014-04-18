package enwei;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
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

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
//Byte Buffer
//convert data type of public key
//Base64 encoding

public class EncryptionTestServer {
	private static ServerSocket ssock;
	private static Socket client;
	private final static int port = 3344;

	private static OutputStream out;
	private static InputStream in;

	private final static SecureRandom random = new SecureRandom();
	private static Cipher cipher;

	private final static int RSAKeySize = 1024;
	private static KeyGenerator DESkeyGen;
	private static KeyPairGenerator RSAKeyGen;
	private static KeyPair serverKeyPair;
	private static PublicKey serverPubKey, clientPubKey;
	private static PrivateKey serverPrivKey;
	private static Key DESkey;
	private static KeyFactory kf;
	private static X509EncodedKeySpec ks;
	private static ByteBuffer byteBuffer;
	private static byte[] byteArray, keyPlainText, keyCipherText, msgPlainText,
			msgCipherText;
	private static int randomNumber, receivedNumber, bufferLen;

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
		// Step A1: Setup server socket
		try {
			ssock = new ServerSocket(port);
		} catch (IOException e) {
			e.printStackTrace();
			System.err.println("Unable to set up server on port " + port);
			System.exit(0);
		}

		// Step A2: Generate RSA Keypair
		RSAKeyGen.initialize(RSAKeySize, random);
		serverKeyPair = RSAKeyGen.generateKeyPair();
		serverPubKey = serverKeyPair.getPublic();
		serverPrivKey = serverKeyPair.getPrivate();

		// Step A3: Accept client connection
		try {
			client = ssock.accept();
		} catch (IOException e) {
			e.printStackTrace();
			System.err.println("Unable to accept client on port " + port);
			System.exit(0);
		}
		try {
			in = client.getInputStream();
			out = client.getOutputStream();
		} catch (IOException e) {
			e.printStackTrace();
			System.err.println("Unable to setup client IO.");
			System.exit(0);
		}
		// Step A4: Send RSA pubkey to client
		byteArray = serverPubKey.getEncoded();
		byteBuffer = ByteBuffer.allocate(4 + serverPubKey.getEncoded().length);
		byteBuffer.putInt(serverPubKey.getEncoded().length);
		byteBuffer.put(byteArray);
		try {
			out.write(byteBuffer.array());
			out.flush();
		} catch (IOException e2) {
			e2.getStackTrace();
			System.err.println("Unable to send public key");
		}
		byteBuffer.clear();

		// Step A5: Acquire RSA pubkey from client
		byteArray = new byte[4];
		try {
			in.read(byteArray, 0, 4);
		} catch (IOException e1) {
			e1.getStackTrace();
			System.err.println("No key length provided");
			System.exit(0);
		}
		bufferLen = ByteBuffer.wrap(byteArray).getInt();
		byteArray = new byte[bufferLen];
		try {
			in.read(byteArray);
		} catch (IOException e1) {
			e1.getStackTrace();
			System.err.println("No public key provided");
			System.exit(0);
		}
		try {
			kf = KeyFactory.getInstance("RSA");
		} catch (Exception e) {
			e.printStackTrace();
			System.err.println("Unable to setup Key Factory");
			System.exit(0);
		}
		ks = new X509EncodedKeySpec(byteArray);
		try {
			clientPubKey = kf.generatePublic(ks);
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
			System.err.println("Key provided is invalid");
			System.exit(0);
		}

		// --------------------------------------------------------------------
		// -Base Condition Established, P and G owns each other's RSA a priori-
		// --------------------------------------------------------------------

		// Step B1: Generate random symmetric key K_s
		try {
			DESkeyGen = KeyGenerator.getInstance("DES");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			System.err.println("DESKeyGen setup error.");
			System.exit(0);
		}
		DESkeyGen.init(56, random);
		DESkey = DESkeyGen.generateKey();

		// Step B2: Encrypt verification message using server privkey
		// (authenticity)
		randomNumber = random.nextInt();
		msgPlainText = ByteBuffer.allocate(4).putInt(randomNumber).array();
		try {
			cipher.init(Cipher.ENCRYPT_MODE, serverPrivKey);
		} catch (InvalidKeyException e) {
			e.printStackTrace();
			System.err.println("Server private key invalid.");
			System.exit(0);
		}
		try {
			msgCipherText = cipher.doFinal(msgPlainText);
		} catch (Exception e) {
			e.printStackTrace();
			System.err.println("Unable to encrypt.");
			System.exit(0);
		}

		// Step B3: Encrypt symmetric key using client pubkey
		// (authenticity, integrity, confidentiality)
		keyPlainText = DESkey.getEncoded();
		try {
			cipher.init(Cipher.ENCRYPT_MODE, clientPubKey);
		} catch (InvalidKeyException e) {
			e.printStackTrace();
			System.err.println("Client public key invalid.");
			System.exit(0);
		}
		try {
			keyCipherText = cipher.doFinal(keyPlainText);
		} catch (Exception e) {
			e.printStackTrace();
			System.err.println("Unable to encrypt second layer.");
			System.exit(0);
		}

		// Step B4: Encrypt verification message ciphertext using symmetric key
		try {
			cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
		} catch (Exception e1) {
			e1.getStackTrace();
			System.err.println("DES Cipher setup error.");
		}
		msgPlainText = msgCipherText;
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

		// Step B5: Send all ciphertext over to client
		byteBuffer = ByteBuffer.allocate(8 + msgCipherText.length
				+ keyCipherText.length);
		byteBuffer.putInt(msgCipherText.length);
		byteBuffer.put(msgCipherText);
		byteBuffer.putInt(keyCipherText.length);
		byteBuffer.put(keyCipherText);
		try {
			out.write(byteBuffer.array());
			out.flush();
		} catch (IOException e2) {
			e2.getStackTrace();
			System.err.println("Unable to send ciphertext");
		}
		byteBuffer.clear();

		// Step B6: Wait for ciphertext from client
		byteArray = new byte[4];
		try {
			in.read(byteArray);
		} catch (IOException e1) {
			e1.getStackTrace();
			System.err.println("No encrypted verification msg length provided");
			System.exit(0);
		}
		bufferLen = ByteBuffer.wrap(byteArray).getInt();
		msgCipherText = new byte[bufferLen];
		try {
			in.read(msgCipherText);
		} catch (IOException e1) {
			e1.getStackTrace();
			System.err.println("No verification msg provided");
			System.exit(0);
		}

		// Step B7: Decrypt ciphertext from client using client pubkey v =
		// K_s(K_s(v))
		try {
			cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		} catch (Exception e1) {
			e1.getStackTrace();
			System.err.println("RSA Cipher setup error.");
		}
		try {
			cipher.init(Cipher.DECRYPT_MODE, clientPubKey);
		} catch (InvalidKeyException e) {
			e.printStackTrace();
			System.err
					.println("Invalid key for decryption of verification msg.");
			System.exit(0);
		}
		try {
			msgPlainText = cipher.doFinal(msgCipherText);
		} catch (Exception e) {
			e.printStackTrace();
			System.err.println("Unable to Decrypt.");
			System.exit(0);
		}
		receivedNumber = ByteBuffer.wrap(msgPlainText).getInt();

		// Step B8: Verify the verification message
		if (receivedNumber == randomNumber) {
			System.out.println("Verified");
		} else {
			System.out.println("Unverified.");
			System.exit(0);
		}

		// -------All messages will be encrypted using K_s from now on---------
		// Step C1: Encrypt sent message s using symmetric key K_s(s)
		try {
			cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
		} catch (Exception e1) {
			e1.getStackTrace();
			System.err.println("DES Cipher setup error.");
		}
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

		// Step C2: Send the ciphertext to client
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

		// Step C3: Receive the ciphertext from client
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

		// Step C4: Decrypt ciphertext from client using symmetric key r =
		// K_s(K_s(r))
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
	}
}
/*
 * //set variables for port number final int port = 3344; //set socket server,
 * socket client, client public key ServerSocket server = null; Socket client =
 * null; Key clientPubKey = null; //an authentication message from server //get
 * the message into byte format String password = "password"; //get the message
 * into byte format
 * 
 * //-----------Part 1 : initialize socket connection---------------------- try{
 * 
 * server = new ServerSocket(port);
 * System.out.println("Server is waiting for client on port "
 * +server.getLocalPort()); client = server.accept();
 * System.out.println("TCP connection is established now");
 * 
 * }catch(Exception e){ e.printStackTrace(); }
 * 
 * //-----------Part 2 : get public key from client------------------------ try{
 * 
 * 
 * creates a byte array to read the length of client public keyuses
 * getInputStream method to return an input stream for reading byte arrayfrom
 * this socket
 * 
 * uses wrap method to convert the existing byte array into byte bufferuses
 * getInt method for reading an int value from byte buffer
 * System.out.println("Length of the public key: "+len);
 * 
 * creates a byte array with length of client public keyreturns an input stream
 * to read the byte array from this socketSystem.out.println("Public Key:\n" +
 * DatatypeConverter.printHexBinary(CLIENT_PUBKEY_IN_BYTES));
 * 
 * the CLIENT_PUBKEY_IN_BYTES will be encoded according to the X.509 standard,
 * the contents of array are copied to protect against subsequent modification
 * uses KeyFactory to get back the client public key from key specifications
 * *(X.509 standard)
 * 
 * System.out.println("Encoded Public Key:\n" +
 * DatatypeConverter.printHexBinary(CLIENT_PUBKEY.getEncoded()));
 * 
 * 
 * byte[] lenb = new byte[4]; client.getInputStream().read(lenb,0,4); ByteBuffer
 * bb = ByteBuffer.wrap(lenb); int len = bb.getInt();
 * System.out.println("Length of the public key: "+len);
 * 
 * byte[] cPubKeyBytes = new byte[len];
 * client.getInputStream().read(cPubKeyBytes);
 * System.out.println("Public Key:\n"+
 * DatatypeConverter.printHexBinary(cPubKeyBytes));
 * 
 * X509EncodedKeySpec ks = new X509EncodedKeySpec(cPubKeyBytes); KeyFactory kf =
 * KeyFactory.getInstance("RSA"); clientPubKey = kf.generatePublic(ks);
 * System.out.println("Encoded Public Key:\n" +
 * DatatypeConverter.printHexBinary(clientPubKey.getEncoded()));
 * 
 * }catch (Exception e) { e.printStackTrace(); }
 * 
 * 
 * 
 * 
 * 
 * 
 * //-----------Part 3 : Encryption for the message--------------------------
 * 
 * 
 * 
 * System.out.println("Start Encryption for plainText");
 * 
 * get an RSA cipher objectinitializes the cipher object into encrypt mode and
 * uses client public keyencrypts the plaintext into ciphertext
 * 
 * System.out.println("Finish Encryption to cipherText:\n"+ new
 * String(cipherText,"UTF8") );
 * 
 * 
 * 
 * System.out.println("Start Encryption for plainText");
 * 
 * Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
 * cipher.init(Cipher.ENCRYPT_MODE, clientPubKey); byte[] cipherText =
 * cipher.doFinal(plainText);
 * 
 * System.out.println("Finish Encryption to cipherText:\n"+ new
 * String(cipherText,"UTF8") );
 * 
 * 
 * //-----------Part 4 : Base64 encoding-------------------------------------
 * 
 * uses BASE64Encoder class to encode the cipherText
 * System.out.println("Base64 Encoded:\n" + encryptedValue);
 * 
 * 
 * BASE64Encoder base64 = new BASE64Encoder(); String encryptedValue =
 * base64.encode(cipherText); System.out.println("Base64 Encoded:\n" +
 * encryptedValue);
 * 
 * 
 * //-----------Part 5 : send Message to client------------------------------
 * 
 * 
 * returns an output stream for the socketwrites the object into the
 * ObjectOutputStreamflush the object
 * 
 * 
 * 
 * ObjectOutputStream obOut = new ObjectOutputStream(client.getOutputStream());
 * obOut.writeObject(encryptedValue); obOut.flush();
 * 
 * //-----------Part 6 : close connection------------------------------------
 * client.close(); }
 * 
 * 
 * }
 */

// --------------SYMMETRIC KEY!!!----------------
// check args and get plaintext

/*
 * if (args.length != 1){ System.err.println("Usage: java LocalCrypto text");
 * System.exit(1); }
 */

/*
 * String input = "AAAAAAAAAAAAAAAA";
 * 
 * byte[] plainText = input.getBytes("UTF8"); // // get a DES secret key
 * 
 * System.out.println("\nStart generating RSA keypair"); KeyPairGenerator keyGen
 * = KeyPairGenerator.getInstance("RSA"); SecureRandom random = new
 * SecureRandom(); keyGen.initialize(512, random); KeyPair key =
 * keyGen.generateKeyPair();
 * System.out.println("Finish generating RSA keypair"); // // get a RSA cipher
 * object and print the provider Cipher cipher =
 * Cipher.getInstance("RSA/ECB/PKCS1Padding");
 * 
 * 
 * System.out.println("\nStart generating DES key"); // Generate a key that's
 * used for DES encryption algorithm KeyGenerator keyGen =
 * KeyGenerator.getInstance("DES"); SecureRandom random = new SecureRandom();
 * keyGen.init(56, random); Key key = keyGen.generateKey();
 * System.out.println("Finish generating DES key"); // // get a DES cipher
 * object and print the provider Cipher cipher =
 * Cipher.getInstance("DES/ECB/PKCS5Padding");
 * 
 * 
 * System.out.println("\n"+cipher.getProvider().getInfo()); // // encrypt using
 * the key and the plaintext System.out.println("\nStart encryption");
 * 
 * //cipher.init(Cipher.ENCRYPT_MODE, key); cipher.init(Cipher.ENCRYPT_MODE,
 * key.getPrivate());
 * 
 * byte[] cipherText = cipher.doFinal(plainText);
 * System.out.println("Finish encryption: "); System.out.println(new
 * String(cipherText, "UTF8")); System.out.println(cipherText.length);
 * 
 * 
 * 
 * //
 *//*****
 * BASE64 Encode***** BASE64Encoder base64 = new BASE64Encoder(); String
 * encryptedValue = base64.encode(cipherText);
 * System.out.println("Base64 Encoded:\n" + encryptedValue);
 *****/
/*
 * // // decrypt the ciphertext using the same key
 * 
 * 
 * System.out.println("\nStart decryption"); //cipher.init(Cipher.DECRYPT_MODE,
 * key); cipher.init(Cipher.DECRYPT_MODE, key.getPublic());
 * 
 * byte[] newPlainText = cipher.doFinal(cipherText);
 * System.out.println("Finish decryption: "); System.out.println(new
 * String(newPlainText, "UTF8"));
 */