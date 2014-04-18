package enwei;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

/**
 * Class containing the set of 4 protocols to be implemented
 * 
 */
public class ServerAuthentication {
	private final SecureRandom random = new SecureRandom();
	private Security s;
	private Keys k;

	// Test code start
	public static void main(String[] args) throws Exception {
		Security s = new Security();
		Keys k = new Keys();
		k.generateRSAKeyPair();
		k.generateDESKey();

		int port = 5555;
		ServerSocket ssock = new ServerSocket(port);
		Socket client = ssock.accept();
		InputStream in = client.getInputStream();
		OutputStream out = client.getOutputStream();

		ServerAuthentication sa = new ServerAuthentication(s, k);
		sa.T5(in, out);

		ssock.close();
	}

	// Test code end

	/**
	 * Creates a class containing the set of security protocols to be
	 * implemented on the server side. Requires a Security class and a Keys
	 * class as an input, and both must already be instantiated and set up.
	 * 
	 * @param s
	 *            the instantiated Security class
	 * @param k
	 *            the instantiated Keys class with RSA keypairs and DES key
	 *            generated
	 */
	ServerAuthentication(Security s, Keys k) {
		this.s = s;
		this.k = k;
	}

	/**
	 * The 1st protocol.
	 * 
	 * @param in
	 *            input stream to receive the encrypted messages from client
	 * @param out
	 *            output stream to send the encrypted messages to client
	 */
	public void T2(InputStream in, OutputStream out) {

	}

	/**
	 * The 2nd protocol.
	 * 
	 * @param in
	 *            input stream to receive the encrypted messages from client
	 * @param out
	 *            output stream to send the encrypted messages to client
	 */
	public void T3(InputStream in, OutputStream out) {

	}

	/**
	 * The 3rd protocol.
	 * 
	 * @param in
	 *            input stream to receive the encrypted messages from client
	 * @param out
	 *            output stream to send the encrypted messages to client
	 */
	public void T4(InputStream in, OutputStream out) {

	}

	/**
	 * The 4th protocol.
	 * 
	 * @param in
	 *            input stream to receive the encrypted messages from client
	 * @param out
	 *            output stream to send the encrypted messages to client
	 */
	public void T5(InputStream in, OutputStream out) {

		// Send RSA pubkey to client
		byte[] byteArray = k.getRSAPubKey().getEncoded();
		byteArray = MsgHandler.createNetworkMsg(byteArray);
		try {
			out.write(byteArray);
			out.flush();
		} catch (IOException e) {
			System.err.println("Unable to send server public key.");
			e.printStackTrace();
		}

		// Acquire RSA pubkey from client
		PublicKey clientPubKey = null;
		try {
			byteArray = MsgHandler.acquireNetworkMsg(in);
		} catch (IOException e) {
			System.err.println("Unable to acquire client public key.");
			e.printStackTrace();
		}
		try {
			clientPubKey = k.PublicKeyFromByteCode(byteArray);
		} catch (InvalidKeySpecException e) {
			System.err.println("Unable to decode client public key.");
			e.printStackTrace();
		}

		// --------------------------------------------------------------------
		// -Base Condition Established, P and G owns each other's RSA a priori-
		// --------------------------------------------------------------------

		// Encrypt symmetric key using client public key
		byte[] keyCipher = s.encrypt(k.getDESKey().getEncoded(), clientPubKey,
				"RSA");

		// Send encrypted symmetric key to client
		try {
			out.write(MsgHandler.createNetworkMsg(keyCipher));
			out.flush();
		} catch (IOException e) {
			System.err.println("Unable to send doubly encrypted nonce.");
			e.printStackTrace();
		}

		// Encrypt nonce using server private key
		byte[] nonce = new byte[4];
		random.nextBytes(nonce);
		byte[] nonceCipher = s.encrypt(nonce, k.getRSAPrivKey(), "RSA");

		// Double encrypt nonce using symmetric key
		nonceCipher = s.encrypt(nonceCipher, k.getDESKey(), "DES");

		// Send doubly encrypted nonce to client
		try {
			out.write(MsgHandler.createNetworkMsg(nonceCipher));
			out.flush();
		} catch (IOException e) {
			System.err.println("Unable to send doubly encrypted nonce.");
			e.printStackTrace();
		}

		// Acquire reply from client
		try {
			byteArray = MsgHandler.acquireNetworkMsg(in);
		} catch (IOException e) {
			System.err.println("Unable to acquire client reply.");
			e.printStackTrace();
		}

		// Decrypt reply
		byteArray = s.decrypt(byteArray, k.getDESKey(), "DES");
		if (ByteBuffer.wrap(byteArray).getInt() == ByteBuffer.wrap(nonce)
				.getInt()) {
			System.out.println("Verified");
		} else {
			System.err.println("Unverified");
			System.exit(0);
		}
	}
}
