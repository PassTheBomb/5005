package enwei;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

public class ClientAuthentication {
	private Security s;
	private Keys k;

	// Test code start
	public static void main(String[] args) throws Exception {
		Security s = new Security();
		Keys k = new Keys();
		k.generateRSAKeyPair();

		int port = 5555;
		String host = "localhost";
		Socket client = new Socket(host, port);
		InputStream in = client.getInputStream();
		OutputStream out = client.getOutputStream();

		ClientAuthentication sa = new ClientAuthentication(s, k);
		sa.T5(in, out);

		client.close();
	}

	// Test code end

	/**
	 * Creates a class containing the set of security protocols to be
	 * implemented on the client side. Requires a Security class and a Keys
	 * class as an input, and both must already be instantiated and set up.
	 * 
	 * @param s
	 *            the instantiated Security class
	 * @param k
	 *            the instantiated Keys class with RSA keypairs generated
	 */
	ClientAuthentication(Security s, Keys k) {
		this.s = s;
		this.k = k;
	}

	/**
	 * The 1st protocol.
	 * 
	 * @param in
	 *            input stream to receive the encrypted messages from server
	 * @param out
	 *            output stream to send the encrypted messages to server
	 */
	public void T2(InputStream in, OutputStream out) {

	}

	/**
	 * The 2nd protocol.
	 * 
	 * @param in
	 *            input stream to receive the encrypted messages from server
	 * @param out
	 *            output stream to send the encrypted messages to server
	 */
	public void T3(InputStream in, OutputStream out) {

	}

	/**
	 * The 3rd protocol.
	 * 
	 * @param in
	 *            input stream to receive the encrypted messages from server
	 * @param out
	 *            output stream to send the encrypted messages to server
	 */
	public void T4(InputStream in, OutputStream out) {

	}

	/**
	 * The 4th protocol.
	 * 
	 * @param in
	 *            input stream to receive the encrypted messages from server
	 * @param out
	 *            output stream to send the encrypted messages to server
	 */
	public void T5(InputStream in, OutputStream out) {

		// Acquire server RSA key from server
		byte[] byteArray = null;
		PublicKey serverPubKey = null;
		try {
			byteArray = MsgHandler.acquireNetworkMsg(in);
		} catch (IOException e) {
			System.err.println("Unable to acquire server public key.");
			e.printStackTrace();
		}
		try {
			serverPubKey = k.PublicKeyFromByteCode(byteArray);
		} catch (InvalidKeySpecException e) {
			System.err.println("Unable to decode server public key.");
			e.printStackTrace();
		}

		// Send client RSA key to server
		byteArray = k.getRSAPubKey().getEncoded();
		byteArray = MsgHandler.createNetworkMsg(byteArray);
		try {
			out.write(byteArray);
			out.flush();
		} catch (IOException e) {
			System.err.println("Unable to send client public key.");
			e.printStackTrace();
		}

		// --------------------------------------------------------------------
		// -Base Condition Established, P and G owns each other's RSA a priori-
		// --------------------------------------------------------------------

		// Receive encrypted symmetric key from server
		try {
			byteArray = MsgHandler.acquireNetworkMsg(in);
		} catch (IOException e2) {
			System.err.println("Unable acquire encrypted key");
			e2.printStackTrace();
		}

		// Decrypt symmetric key
		byteArray = s.decrypt(byteArray, k.getRSAPrivKey(), "RSA");
		k.setDESKey(k.DESKeyFromByteCode(byteArray));

		// Receive doubly encrypted nonce from server
		try {
			byteArray = MsgHandler.acquireNetworkMsg(in);
		} catch (IOException e1) {
			System.err.println("Unable acquire encrypted nonce");
			e1.printStackTrace();
		}

		// Decrypt second encryption layer using symmetric key
		byteArray = s.decrypt(byteArray, k.getDESKey(), "DES");

		// Decrypt first encryption layer using server public key
		byteArray = s.decrypt(byteArray, serverPubKey, "RSA");

		// Encrypt nonce using symmetric key
		byteArray = s.encrypt(byteArray, k.getDESKey(), "DES");

		// Send encrypted nonce to server
		try {
			out.write(MsgHandler.createNetworkMsg(byteArray));
			out.flush();
		} catch (IOException e) {
			System.err.println("Unable to send encrypted nonce");
			e.printStackTrace();
		}
	}
}
