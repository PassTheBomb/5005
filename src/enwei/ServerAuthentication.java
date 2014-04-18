package enwei;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.security.Key;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

public class ServerAuthentication {
	private final SecureRandom random = new SecureRandom();
	private Security s;
	private Keys k;

	ServerAuthentication(Security s, Keys k) {
		this.s = s;
		this.k = k;
	}

	public void T2(InputStream in, OutputStream out) {

	}

	public Key T3(InputStream in, OutputStream out) {

	}

	public Key T4(InputStream in, OutputStream out) {
		
	}
	
	public Key T5(InputStream in, OutputStream out){

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
		PublicKey clientPubKey;
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
		
		//Encrypt nonce using server private key
		byte[] nonce = new byte[4];
		random.nextBytes(nonce);
	}
}
