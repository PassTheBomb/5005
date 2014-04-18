package enwei;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
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

	public void T3(InputStream in, OutputStream out) {

	}

	public void T4(InputStream in, OutputStream out) {
		
	}
	
	public void T5(InputStream in, OutputStream out){

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
		byte[] keyCipher = s.encrypt(k.getDESKey().getEncoded(), clientPubKey, "RSA");
		
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
		
		//Send doubly encrypted nonce to client
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
		
		if (byteArray.equals(nonce)){
			System.out.println("Verified");
		}
		else{
			System.err.println("Unverified");
			System.exit(0);
		}
	}
}
