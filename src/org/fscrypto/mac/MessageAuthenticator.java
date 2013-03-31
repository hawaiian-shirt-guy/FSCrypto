package org.fscrypto.mac;

import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.io.IOUtils;

import org.fscrypto.utils.InputStreamReadCallback;
import org.fscrypto.utils.InputStreamReader;

//TODO: What to do about these exceptions?
/**
 * This class is used to create and verify message authentication codes
 * @author John Larison
 * @since 0.1.ALPHA
 * @see Algorithms
 */
public class MessageAuthenticator {
	
	/**
	 * Used to generate a message authentication code for the provided data
	 * @param algorithm The standard name of the algorithm with which to create the message authentication code
	 * @param in The message
	 * @param key Key data source
	 * @param out Where the message authentication code is written
	 * @throws Exception If anything goes wrong with the underlying encryption or IO
	 */
	public static void generateCode(String algorithm, InputStream in, InputStream key, OutputStream out) throws Exception {
		out.write(generateCode(algorithm, in, key));
	}
	
	/**
	 * 
	 * @param algorithm The standard name of the algorithm with which to create the message authentication code
	 * @param in The message
	 * @param key Key data source
	 * @param code The message authentication code to check
	 * @return True if the message authentication code is valid.  False otherwise
	 * @throws Exception If anything goes wrong with the underlying encryption or IO
	 */
	public static boolean verifyCode(String algorithm, InputStream in, InputStream key, InputStream code) throws Exception {
		byte[] knownGood = generateCode(algorithm, in, key);
		byte[] test = IOUtils.toByteArray(code);
		if (knownGood.length != test.length) {
			return false;
		}
		for (int i = 0; i < knownGood.length; ++i) {
			if (knownGood[i] != test[i]) {
				return false;
			}
		}
		return true;
	}
	
	private static byte[] generateCode(String algorithm, InputStream in, InputStream key) throws Exception {
		byte[] keyBytes = IOUtils.toByteArray(key);
		if (keyBytes.length == 0) {
			keyBytes = new byte[1];
			keyBytes[0] = 0;
		}
		SecretKeySpec keySpec = new SecretKeySpec(keyBytes, algorithm);
		final Mac mac = Mac.getInstance(algorithm);
		mac.init(keySpec);
		InputStreamReader.read(in, new InputStreamReadCallback() {
			public void update(byte b) throws GeneralSecurityException {
				mac.update(b);
			}
			public void update(byte[] bytes) throws GeneralSecurityException {
				mac.update(bytes);				
			}
		});
		return mac.doFinal();
	}
}
