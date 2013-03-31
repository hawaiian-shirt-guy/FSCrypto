package org.fscrypto.signature;

import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

import org.apache.commons.io.IOUtils;

import org.fscrypto.utils.InputStreamReadCallback;
import org.fscrypto.utils.InputStreamReader;

//TODO: What to do about these throws clauses...
/**
 * This class is used to generate and verify cryptographic signatures using asymmetric-key ciphers.
 * @author John Larison
 * @since 0.1.ALPHA
 * @see {@linkAlgorithms} {@link Digests}
 */
public class Signer {
	
	/**
	 * Generate a cryptographic signature
	 * @param digest The standard name of the digest to use
	 * @param encryption The standard name of the cipher to use
	 * @param in The data to sign
	 * @param key The private key with which to sign the data
	 * @param out Where to write the signature
	 * @throws Exception If anything goes wrong with the underlying encryption or IO
	 */
	public static void sign(String 			digest, 
							String 			encryption, 
							InputStream 	in, 
							PrivateKey 		key, 
							OutputStream	out) throws Exception {
		String algorithm = digest + "with" + encryption;
		final Signature signature = Signature.getInstance(algorithm);
		signature.initSign(key);
		InputStreamReader.read(in, new InputStreamReadCallback() {
			public void update(byte b) throws GeneralSecurityException {
				signature.update(b);				
			}
			public void update(byte[] bytes) throws GeneralSecurityException {
				signature.update(bytes);				
			}
		});
		out.write(signature.sign());
	}
	
	/**
	 * Verifies a cryptographic signature
	 *@param digest The standard name of the digest to use
	 * @param encryption The standard name of the cipher to use
	 * @param in The data whose signature to verify
	 * @param key The public key used to verify the signature
	 * @param signature The signature to verify
	 * @return True if the signature is valid, False otherwise
	 * @throws Exception If anything goes wrong with the underlying encryption or IO
	 */
	public static boolean verifySignature(String		digest, 
										  String 		encryption, 
										  InputStream 	in, 
										  PublicKey 	key, 
										  InputStream	signature) throws Exception {
		String algorithm = digest + "with" + encryption;
		final Signature signatureChecker = Signature.getInstance(algorithm);
		signatureChecker.initVerify(key);
		InputStreamReader.read(in, new InputStreamReadCallback() {
			public void update(byte b) throws GeneralSecurityException {
				signatureChecker.update(b);
			}
			public void update(byte[] bytes) throws GeneralSecurityException {
				signatureChecker.update(bytes);
			}
		});
		return signatureChecker.verify(IOUtils.toByteArray(signature));
	}
}
