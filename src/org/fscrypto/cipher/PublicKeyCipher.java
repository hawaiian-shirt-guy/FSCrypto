package org.fscrypto.cipher;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.Cipher;

import org.fscrypto.utils.InputStreamReadCallback;
import org.fscrypto.utils.InputStreamReader;

/**
 * This class is used to encrypt or decrypt data using an asymmetric-key cipher capable of encryption.
 * @author John Larison
 * @since 0.1.ALPHA
 * @see {@link Engines} {@link Paddings} {@link Modes}
 */
public class PublicKeyCipher {
	
	/**
	 * Performs encryption using the specified asymmetric-key cipher.
	 * @param engine The standard name of the engine to use for encryption
	 * @param padding The standard name of the padding scheme to use for encryption
	 * @param mode The standard name of the cipher mode to use for encryption
	 * @param provider The name of the provider to use for encryption
	 * @param in The {@link InputStream} from which to read the data to be encrypted
	 * @param key The {@link PublicKey} to use to encrypt the data
	 * @param out The {@link OutputStream} to which the encrypted data is written
	 * @throws Exception If anything goes wrong with the underlying encryption or IO
	 */
	public static void encrypt(String 		engine, 
							   String 		padding, 
							   String 		mode, 
							   String 		provider, 
							   InputStream 	in, 
							   PublicKey	key,
							   final OutputStream	out) throws Exception {
		final Cipher cipher = Cipher.getInstance(engine + "/" + mode + "/" + padding);
		cipher.init(Cipher.ENCRYPT_MODE, key);
		InputStreamReader.read(in, new InputStreamReadCallback() {
			public void update(byte b) throws IOException, GeneralSecurityException {
				byte[] input = {b};
				update(input);
			}
			public void update(byte[] bytes) throws IOException, GeneralSecurityException {
				out.write(cipher.update(bytes));
			}
		});
		out.write(cipher.doFinal());
	}
	
	/**
	 * Performs decryption using the specified asymmetric-key cipher.
	 * @param engine The standard name of the engine to use for encryption
	 * @param padding The standard name of the padding scheme to use for encryption
	 * @param mode The standard name of the cipher mode to use for encryption
	 * @param provider The name of the provider to use for encryption
	 * @param in The {@link InputStream} from which to read the encrypted data
	 * @param key The {@link PrivateKey} to use to decrypt the data
	 * @param out The {@link OutputStream} to which the decrypted data is written
	 * @throws Exception If anything goes wrong with the underlying encryption or IO
	 */
	public static void decrypt(String 		engine, 
							   String 		padding, 
							   String 		mode, 
							   String 		provider, 
							   InputStream 	in, 
							   PrivateKey	key,
							   final OutputStream	out) throws Exception {
		final Cipher cipher = Cipher.getInstance(engine + "/" + mode + "/" + padding);
		cipher.init(Cipher.DECRYPT_MODE, key);
		InputStreamReader.read(in, new InputStreamReadCallback() {
			public void update(byte b) throws IOException, GeneralSecurityException {
				byte[] input = {b};
				update(input);
			}
			public void update(byte[] bytes) throws IOException, GeneralSecurityException {
				out.write(cipher.update(bytes));
			}
		});
		out.write(cipher.doFinal());
	}
}
