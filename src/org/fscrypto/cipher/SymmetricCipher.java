package org.fscrypto.cipher;

import static org.fscrypto.cipher.Modes.*;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.io.IOUtils;

import org.fscrypto.utils.InputStreamReadCallback;
import org.fscrypto.utils.InputStreamReader;

//TODO: What do we want to do with these throws clauses?
/**
 * This class is used to encrypt or decrypt data using an symmetric-key cipher such as AES.  All methods are thread-safe.
 * @author John Larison
 * @since 0.1.ALPHA
 * @see {@link Engines} {@link Paddings} {@link Modes}
 */
public class SymmetricCipher {
	
	/**
	 * Performs encryption using the specified symmetric-key cipher.
	 *@param engine The standard name of the engine to use for encryption
	 * @param padding The standard name of the padding scheme to use for encryption
	 * @param mode The standard name of the cipher mode to use for encryption
	 * @param provider The name of the provider to use for encryption
	 * @param in The {@link InputStream} from which to read the data to be encrypted
	 * @param key The {@link InputStream} from which to read the key data
	 * @param out The {@link OutputStream} to which the encrypted data is written
	 * @throws Exception If anything goes wrong with the underlying encryption or IO
	 */
	public static void encrypt(		 String 		engine, 
							   		 String 		padding, 
							   		 String 		mode, 
							   		 String 		provider, 
							   		 InputStream 	in, 
							   		 InputStream 	key, 
							   final OutputStream	out) throws Exception {
		SecretKeySpec keySpec = new SecretKeySpec(IOUtils.toByteArray(key), engine);
		final Cipher cipher = Cipher.getInstance(engine + "/" + mode + "/" + padding);
		cipher.init(Cipher.ENCRYPT_MODE, keySpec);
		
		byte[] iv = cipher.getIV();
		if (iv != null) {
			out.write(iv);
			cipher.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(iv));
		}
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
	 * Performs decryption using the specified symmetric-key cipher.
	 * @param engine The standard name of the engine to use for encryption
	 * @param padding The standard name of the padding scheme to use for encryption
	 * @param mode The standard name of the cipher mode to use for encryption
	 * @param provider The name of the provider to use for encryption
	 * @param in The {@link InputStream} from which to read the encrypted data
	 * @param key The {@link InputStream} from which to read the key data
	 * @param out The {@link OutputStream} to which the decrypted data is written
	 * @throws Exception If anything goes wrong with the underlying encryption or IO
	 */
	public static void decrypt(		 String 		engine, 
			   				   		 String 		padding, 
			   				   		 String 		mode, 
			   				   		 String 		provider, 
			   				   		 InputStream 	in, 
			   				   		 InputStream 	key, 
			   				   final OutputStream	out) throws Exception {
		SecretKeySpec keySpec = new SecretKeySpec(IOUtils.toByteArray(key), engine);
		final Cipher cipher = Cipher.getInstance(engine + "/" + mode + "/" + padding);
		
		if (!(NO_MODE.equalsIgnoreCase(mode) || ECB.equals(mode))) {
			byte[] iv = new byte[cipher.getBlockSize()];
			int readIn = in.read(iv);
			if (readIn != iv.length) {
				int totalReadIn = readIn;
				while (readIn != -1 && totalReadIn < iv.length) {
					readIn = in.read(iv, totalReadIn, iv.length - totalReadIn);
					totalReadIn += readIn;
				}
				if (totalReadIn != iv.length) {
					throw new IllegalArgumentException("Input stream must contain at least one block worth of data");
				}
			}
			cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(iv));
		} else {
			cipher.init(Cipher.DECRYPT_MODE, keySpec);
		}
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
