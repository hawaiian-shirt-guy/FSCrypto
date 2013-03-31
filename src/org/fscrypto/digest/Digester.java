package org.fscrypto.digest;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Random;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.IOUtils;
import org.apache.commons.io.output.ByteArrayOutputStream;

import org.fscrypto.utils.InputStreamReadCallback;
import org.fscrypto.utils.InputStreamReader;

//TODO: What do we want to do with this throws clause?
/**
 * This class is used to provide cryptographic hashes of data using standard message digest algorithms
 * @author john_larison
 * @since 0.1.ALPHA
 * @see Algorithms
 */
public class Digester {
	
    /**
     * Table with characters for Base16 transformation.
     */
    private static final String BASE_16_SET = "0123456789abcdef";
	
	/**
	 * Workhorse method for the Digester class.  Used to calculate cryptographic hashes 
	 * @param algorithm The hashing algorithm to use
	 * @param in The {@link InputStream} from which to read to data to hash
	 * @param out The {@link OutputStream} to which to write the hash
	 * @throws IOException If an exception occurs with the underlying IO mechanisms
	 * @throws GeneralSecurityException If an exception occurs within the underlying cryptographic framework
	 */
	public static void generateHash(String 			algorithm, 
									InputStream 	in, 
									OutputStream	out) throws IOException, GeneralSecurityException {
		final MessageDigest digester = MessageDigest.getInstance(algorithm);
		InputStreamReader.read(in, new InputStreamReadCallback() {
			public void update(byte b) throws GeneralSecurityException {
				digester.update(b);
			}
			public void update(byte[] bytes) throws GeneralSecurityException {
				digester.update(bytes);				
			}
		});
		out.write(digester.digest());
	}
	
	/**
	 * Default password hashing tool.  Defaults to {@link Algorithms}.SHA_512.  Defaults to random 8 byte salt in hex.
	 * Returns the password in the django format. {@linkplain https://docs.djangoproject.com/en/dev/topics/auth/passwords/}
	 * @param password
	 * @return
	 * @throws IOException
	 * @throws GeneralSecurityException
	 */
	public static String generatePasswordHash(String password) throws IOException, GeneralSecurityException {
		return generatePasswordHash(password, getRandomSalt(16), Algorithms.SHA_512);
	}
	
	/**
	 * Password hashing tool.
	 * Returns the password in the django format. {@linkplain https://docs.djangoproject.com/en/dev/topics/auth/passwords/}
	 * @param password
	 * @param algorithm
	 * @return
	 * @throws IOException
	 * @throws GeneralSecurityException
	 */
	public static String generatePasswordHash(String password, String salt, String algorithm) throws IOException, GeneralSecurityException {

		InputStream inPass = IOUtils.toInputStream(salt + password);
		ByteArrayOutputStream byteHash = new ByteArrayOutputStream();
		generateHash(algorithm, inPass, byteHash);
		String hexHash = new String(Hex.encodeHex(byteHash.toByteArray(), true));
		
		return algorithm + "$" + salt + "$" + hexHash;
	}
	
    /**
     * Generates a string of random chars from the hex set.
     * @param length Number of chars to generate.
     */
    public static String getRandomSalt(int length) {
        StringBuilder saltString = new StringBuilder();
        for (int i = 1; i <= length; i++) {
            saltString.append(BASE_16_SET.charAt(new Random().nextInt(BASE_16_SET.length())));
        }
        return saltString.toString();
    }
}
