package org.fscrypto.cipher;

/**
 * Convenience constants and methods for Cipher names
 * @author John Larison
 */
public class Paddings {
	//Guaranteed provided by JCE===============================================
	public static final String NO_PADDING = "NoPadding";
	public static final String ISO10126 = "ISO10123Padding";
	public static final String PKCS5 = "PKCS5Padding";
	public static final String SSL3 = "SSL3Padding";

	/**
	 * Convenience method for creating padding names of the form OAEPWith(digest)And(MFG)Padding
	 * @param digest The digest name to use with OAEP
	 * @param mgf The momentum generating function to use with OAEP
	 * @return A Standard Names Document compliant OAEP name
	 */
	public static String OAEP(String digest, String mgf) {
		return "OAEPWith" + digest + "And" + mgf + "Padding";
	}
}
