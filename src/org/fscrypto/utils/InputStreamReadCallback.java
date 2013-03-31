package org.fscrypto.utils;

import java.io.IOException;
import java.security.GeneralSecurityException;

/**
 * Callback interface used by the {@link InputStreamReader}
 * @author John Larison
 * @since 0.1.ALPHA
 * @see InputStreamReader
 */
public interface InputStreamReadCallback {
	
	/**
	 * Receive the next group of bytes read from the input stream
	 * @param bytes
	 * @throws IOException If an IO exception occurs in the callback
	 * @throws GeneralSecurityException If a cryptographic exception occurs in the callback
	 */
	public void update(byte[] bytes) throws IOException, GeneralSecurityException;
	
	/**
	 * Receive the next byte read from the input stream
	 * @param b
	 * @throws IOException If an IO exception occurs in the callback
	 * @throws GeneralSecurityException If a cryptographic exception occurs in the callback
	 */
	public void update(byte b) throws IOException, GeneralSecurityException;
}
