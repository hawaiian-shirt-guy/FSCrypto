package org.fscrypto.utils;

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;

/**
 * Used to wrap a callback in general boilerplate IO code while allowing for efficient use of blocking IO streams.
 * @author John Larison
 * @since 0.1.ALPHA
 * @see InputStreamReadCallback
 */
public class InputStreamReader {
	
	/**
	 * Reads all available data from the input stream, passing all data read to the specified {@link InputStreamReadCallback}
	 * @param in
	 * @param callback
	 * @throws IOException If an IO exception occurs in the callback
	 * @throws GeneralSecurityException If a cryptographic exception occurs in the callback
	 */
	public static void read(InputStream in, InputStreamReadCallback callback) throws IOException, GeneralSecurityException {
		while (true) {
			int readIn = in.available();
			if (readIn != 0) {
				byte[] input = new byte[readIn];
				int read = in.read(input);
				if (read == -1) {
					break;
				}
				callback.update(input);
			} else {
				int input = in.read();
				if (input == -1) {
					break;
				}
				callback.update((byte)input);
			}
		}
	}
}
