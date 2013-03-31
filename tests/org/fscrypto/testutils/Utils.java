package org.fscrypto.testutils;

import java.io.InputStream;
import java.security.KeyStore;
import java.security.Provider;

import javax.crypto.Cipher;

public class Utils {
	public static String[] getSupportedModes(String algorithm) throws Exception {
		Cipher cipher = Cipher.getInstance(algorithm);
		Provider provider = cipher.getProvider();
		Provider.Service service = provider.getService("Cipher", algorithm);
		String modes = service.getAttribute("SupportedModes");
		return modes.split("\\|");
	}
	
	public static String[] getSupportedPaddings(String algorithm) throws Exception {
		Cipher cipher = Cipher.getInstance(algorithm);
		Provider provider = cipher.getProvider();
		Provider.Service service = provider.getService("Cipher", algorithm);
		String modes = service.getAttribute("SupportedPaddings");
		return modes.split("\\|");
	}
	
	public static int getBlockSize(String algorithm) throws Exception {
		Cipher cipher = Cipher.getInstance(algorithm);
		return cipher.getBlockSize();
	}
	
	public static KeyStore loadKeystore(String name) throws Exception {
		KeyStore keyStore = KeyStore.getInstance("PKCS12");
		InputStream keyStoreIn = 
				Thread.currentThread().getContextClassLoader().getResourceAsStream(name);
		if (keyStoreIn == null) {
			throw new IllegalArgumentException("No file exists with given name: " + name);
		}
		keyStore.load(keyStoreIn, "changeit".toCharArray());
		return keyStore;
	}
	
	public static String calculateSignatureFilename(String input, String alias, String digest) {
		return input.split("\\.")[0] + "-" + alias.toLowerCase() + "-" + digest.toLowerCase() + ".sig";
	}
	public static String calculateEncryptedFilename(String input, String alias) {
		return input.split("\\.")[0] + "-" + alias.toLowerCase() + ".enc";
	}
}
