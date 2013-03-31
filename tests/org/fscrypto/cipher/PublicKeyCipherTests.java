package org.fscrypto.cipher;

import static org.junit.Assert.*;
import static org.fscrypto.cipher.Engines.*;
import static org.fscrypto.cipher.Paddings.*;

import org.apache.commons.io.IOUtils;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.nio.ByteBuffer;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

import org.junit.Test;

import org.fscrypto.testutils.Utils;

public class PublicKeyCipherTests {
	private static final String[] DEFAULT_ENGINES = {RSA};
	@SuppressWarnings("serial")
	private static final Map<String, String> KEY_STORES = new HashMap<String, String>(){{
		put(RSA, "rsa-test.p12");
	}};
	String[] testInput = {"test1.txt", "test2.txt"};
		
	@Test
	public void testEncrypt() throws Exception {
		for (int i = 0; i < DEFAULT_ENGINES.length; ++i) {
			String engine = DEFAULT_ENGINES[i];
			KeyStore keyStore = Utils.loadKeystore(KEY_STORES.get(engine));
			Enumeration<String> aliases = keyStore.aliases();
			while (aliases.hasMoreElements()) {
				String alias = aliases.nextElement();
				PublicKey pubKey = keyStore.getCertificate(alias).getPublicKey();
				for (String mode : Utils.getSupportedModes(engine)) {
					for (String padding : Utils.getSupportedPaddings(engine)) {								
						byte[] dummyData = new byte[new Random().nextInt(126)];
						new Random().nextBytes(dummyData);
						ByteArrayOutputStream out = new ByteArrayOutputStream();
						
						PublicKeyCipher.encrypt(engine, 
												padding, 
												mode, 
												"JCE", 
												new ByteArrayInputStream(dummyData),
												pubKey, 
												out);
						
						byte[] testOutput = out.toByteArray();
						out.close();
						assertTrue("testEncrypt() failed with Transform: " + engine + "/" + mode + "/" + padding + 
								   " Key: " + alias, 
								   testOutput.length > 0);
					}
				}
			}
		}
	}

	@Test
	public void testDecrypt() throws Exception {
		for (int i = 0; i < DEFAULT_ENGINES.length; ++i) {
			String engine = DEFAULT_ENGINES[i];
			KeyStore keyStore = Utils.loadKeystore(KEY_STORES.get(engine));
			Enumeration<String> aliases = keyStore.aliases();
			while (aliases.hasMoreElements()) {
				String alias = aliases.nextElement();
				PrivateKey privKey = (PrivateKey)keyStore.getKey(alias, "changeit".toCharArray());
				for (String input : testInput) {
					PipedOutputStream pos = new PipedOutputStream();
					PipedInputStream pis = new PipedInputStream(pos);
					ClassLoader cloader = Thread.currentThread().getContextClassLoader();
					InputStream fileIn = cloader.getResourceAsStream(Utils.calculateEncryptedFilename(input, alias));
					PublicKeyCipher.decrypt(engine, "PKCS1PADDING", "ECB", "JCE", fileIn, privKey, pos);
					pos.close();
					InputStream expected = cloader.getResourceAsStream(input);
					assertArrayEquals("testDecrypt() failed with key: " + alias + " on file: " + input,
									  IOUtils.toByteArray(expected), 
									  IOUtils.toByteArray(pis));
				}
			}
		}
	}
	
	@Test
	public void testSanity() throws Exception {
		for (int i = 0; i < DEFAULT_ENGINES.length; ++i) {
			String engine = DEFAULT_ENGINES[i];
			KeyStore keyStore = Utils.loadKeystore(KEY_STORES.get(engine));
			Enumeration<String> aliases = keyStore.aliases();
			while (aliases.hasMoreElements()) {
				String alias = aliases.nextElement();
				PublicKey pubKey = keyStore.getCertificate(alias).getPublicKey();
				PrivateKey privKey = (PrivateKey)keyStore.getKey(alias, "changeit".toCharArray());
				for (String mode : Utils.getSupportedModes(engine)) {
					for (String padding : Utils.getSupportedPaddings(engine)) {		
						byte[] dummyData = new byte[new Random().nextInt(126)];
						new Random().nextBytes(dummyData);
						
						PipedInputStream decryptIn = new PipedInputStream();
						PipedOutputStream encryptOut = new PipedOutputStream(decryptIn);
						PipedInputStream stringInput = new PipedInputStream();
						PipedOutputStream decryptOut = new PipedOutputStream(stringInput);
						
						PublicKeyCipher.encrypt(engine, 
												padding, 
												mode, 
												"JCE", 
												new ByteArrayInputStream(dummyData),
												pubKey, 
												encryptOut);							
						encryptOut.close();							
						PublicKeyCipher.decrypt(engine, 
												padding, 
												mode, 
												"JCE", 
												decryptIn, 
												privKey, 
												decryptOut);
						decryptOut.close();
						if (NO_PADDING.equalsIgnoreCase(padding)) {
							int startingZeros = 0;
							ByteBuffer buffer = ByteBuffer.allocate(dummyData.length);
							while (dummyData[startingZeros] == 0) {
								++startingZeros;
								buffer.put((byte)0);
							}
							int b = 0;
							while (b == 0) {
								b = stringInput.read();
							}
							buffer.put((byte)b);
							for (int c = stringInput.read(); c != -1; c= stringInput.read()) {
									buffer.put((byte)c);
							}
							byte[] fuckYou = buffer.array();
							assertArrayEquals("testSanity() failed with Transform: " + engine + "/" + mode + "/" + padding + 
									   		  " Key: " + alias, 
									   		  dummyData, 
									   		  fuckYou);
						} else {
							assertArrayEquals("testSanity() failed with Transform: " + engine + "/" + mode + "/" + padding + 
							   		  		  " Key: " + alias, 
							   		  		  dummyData, 
							   		  		  IOUtils.toByteArray(stringInput));
						}
					}
				}
			}
		}
	}
}
