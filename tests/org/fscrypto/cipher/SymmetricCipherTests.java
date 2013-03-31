package org.fscrypto.cipher;

import static org.fscrypto.cipher.Engines.*;
import static org.fscrypto.cipher.Modes.*;
import static org.fscrypto.cipher.Paddings.*;
import static org.junit.Assert.*;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.util.Random;

import org.apache.commons.io.IOUtils;
import org.junit.Ignore;
import org.junit.Test;

import org.fscrypto.testutils.Utils;


public class SymmetricCipherTests {
	private static final String DEFAULT_ENGINES[] = {AES, ARCFOUR, BLOWFISH, DES, DESEDE, RC2, RC4};
	private static final int DEFAULT_KEYSIZES[][] = {{128, 256, 64}, {40, 1024, 1}, {32, 8, 448}, {64, 64, 2}, 
													 {192, 192, 1}, {40, 1024, 1}, {40, 1024, 1}};
	
	@Test
	public void testEncrypt() throws Exception {
		ByteArrayOutputStream out;
		for (int i = 0; i < DEFAULT_ENGINES.length; ++i) {
			String engine = DEFAULT_ENGINES[i];
			for (String padding : Utils.getSupportedPaddings(engine)) {
				for (String mode : Utils.getSupportedModes(engine)) {
					if (mode.equalsIgnoreCase(CTR)  || mode.equalsIgnoreCase(CTS_Mode)) {
						if (!padding.equalsIgnoreCase(NO_PADDING)) {
							continue;
						}
					}
					for (int keySize = DEFAULT_KEYSIZES[i][0]; 
						 	 keySize <= DEFAULT_KEYSIZES[i][1]; 
							 keySize += DEFAULT_KEYSIZES[i][2]) {
						
						out = new ByteArrayOutputStream();
						byte[] key = new byte[keySize / 8];
						new Random().nextBytes(key);
						int dataSize = Utils.getBlockSize(engine) == 0 ? 13 : 10 * Utils.getBlockSize(engine); 
						byte[] dummyData = new byte[dataSize];
						
						new Random().nextBytes(dummyData);
						SymmetricCipher.encrypt(engine, 
										 		padding, 
										 		mode, 
										 		null, 
										 		new ByteArrayInputStream(dummyData), 
										 		new ByteArrayInputStream(key), 
										 		out);
						byte[] testOutput = out.toByteArray();
						out.close();
						assertTrue("testEncrypt() failed with Transform: " + engine + "/" + mode + "/" + padding + " " + 
								   "Key size: " + keySize,
								   testOutput.length > 0);
					}
				}
			}
		}
	}

	@Test
	@Ignore
	public void testDecrypt() throws Exception {
	}
	
	@Test
	public void testSanity() throws Exception {
		PipedInputStream decryptIn;
		PipedOutputStream encryptOut;
		PipedInputStream stringInput;
		PipedOutputStream decryptOut;
		
		for (int i = 0; i < DEFAULT_ENGINES.length; ++i) {
			String engine = DEFAULT_ENGINES[i];
			for (String padding : Utils.getSupportedPaddings(engine)) {
				for (String mode : Utils.getSupportedModes(engine)) {
					if (mode.equalsIgnoreCase(CTR)  || mode.equalsIgnoreCase(CTS_Mode)) {
						if (!padding.equalsIgnoreCase(NO_PADDING)) {
							continue;
						}
					}
					for (int keySize = DEFAULT_KEYSIZES[i][0]; 
						 	 keySize <= DEFAULT_KEYSIZES[i][1]; 
							 keySize += DEFAULT_KEYSIZES[i][2]) {
						
						decryptIn = new PipedInputStream();
						encryptOut = new PipedOutputStream(decryptIn);
						stringInput = new PipedInputStream();
						decryptOut = new PipedOutputStream(stringInput);
						
						byte[] key = new byte[keySize / 8];
						new Random().nextBytes(key);
						byte[] dummyData = new byte[new Random().nextInt(10) * Utils.getBlockSize(engine)];
						
						new Random().nextBytes(dummyData);
						SymmetricCipher.encrypt(engine, 
										 		padding, 
										 		mode, 
										 		null, 
										 		new ByteArrayInputStream(dummyData), 
										 		new ByteArrayInputStream(key), 
										 		encryptOut);
						encryptOut.close();
						SymmetricCipher.decrypt(engine, 
												padding, 
												mode, 
												null, 		
												decryptIn, 
												new ByteArrayInputStream(key), 
												decryptOut);
						decryptOut.close();
						assertArrayEquals("testSanity() failed with Transform: " + engine + "/" + mode + "/" + padding + 
										  " " + "Key size: " + keySize,
								   		  dummyData, 
								   		  IOUtils.toByteArray(stringInput));
					}
				}
			}
		}
	}
}
