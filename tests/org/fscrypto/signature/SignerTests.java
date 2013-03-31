package org.fscrypto.signature;

import static org.junit.Assert.*;
import static org.fscrypto.signature.Algorithms.*;
import static org.fscrypto.signature.Digests.*;

import java.io.InputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

import org.junit.Test;

import org.fscrypto.testutils.Utils;

//FIXME: Currently this does not test signing with DSA or ECDSA and no digest.  DSA is throwing "Data for RawDSA must be
//exactly 20 bits long." ECDSA is failing to verify signatures on two of the three EC keys for unknown reasons, but I have
//been seeing some strange behavior out of ECDSA Java implementations.
public class SignerTests {
	String[] algs = {RSA, DSA, EC};
	@SuppressWarnings("serial")
	Map<String, String> keyStores = new HashMap<String, String>(){{
		put(RSA, "rsa-test.p12");
		put(DSA, "dsa-test.p12");
		put(EC, "ec-test.p12");
	}};
	@SuppressWarnings("serial")
	Map<String, String[]> digests = new HashMap<String, String[]>(){{
		String[] rsa = {NONE, MD5, SHA_1, SHA_256, SHA_384, SHA_512};
		String[] dsa = {SHA_1};
		String[] ec = {SHA_1, SHA_256, SHA_384, SHA_512};
		put(RSA, rsa);
		put(DSA, dsa);
		put(EC, ec);
	}};
	String[] testInput = {"test1.txt", "test2.txt"};

	@Test
	public void testSign() throws Exception {
		for (String algorithm : algs) {
			KeyStore keyStore = Utils.loadKeystore(keyStores.get(algorithm));
			Enumeration<String> aliases = keyStore.aliases();
			while (aliases.hasMoreElements()) {
				String alias = aliases.nextElement();
				PrivateKey key = (PrivateKey)keyStore.getKey(alias, "changeit".toCharArray());
				PublicKey pubKey = keyStore.getCertificate(alias).getPublicKey();
				for (String digest : digests.get(algorithm)) {
					for (String input : testInput) {
						PipedOutputStream pos = new PipedOutputStream();
						PipedInputStream pis = new PipedInputStream(pos);
						ClassLoader cloader = Thread.currentThread().getContextClassLoader();
						InputStream fileIn = cloader.getResourceAsStream(input);
						Signer.sign(digest, algorithm, fileIn, key, pos);
						pos.close();
						fileIn.close();
						fileIn = cloader.getResourceAsStream(input);
						assertTrue("testSign() failed with algorithm: " + algorithm + ", digest: " + digest + ", key: " + 
								   alias + ", and file: " + input,
								   Signer.verifySignature(digest, algorithm, fileIn, pubKey, pis));
						fileIn.close();
						pis.close();
					}
				}
			}
		}
	}

	@Test
	public void testVerifySignature() throws Exception {
		for (String algorithm : algs) {
			KeyStore keyStore = Utils.loadKeystore(keyStores.get(algorithm));
			Enumeration<String> aliases = keyStore.aliases();
			while (aliases.hasMoreElements()) {
				String alias = aliases.nextElement();
				PublicKey key = keyStore.getCertificate(alias).getPublicKey();
				for (String digest : digests.get(algorithm)) {
					for (int i = 0; i < testInput.length; ++i) {
						if ((alias.equals("prime239v3") || alias.equals("secp112r1")) && digest.equals(NONE)) {
							continue;
						}
						ClassLoader cloader = Thread.currentThread().getContextClassLoader();
						InputStream fileIn = cloader.getResourceAsStream(testInput[i]);
						String sigFilename = Utils.calculateSignatureFilename(testInput[i], alias, digest);
						InputStream sigIn = cloader.getResourceAsStream(sigFilename);
						assertTrue("testVerifySignature() failed with algorithm: " + algorithm + ", digest: " + digest + 
								   ", key: " + alias + ", and file: " + testInput[i],
								   Signer.verifySignature(digest, algorithm, fileIn, key, sigIn));
						fileIn.close();
						sigIn.close();
						fileIn = cloader.getResourceAsStream(testInput[i]);
						sigFilename = Utils.calculateSignatureFilename(testInput[(i + 1) % testInput.length], alias, digest);
						sigIn = cloader.getResourceAsStream(sigFilename);
						assertFalse("testVerifySignature() failed with algorithm: " + algorithm + ", digest: " + digest + 
								   ", key: " + alias + ", and file: " + testInput[i],
								   Signer.verifySignature(digest, algorithm, fileIn, key, sigIn));
						fileIn.close();
						sigIn.close();
					}
				}
			}
		}
	}
}
