package org.fscrypto.digest;

import static org.junit.Assert.*;
import static org.fscrypto.digest.Algorithms.*;

import java.io.InputStream;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.IOUtils;
import org.junit.Test;

public class DigesterTests {
	String[] algs = {MD2, MD5, SHA_1, SHA_256, SHA_384, SHA_512};
		
	@Test
	public void testGenerateHash() throws Exception {
		String[] tests = {"The quick brown fox jumps over the lazy dog", "The quick brown fox jumps over the lazy cog", ""};
		@SuppressWarnings("serial")
		Map<String, String[]> hashes = new HashMap<String, String[]>(){{
			String[] md2 = {"03d85a0d629d2c442e987525319fc471", "6b890c9292668cdbbfda00a4ebf31f05", 
							"8350e5a3e24c153df2275c9f80692773"};
			put(MD2, md2);
			String[] md5 = {"9e107d9d372bb6826bd81d3542a419d6", "1055d3e698d289f2af8663725127bd4b", 
							"d41d8cd98f00b204e9800998ecf8427e"};
			put(MD5, md5);
			String[] sha1 = {"2fd4e1c67a2d28fced849ee1bb76e7391b93eb12", "de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3",
							 "da39a3ee5e6b4b0d3255bfef95601890afd80709"};
			put(SHA_1, sha1);
			String[] sha256 = {"d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592", 
							   "e4c4d8f3bf76b692de791a173e05321150f7a345b46484fe427f6acc7ecc81be",
							   "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"};
			put(SHA_256, sha256);
			String[] sha384 = {
					"ca737f1014a48f4c0b6dd43cb177b0afd9e5169367544c494011e3317dbf9a509cb1e5dc1e85a941bbee3d7f2afbc9b1",
					"098cea620b0978caa5f0befba6ddcf22764bea977e1c70b3483edfdf1de25f4b40d6cea3cadf00f809d422feb1f0161b",
					"38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"};
			put(SHA_384, sha384);
			String[] sha512 = {
					"07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6",
					"3eeee1d0e11733ef152a6c29503b3ae20c4f1f3cda4cb26f1bc1a41f91c7fe4ab3bd86494049e201c4bd5155f31ecb7a3c8606843c4cc8dfcab7da11c8ae5045",
					"cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"};
			put(SHA_512, sha512);
		}};
		for (String algorithm : algs) {
			for (int i = 0; i < tests.length; ++i) {
				InputStream in = IOUtils.toInputStream(tests[i]);
				PipedInputStream result = new PipedInputStream();
				OutputStream out = new PipedOutputStream(result);
				Digester.generateHash(algorithm, in, out);
				out.close();
				String test = new String(Hex.encodeHex(IOUtils.toByteArray(result)));
				assertEquals(hashes.get(algorithm)[i].toLowerCase(), test.toLowerCase());
			}
		}
	}
}
