package org.fscrypto.mac;

import static org.junit.Assert.*;
import static org.fscrypto.mac.Algorithms.*;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.IOUtils;
import org.junit.Test;

public class MessageAuthenticatorTests {
	String[] algs = {HMAC_MD5, HMAC_SHA1, HMAC_SHA256, HMAC_SHA384, HMAC_SHA512};
	String[] testStrings = {"The quick brown fox jumps over the lazy dog", "The quick brown fox jumps over the lazy cog", ""};
	String[] keys = {"key", ""};
	
	@SuppressWarnings("serial")
	Map<String, Map<String, String[]>> codes = new HashMap<String, Map<String,String[]>>(){{
		put(HMAC_MD5, new HashMap<String, String[]>(){{
			String[] knownGood = {"80070713463e7749b90c2dc24911e275", "f734cebb1ebaf1480795349e4a515799", 
								  "63530468a04e386459855da0063b6596"};
			put("key", knownGood);
			String[] knownGood2 = {"ad262969c53bc16032f160081c4a07a0", "b80343a0feacb4887ea5c323737644bd", 
								   "74e6f7298a9c2d168935f58c001bad88"};
			put("", knownGood2);
		}});
		put(HMAC_SHA1, new HashMap<String, String[]>(){{
			String[] knownGood = {"de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9", "ad8d3f85da865d37e37ae5d7ab8ee32c5681ebc1", 
								  "f42bb0eeb018ebbd4597ae7213711ec60760843f"};
			put("key", knownGood);
			String[] knownGood2 = {"2ba7f707ad5f187c412de3106583c3111d668de8", "158725d9967a4cb4df85c0f500accb283236ad79", 
								   "fbdb1d1b18aa6c08324b7d64b71fb76370690e1d"};
			put("", knownGood2);
		}});
		put(HMAC_SHA256, new HashMap<String, String[]>(){{
			String[] knownGood = {"f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8", 
								  "3f7d9044432ff5c2a390eea7dbb3fcbdbb7b51bb0089fa7354d135500e0bca36", 
								  "5d5d139563c95b5967b9bd9a8c9b233a9dedb45072794cd232dc1b74832607d0"};
			put("key", knownGood);
			String[] knownGood2 = {"fb011e6154a19b9a4c767373c305275a5a69e8b68b0b4c9200c383dced19a416", 
								   "06c9344e6e96903114656d2391fbc36af735bfe5078592f9f9c2af1581e0682c", 
								   "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad"};
			put("", knownGood2);
		}});
		put(HMAC_SHA384, new HashMap<String, String[]>(){{
			String[] knownGood = {
					"d7f4727e2c0b39ae0f1e40cc96f60242d5b7801841cea6fc592c5d3e1ae50700582a96cf35e1e554995fe4e03381c237", 
					"c550bf5a491af63f266daa271c2a449323d5adbc405080cbe437190ab60b49b63bd436c159259484331a40540bb0787b", 
					"99f44bb4e73c9d0ef26533596c8d8a32a5f8c10a9b997d30d89a7e35ba1ccf200b985f72431202b891fe350da410e43f"};
			put("key", knownGood);
			String[] knownGood2 = {
					"0a3d8f99afb726f97d32cc513f3a5ad51246984fd3e916cefb82fc7967ee42eae547cd88aefd84493d2585e55906e1b0", 
					"2238f8408bc68134d559b615879a029e409e60038421ff34bd40c8e4ee34ea1e152a6fa401c5f3336d66488e1c253e56", 
					"6c1f2ee938fad2e24bd91298474382ca218c75db3d83e114b3d4367776d14d3551289e75e8209cd4b792302840234adc"};
			put("", knownGood2);
		}});
		put(HMAC_SHA512, new HashMap<String, String[]>(){{
			String[] knownGood = {
					"b42af09057bac1e2d41708e48a902e09b5ff7f12ab428a4fe86653c73dd248fb82f948a549f7b791a5b41915ee4d1ec3935357e4e2317250d0372afa2ebeeb3a", 
					"f3e0fd665455729c1f1da82f7f72eb41d3a6b886f523a57f4c2e2bb1f081cc394c824de9371a1751d52ac496128efca5e6ac61a8536091eeb093c4f89ad9c5d6", 
					"84fa5aa0279bbc473267d05a53ea03310a987cecc4c1535ff29b6d76b8f1444a728df3aadb89d4a9a6709e1998f373566e8f824a8ca93b1821f0b69bc2a2f65e"};
			put("key", knownGood);
			String[] knownGood2 = {
					"1de78322e11d7f8f1035c12740f2b902353f6f4ac4233ae455baccdf9f37791566e790d5c7682aad5d3ceca2feff4d3f3fdfd9a140c82a66324e9442b8af71b6", 
					"8f8f4c709a00fd1b7b4873cc2b46f58d86aff52db18dbde9c3d3e8dbe9b4cfcb8bc4efbb8c07c4d1a14b3c33aa3577a987568df2ebd7357445eb570500fed3d6", 
					"b936cee86c9f87aa5d3c6f2e84cb5a4239a5fe50480a6ec66b70ab5b1f4ac6730c6c515421b327ec1d69402e53dfb49ad7381eb067b338fd7b0cb22247225d47"};
			put("", knownGood2);
		}});
	}};
	
	@Test
	public void testGenerateCode() throws Exception {
		for (String algorithm : algs) {
			for (String key : keys) {
				for (int i = 0; i < testStrings.length; ++i) {
					InputStream in = IOUtils.toInputStream(testStrings[i]);
					InputStream keyStream = IOUtils.toInputStream(key);
					PipedInputStream result = new PipedInputStream();
					OutputStream out = new PipedOutputStream(result);
					MessageAuthenticator.generateCode(algorithm, in, keyStream, out);
					out.close();
					String actual = new String(Hex.encodeHex(IOUtils.toByteArray(result)));
					assertEquals(codes.get(algorithm).get(key)[i].toLowerCase(), actual.toLowerCase());
				}
			}
		}
	}

	@Test
	public void testVerifyCode() throws Exception {
		for (String algorithm : algs) {
			for (String key : keys) {
				for (int i = 0; i < testStrings.length; ++i) {
					InputStream in = IOUtils.toInputStream(testStrings[i]);
					InputStream keyStream = IOUtils.toInputStream(key);
					InputStream code = new ByteArrayInputStream(Hex.decodeHex(codes.get(algorithm).get(key)[i].toCharArray()));
					assert(MessageAuthenticator.verifyCode(algorithm, in, keyStream, code));
					in = IOUtils.toInputStream(testStrings[i]);
					keyStream = IOUtils.toInputStream(key);
					code = new ByteArrayInputStream(
							Hex.decodeHex(codes.get(algorithm).get(key)[(i + 1) % testStrings.length].toCharArray())
					);
					assertFalse(MessageAuthenticator.verifyCode(algorithm, in, keyStream, code));
				}
			}
		}
	}
}