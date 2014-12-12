package com.urqa.common;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Base64;

public class Encryptor {

	public static final String ENCRYPTION = "ENTRYPTION";
	public static final String ENCRYPTION_BASE_KEY = "ENTRYPTION_BASE_KEY";
	public static final String ENCRYPTION_TOKEN = "ENCRYPTION_PRIVATE_KEY";

	public static String baseKey;
	public static String token;

	private static Cipher encryptor;
	private static Cipher decryptor;
	private static String IV = "0000000000000000";
	private static SecretKey secureKey;

	public static KeyStore getToken() throws Exception {

		String public_key = "";

		// Generate RSA key pairs
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(1024);
		KeyPair keypair = keyGen.genKeyPair();
		byte[] publicKey = keypair.getPublic().getEncoded();

		public_key = "-----BEGIN PUBLIC KEY-----\\n"
				+ Base64.encodeToString(publicKey, 0)
				+ "\\n-----END PUBLIC KEY-----\\n";

		// request Key
		String url = "http://localhost:55555/urqa/client/get_key";
		String data = "{\"public\":\"" + public_key + "\"}";

		String response = Encrytor.sendPost(url, data, false);

		// token parse
		String enc_data = Encrytor.getJsonToken(response, "enc_data");
		System.out.println("enc_data " + enc_data);

		// rsa decode
		KeyStore ks = new KeyStore();
		try {
			Cipher rsa;
			rsa = Cipher.getInstance("RSA");
			rsa.init(Cipher.DECRYPT_MODE, keypair.getPrivate());
			byte[] utf8 = rsa.doFinal(Base64.decode(enc_data, 0));
			String enc_data2 = new String(utf8, "UTF8");

			ks.baseKey = Encrytor.getJsonToken(enc_data2, "basekey");
			ks.token = Encrytor.getJsonToken(enc_data2, "token");

		} catch (Exception e) {
			e.printStackTrace();
		}

		System.out.println("token " + ks.token);
		System.out.println("basekey " + ks.baseKey);

		return ks;
	}

	public static class KeyStore {
		public String token;
		public String baseKey;

		public KeyStore() {
			// TODO Auto-generated constructor stub
		}

		public KeyStore(String token, String baseKey) {
			// TODO Auto-generated constructor stub
			this.token = token;
			this.baseKey = baseKey;
		}
	}

	/*
	 * network 부분 갈아끠워야 함ㄴ
	 */
	private static String sendPost(String url, String data, boolean isEncrypt) throws Exception {

		URL obj = new URL(url);
		HttpURLConnection con = (HttpURLConnection) obj.openConnection();

		// add reuqest header
		con.setRequestMethod("POST");
		con.setRequestProperty("User-Agent", "Urqa Client");
		con.setRequestProperty("Content-type", "application/json");
		con.setRequestProperty("Charset", "utf8");

		// add Version info ( 암호화에는 영향 없지만, 이번 부터 버전 해더를 넣는 것을 기본 정책으로 가져갈 예정 )
		con.setRequestProperty("version", "1.0.0");

		// header 타입 암호화 요청일 경우에 아래의 형식으로 요청 한다.
		if (isEncrypt) {
			// header 모드 일 때만 보낸다.
			con.setRequestProperty("Urqa-Encrypt-Opt",
					"aes-256-cbc-pkcs5padding+base64");
		}

		// Send post request
		con.setDoOutput(true);
		DataOutputStream wr = new DataOutputStream(con.getOutputStream());
		wr.writeBytes(data);
		wr.flush();
		wr.close();

		int responseCode = con.getResponseCode();
		System.out.println("\nSending 'POST' request to URL : " + url);
		System.out.println("Response Code : " + responseCode);

		BufferedReader in = new BufferedReader(new InputStreamReader(
				con.getInputStream()));
		String inputLine;
		StringBuffer response = new StringBuffer();

		while ((inputLine = in.readLine()) != null) {
			response.append(inputLine);
		}
		in.close();

		return response.toString();
	}

	private static String getJsonToken(String json, String key) {
		String wrapped_key = "\"" + key + "\"";
		int start_idx = json.indexOf(wrapped_key) + wrapped_key.length();
		start_idx = json.indexOf('"', start_idx) + 1;
		int end_idx = json.indexOf('"', start_idx);
		return json.substring(start_idx, end_idx);
	}

	/**
	 * 
	 * @param src
	 * @return AEC-256-cbc-pkcs5padding + BASE64
	 * @throws NoSuchPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidAlgorithmParameterException
	 * @throws InvalidKeyException
	 */
	public static String encrypt(String data) throws InvalidKeyException,
			NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidAlgorithmParameterException {
		if (baseKey == null || token == null) {
			throw new IllegalArgumentException(
					"you dont initialize basekey or token");
		}
		data = "{  \"token\":\"" + token + "\", \"enc_data\" : \""
				+ encrypt(baseKey, data.getBytes()) + "\", \"src_len\":"
				+ data.getBytes().length + " }";
		return data;
	}

	private static String encrypt(String baseKey, byte[] src)
			throws NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidKeyException, InvalidAlgorithmParameterException {

		byte[] key = SHA256(baseKey);

		if (secureKey == null) {
			secureKey = new SecretKeySpec(key, "AES");
		}

		if (encryptor == null) {
			encryptor = Cipher.getInstance("AES/CBC/PKCS5Padding");
			encryptor.init(Cipher.ENCRYPT_MODE, secureKey, new IvParameterSpec(
					IV.getBytes()));
		}

		byte[] encrypted = null;

		try {
			encrypted = encryptor.doFinal(src);
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		}
		return Base64.encodeToString(encrypted, 0);
	}

	/**
	 * 
	 * @param src
	 * @return source data
	 * @throws NoSuchPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidAlgorithmParameterException
	 * @throws InvalidKeyException
	 */
	public byte[] decrypt(String baseKey, String src)
			throws NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidKeyException, InvalidAlgorithmParameterException {

		byte[] key = SHA256(baseKey);

		if (secureKey == null) {
			secureKey = new SecretKeySpec(key, "AES");
		}

		if (decryptor == null) {
			decryptor = Cipher.getInstance("AES/CBC/PKCS5Padding");
			decryptor.init(Cipher.DECRYPT_MODE, secureKey, new IvParameterSpec(
					IV.getBytes()));
		}

		byte[] dec = Base64.decode(src, 0);
		byte[] ret = null;

		try {
			ret = decryptor.doFinal(dec);
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		}

		return ret;
	}

	private static byte[] SHA256(String str) {
		try {

			MessageDigest sh = MessageDigest.getInstance("SHA-256");
			sh.update(str.getBytes());
			byte byteData[] = sh.digest();
			return byteData;

		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return null;
	}
}
