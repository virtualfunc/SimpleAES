package com.virtualfunc.SimpleAES;

import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;

/**
 * A simple implementation for AES encryption.
 */
public class SimpleAES {
	public static final int INITIALIZATION_VECTOR_SIZE_BYTES = 16;
	public static final int KEY_SIZE_BITS = 256;
	public static final String PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA512";
	public static final int SALT_BYTES = 32;

	SecretKeySpec key;

	/**
	 * Creates a random salt.
	 *
	 * @return the salt as a byte array
	 */
	static public byte[] createSalt()
	{
		byte[] salt = new byte[SALT_BYTES];

		SecureRandom random = new SecureRandom();
		random.nextBytes(salt);

		return salt;
	}

	/**
	 * Creates a cryptographic hash string from a byte array.
	 *
	 * @param bytes the source data
	 * @return
	 */
	public static String getHash(byte[] bytes) {
		try {
			MessageDigest digest = MessageDigest.getInstance("SHA-256");

			byte[] hash = digest.digest(bytes);
			StringBuilder sb = new StringBuilder();

			for(int i = 0; i < hash.length; i++) {
				sb.append(String.format("%02x", hash[i]));
			}

			return sb.toString();
		} catch (NoSuchAlgorithmException e) {

		}

		return null;
	}

	/**
	 * Default constructor that initializes with a random key.
	 */
	public SimpleAES() {
		init(createRandomKey());
	}

	/**
	 * Constructor that initializes with a password/phrase and salt.
	 *
	 * @param password to use as key
	 */
	public SimpleAES(String password, byte[] salt)
	{
		init(createKeyFromPassword(password.toCharArray(), salt));
	}

	/**
	 * Creates an AES instance of the Cipher class.
	 *
	 * @return the Cipher object
	 */
	Cipher createCipher()	{
		Cipher cipher = null;

		try {
			cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		}
		catch (NoSuchPaddingException e) {
			e.printStackTrace();
		}
		catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}

		return cipher;
	}

	/**
	 * Creates a random initialization vector.
	 *
	 * @return the initialization vector
	 */
	IvParameterSpec createRandomInitializationVector() {
		// self-seeded randomizer to generate IV
		byte iv[] = new byte[INITIALIZATION_VECTOR_SIZE_BYTES];
		SecureRandom secRandom = new SecureRandom();
		secRandom.nextBytes(iv);

		return new IvParameterSpec(iv);
	}

	/**
	 * Creates a random encryption key.
	 *
	 * @return the key.
	 */
	SecretKeySpec createRandomKey() {
		SecretKeySpec secretKeySpec = null;

		try {
			KeyGenerator keygen = KeyGenerator.getInstance("AES");
			keygen.init(KEY_SIZE_BITS);

			byte[] key = keygen.generateKey().getEncoded();
			secretKeySpec = new SecretKeySpec(key, "AES");
		}
		catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}

		return secretKeySpec;
	}

	/**
	 * Creates an encryption key based on the given password and salt.
	 *
	 * @param password the password/phrase as a string
	 * @param salt the salt to use when generating the key
	 * @return the encryption key.
	 */
	SecretKeySpec createKeyFromPassword(char[] password, byte[] salt)
	{
		SecretKeySpec secretKeySpec = null;

		PBEKeySpec spec = new PBEKeySpec(password, salt, 1000, KEY_SIZE_BITS);

		try {
			SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM);
			secretKeySpec = new SecretKeySpec(keyFactory.generateSecret(spec).getEncoded(), "AES");
		}
		catch (InvalidKeySpecException e) {
			e.printStackTrace();
		}
		catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}

		return secretKeySpec;
	}

	/**
	 * Decrypts an input stream to an output stream.
	 *
	 * @param inputStream encrypted input stream
	 * @param outputStream plain text output stream
	 *
	 * @return true if succeeded, false if failed
	 */
	public boolean decrypt(InputStream inputStream, OutputStream outputStream) {
		boolean status = false;

		try {
			// first load initialization vector
			byte[] iv = new byte[INITIALIZATION_VECTOR_SIZE_BYTES];
			inputStream.read(iv);
			IvParameterSpec initializationVector = new IvParameterSpec(iv);

			// next create the Cipher object in decrypt mode
			Cipher cipher = createCipher();
			cipher.init(Cipher.DECRYPT_MODE, key, initializationVector, new SecureRandom());

			// decrypt input stream to output stream
			CipherOutputStream cos = new CipherOutputStream(outputStream, cipher);
			byte[] buffer = new byte[8192];
			int i = inputStream.read(buffer);

			while (i != -1) {
				cos.write(buffer, 0, i);
				i = inputStream.read(buffer);
			}

			cos.close();
			inputStream.close();
			outputStream.close();

			status = true;
		}
		catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		}
		catch(InvalidKeyException e) {
			e.printStackTrace();
		}
		catch (IOException e) {
			e.printStackTrace();
		}

		return status;
	}

	/**
	 * Encrypts an input stream to an output stream.
	 *
	 * @param inputStream plain text input stream.
	 * @param outputStream encrypted output stream.
	 *
	 * @return true if succeeded, false if failed
	 */
	public boolean encrypt(InputStream inputStream, OutputStream outputStream) {
		boolean status = false;

		try {
			// first create and write the initialization vector
			IvParameterSpec initializationVector = createRandomInitializationVector();
			outputStream.write(initializationVector.getIV());

			// create the cipher object in encrypt mode
			Cipher cipher = createCipher();
			cipher.init(Cipher.ENCRYPT_MODE, key, initializationVector, new SecureRandom()) ;

			// encrypt input stream to output stream
			CipherOutputStream cos = new CipherOutputStream(outputStream, cipher);
			byte[] buffer = new byte[8192];
			int i = inputStream.read(buffer);

			while (i != -1)
			{
				cos.write(buffer, 0, i);
				i = inputStream.read(buffer);
			}

			cos.close();
			inputStream.close();
			outputStream.close();

			status = true;
		}
		catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		}
		catch(InvalidKeyException e) {
			e.printStackTrace();
		}
		catch (IOException e) {
			e.printStackTrace();
		}

		return status;
	}

	/**
	 * Retrieves the encryption key as a byte array.
	 *
	 * @return the encryption key
	 */
	public byte[] getKey()
	{
		return key.getEncoded();
	}

	/**
	 * Initializes the object.
	 *
	 * @param key the key for encryption/decryption.
	 */
	void init(SecretKeySpec key)
	{
		this.key = key;
	}
}
