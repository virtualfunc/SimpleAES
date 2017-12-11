package com.virtualfunc.SimpleAES;

import org.junit.*;
import java.io.*;

public class SimpleAESTest {
	@Test
	public void encrypt() throws Exception {
		String password = "my secret password";
		byte[] passwordSalt = SimpleAES.createSalt();

		// encrypt string
		SimpleAES simpleAES1 = new SimpleAES(password, passwordSalt);
		String plainText = "this is my test string";
		ByteArrayInputStream plainTextInputStream = new ByteArrayInputStream(plainText.getBytes());
		ByteArrayOutputStream encryptedOutputStream = new ByteArrayOutputStream();
		simpleAES1.encrypt(plainTextInputStream, encryptedOutputStream);

		// decrypt string
		SimpleAES simpleAES2 = new SimpleAES(password, passwordSalt);
		ByteArrayInputStream encryptedInputStream = new ByteArrayInputStream(encryptedOutputStream.toByteArray());
		ByteArrayOutputStream decryptedOutputStream = new ByteArrayOutputStream();
		simpleAES2.decrypt(encryptedInputStream, decryptedOutputStream);
		String decryptedText = decryptedOutputStream.toString();

		// did we get the original plain text?
		Assert.assertEquals(plainText, decryptedText);
	}

	@Test
	public void getKey() throws Exception {
		String password = "my secret password";
		byte[] passwordSalt = SimpleAES.createSalt();

		SimpleAES simpleAES1 = new SimpleAES(password, passwordSalt);
		SimpleAES simpleAES2 = new SimpleAES(password, passwordSalt);

		// make sure keys match
		byte[] key1 = simpleAES1.getKey();
		byte[] key2 = simpleAES2.getKey();
		Assert.assertEquals(key1.length, key2.length);

		for (int i = 0; i < key1.length; i++)
		{
			Assert.assertEquals(key1[i], key2[i]);
		}
	}
}
