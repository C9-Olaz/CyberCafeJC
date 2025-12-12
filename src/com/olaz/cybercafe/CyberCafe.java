package com.olaz.cybercafe;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

/**
	AID: 06 03 30 26 01 17 00

**/

public class CyberCafe extends Applet
{
	
	private static final byte INS_VERIFY_PIN = (byte) 0x20;
	private static final byte INS_CHANGE_PIN = (byte) 0x21;
	private static final byte INS_CHECK_LOCK = (byte) 0x22;
	private static final byte INS_UNBLOCK_PIN = (byte) 0x2C;
		
	private static final byte INS_SET_INFO = (byte)0x50;
	private static final byte INS_GET_INFO = (byte)0x51;
	
	private static final byte PIN_TRY_LIMIT = (byte) 0x03;
	private static final byte MIN_PIN_SIZE = (byte) 0x04;
	private static final byte MAX_PIN_SIZE = (byte) 0x06;
	
	private static final short MAX_ID_SIZE = (short) 16;
	private static final short MAX_USERNAME_SIZE = (short) 32;
	private static final short MAX_NAME_SIZE = (short) 32;
	private static final short MAX_LEVEL_SIZE = (short) 16;
	
	private static final byte[] DEFAULT_PIN = {'0', '0', '0', '0'};
	private static final byte SEPARATOR = (byte) 0x7C;
	
	private byte[] memberId;
	private byte[] username;
	private byte[] fullName;
	private byte[] memberLevel;
	
	private short memberIdLen;
	private short usernameLen;
	private short fullNameLen;
	private short memberLevelLen;
	
	private OwnerPIN pin;

	private AESKey aesKey;
	private Cipher aesCipher;
	private RandomData random;

	private CyberCafe() {
		pin = new OwnerPIN(PIN_TRY_LIMIT, MAX_PIN_SIZE);
		
		byte[] defaultPin = {'0', '0', '0', '0'};
		pin.update(DEFAULT_PIN, (short) 0, (byte) DEFAULT_PIN.length);
		
		memberId = new byte[MAX_ID_SIZE];
		username = new byte[MAX_USERNAME_SIZE];
		fullName = new byte[MAX_NAME_SIZE];
		memberLevel = new byte[MAX_LEVEL_SIZE];
		
		memberIdLen = 0;
		usernameLen = 0;
		fullNameLen = 0;
		memberLevelLen = 0;

		random = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
		aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
		byte[] keyData = new byte[16];
		random.generateData(keyData, (short)0, (short)16);
		aesKey.setKey(keyData, (short)0);

		aesCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);
	}

	public static void install(byte[] bArray, short bOffset, byte bLength) 
	{
		new CyberCafe().register(bArray, (short) (bOffset + 1), bArray[bOffset]);
	}
	

	public void process(APDU apdu)
	{
		if (selectingApplet())
		{
			return;
		}

		byte[] buf = apdu.getBuffer();
		switch (buf[ISO7816.OFFSET_INS])
		{
		case INS_VERIFY_PIN:
			verifyPin(apdu, buf);
			break;
			
		case INS_CHANGE_PIN:
			changePin(apdu, buf);
			break;
			
		case INS_UNBLOCK_PIN:
			resetAndUnblock();
			break;
			
		case INS_SET_INFO:
			setInfo(apdu, buf);
			break;
			
		case INS_GET_INFO:
			getAllInfo(apdu, buf);
			break;
		
		case INS_CHECK_LOCK:
			checkLock();
			break;
		default:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}
	
	private void verifyPin(APDU apdu, byte[] buf) {
		short dataLength = apdu.setIncomingAndReceive();
		
		if (pin.check(buf, ISO7816.OFFSET_CDATA, (byte) dataLength) == false) {
			short triesRemaining = pin.getTriesRemaining();
			
			if (triesRemaining == 0) {
				ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
			}
			
			ISOException.throwIt( (short) (0x63C0 | triesRemaining));
		}
	}
	
	private void changePin(APDU apdu, byte[] buf) {
		if (!pin.isValidated()) {
			ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
		}
		
		short dataLength = apdu.setIncomingAndReceive();
		
		if (dataLength > MAX_PIN_SIZE|| dataLength < MIN_PIN_SIZE) {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}
		
		pin.update(buf, ISO7816.OFFSET_CDATA, (byte) dataLength);
	}
	
	private void resetAndUnblock() {
		pin.resetAndUnblock();
		pin.update(DEFAULT_PIN, (short) 0, (byte) DEFAULT_PIN.length);
	}
	
	private void checkLock() {
		if (pin.getTriesRemaining() == 0) {
			ISOException.throwIt((short) 0x6983);
		} else {
			ISOException.throwIt(ISO7816.SW_NO_ERROR);
		}
	}
	
	private void setInfo(APDU apdu, byte[] buf) {
		if (!pin.isValidated()) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);

		short len = apdu.setIncomingAndReceive();
		short start = ISO7816.OFFSET_CDATA;
		short end = (short)(start + len);

		short sep1 = -1, sep2 = -1, sep3 = -1;
		for (short i = start; i < end; i++) {
			if (buf[i] == SEPARATOR) {
				if (sep1 == -1) sep1 = i;
				else if (sep2 == -1) sep2 = i;
				else if (sep3 == -1) { sep3 = i; break; }
			}
		}

		if (sep1 == -1 || sep2 == -1 || sep3 == -1) ISOException.throwIt(ISO7816.SW_DATA_INVALID);

		short l1 = (short)(sep1 - start);
		short l2 = (short)(sep2 - sep1 - 1);
		short l3 = (short)(sep3 - sep2 - 1);
		short l4 = (short)(end - sep3 - 1);

		if (l1 > MAX_ID_SIZE || l2 > MAX_USERNAME_SIZE || l3 > MAX_NAME_SIZE || l4 > MAX_LEVEL_SIZE) {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}

		byte[] tmp = new byte[MAX_NAME_SIZE]; // Temp buffer for padding
		aesCipher.init(aesKey, Cipher.MODE_ENCRYPT);

		// memberId
		{
			short pad = (short)(16 - (l1 & 0x0F));
			short total = (short)(l1 + pad);
			Util.arrayCopy(buf, start, tmp, (short)0, l1);
			for (short i = l1; i < total; i++) tmp[i] = (byte) pad;
			// Result stored in this.memberId
			memberIdLen = aesCipher.doFinal(tmp, (short)0, total, memberId, (short)0);
		}

		// username
		{
			short pad = (short)(16 - (l2 & 0x0F));
			short total = (short)(l2 + pad);
			Util.arrayCopy(buf, (short)(sep1 + 1), tmp, (short)0, l2);
			for (short i = l2; i < total; i++) tmp[i] = (byte) pad;
			// Result stored in this.username
			usernameLen = aesCipher.doFinal(tmp, (short)0, total, username, (short)0);
		}

		// fullName
		{
			short pad = (short)(16 - (l3 & 0x0F));
			short total = (short)(l3 + pad);
			Util.arrayCopy(buf, (short)(sep2 + 1), tmp, (short)0, l3);
			for (short i = l3; i < total; i++) tmp[i] = (byte) pad;
			// Result stored in this.fullName
			fullNameLen = aesCipher.doFinal(tmp, (short)0, total, fullName, (short)0);
		}

		// memberLevel
		{
			short pad = (short)(16 - (l4 & 0x0F));
			short total = (short)(l4 + pad);
			Util.arrayCopy(buf, (short)(sep3 + 1), tmp, (short)0, l4);
			for (short i = l4; i < total; i++) tmp[i] = (byte) pad;
			// Result stored in this.memberLevel
			memberLevelLen = aesCipher.doFinal(tmp, (short)0, total, memberLevel, (short)0);
		}

		short outOffset = 0;

		// Append Encrypted Member ID
		Util.arrayCopy(memberId, (short)0, buf, outOffset, memberIdLen);
		outOffset += memberIdLen;

		// Append Encrypted Username
		Util.arrayCopy(username, (short)0, buf, outOffset, usernameLen);
		outOffset += usernameLen;

		// Append Encrypted FullName
		Util.arrayCopy(fullName, (short)0, buf, outOffset, fullNameLen);
		outOffset += fullNameLen;

		// Append Encrypted Level
		Util.arrayCopy(memberLevel, (short)0, buf, outOffset, memberLevelLen);
		outOffset += memberLevelLen;

		// Send the response
		apdu.setOutgoing();
		apdu.setOutgoingLength(outOffset);
		apdu.sendBytes((short)0, outOffset);
	}

	private void getAllInfo(APDU apdu, byte[] buf) {
		if (!pin.isValidated()) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);

		aesCipher.init(aesKey, Cipher.MODE_DECRYPT);

		short p = 0;
		// decrypt memberId
		{
			short out = aesCipher.doFinal(memberId, (short)0, memberIdLen, buf, p);
			short unpad = (short)(buf[(short)(p + out - 1)] & 0xFF);
			out -= unpad;
			p += out;
			buf[p++] = SEPARATOR;
		}

		// decrypt username
		{
			short out = aesCipher.doFinal(username, (short)0, usernameLen, buf, p);
			short unpad = (short)(buf[(short)(p + out - 1)] & 0xFF);
			out -= unpad;
			p += out;
			buf[p++] = SEPARATOR;
		}

		// decrypt fullName
		{
			short out = aesCipher.doFinal(fullName, (short)0, fullNameLen, buf, p);
			short unpad = (short)(buf[(short)(p + out - 1)] & 0xFF);
			out -= unpad;
			p += out;
			buf[p++] = SEPARATOR;
		}

		// decrypt memberLevel
		{
			short out = aesCipher.doFinal(memberLevel, (short)0, memberLevelLen, buf, p);
			short unpad = (short)(buf[(short)(p + out - 1)] & 0xFF);
			out -= unpad;
			p += out;
		}

		apdu.setOutgoing();
		apdu.setOutgoingLength(p);
		apdu.sendBytes((short)0, p);
	}

}
