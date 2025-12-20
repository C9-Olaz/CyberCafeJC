package com.olaz.cybercafe;

// import java.applet.Applet;
// import java.security.KeyPair;
// import java.security.interfaces.RSAPrivateKey;
// import java.security.interfaces.RSAPublicKey;

// import javax.crypto.Cipher;
// import javax.rmi.CORBA.Util;

// import java.applet.Applet;
// import java.security.KeyPair;
// import java.security.interfaces.RSAPrivateKey;
// import java.security.interfaces.RSAPublicKey;

// import javax.crypto.Cipher;
// import javax.rmi.CORBA.Util;

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
	private static final byte INS_RESET_TRY = (byte) 0x2D;
	private static final byte INS_GET_IMAGE_CHUNK = (byte) 0x52;
	private static final byte INS_UPLOAD_IMAGE_CHUNK = (byte) 0x53;
	
    private static final byte INS_GET_PUBKEY  = (byte) 0x30;
    private static final byte INS_SIGN_RSA    = (byte) 0x31;
    private static final byte INS_GET_PRIVKEY = (byte) 0x32;
		
	private static final byte INS_SET_INFO = (byte)0x50;
	private static final byte INS_GET_INFO = (byte)0x51;
	
	private static final byte PIN_TRY_LIMIT = (byte) 0x03;
	private static final byte MIN_PIN_SIZE = (byte) 0x04;
	private static final byte MAX_PIN_SIZE = (byte) 0x06;
	
	private static final short MAX_ID_SIZE = (short) 16;
	private static final short MAX_USERNAME_SIZE = (short) 32;
	private static final short MAX_NAME_SIZE = (short) 64;
	private static final short MAX_LEVEL_SIZE = (short) 16;
	private static final short MAX_IMG_SIZE = (short) 4096;
	
	private static final byte[] DEFAULT_PIN = {'0', '0', '0', '0'};
	private static final byte SEPARATOR = (byte) 0x7C;
	
	private byte[] memberId;
	private byte[] username;
	private byte[] fullName;
	private byte[] img;
	private byte[] memberLevel;
	
	private short memberIdLen;
	private short usernameLen;
	private short fullNameLen;
	private short imgLen;
	private short memberLevelLen;
	
	private OwnerPIN pin;

	private AESKey aesKey;
	private Cipher aesCipher;
	private RandomData random;
	
	private RSAPrivateKey rsaPrivKey;
    private RSAPublicKey rsaPubKey;
    private Cipher rsaCipher;
    private KeyPair rsaKeyPair;

	private CyberCafe() {
		pin = new OwnerPIN(PIN_TRY_LIMIT, MAX_PIN_SIZE);
		
		byte[] defaultPin = {'0', '0', '0', '0'};
		pin.update(DEFAULT_PIN, (short) 0, (byte) DEFAULT_PIN.length);
		
		memberId = new byte[MAX_ID_SIZE];
		username = new byte[MAX_USERNAME_SIZE];
		fullName = new byte[MAX_NAME_SIZE];
		img = new byte[MAX_IMG_SIZE];
		memberLevel = new byte[MAX_LEVEL_SIZE];
		
		memberIdLen = 0;
		usernameLen = 0;
		fullNameLen = 0;
		imgLen = 0;
		memberLevelLen = 0;

		random = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
		aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
		byte[] keyData = new byte[16];
		random.generateData(keyData, (short)0, (short)16);
		aesKey.setKey(keyData, (short)0);

		aesCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);
		
		rsaKeyPair = new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_1024);
        rsaCipher = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);
        
        rsaKeyPair.genKeyPair();
        rsaPrivKey = (RSAPrivateKey) rsaKeyPair.getPrivate();
        rsaPubKey = (RSAPublicKey) rsaKeyPair.getPublic();
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
				
		case INS_GET_PRIVKEY:
            getPrivateKey(apdu, buf);
			break;
			
		case INS_RESET_TRY:
			resetTry();
			break;
			
		case INS_UNBLOCK_PIN:
			resetAndUnblock();
			break;
			
		case INS_GET_PUBKEY:
			getPublicKey(apdu, buf);
			break;
		
		case INS_SIGN_RSA:
			signRSA(apdu, buf);
			break;
			
		case INS_SET_INFO:
			setInfo(apdu, buf);
			break;
			
		case INS_GET_IMAGE_CHUNK:
			getImageChunk(apdu, apdu.getBuffer());
			break;

		case INS_UPLOAD_IMAGE_CHUNK: // 2. Add this case
			uploadImageChunk(apdu, buf);
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
	
	private void signRSA(APDU apdu, byte[] buf) {
        short len = apdu.setIncomingAndReceive();
        
        rsaCipher.init(rsaPrivKey, Cipher.MODE_ENCRYPT); 
        
        short outLen = rsaCipher.doFinal(buf, ISO7816.OFFSET_CDATA, len, buf, (short)0);
        
        apdu.setOutgoingAndSend((short)0, outLen);
    }

    private void getPublicKey(APDU apdu, byte[] buf) {
        short modLen = rsaPubKey.getModulus(buf, (short)0);
		apdu.setOutgoingAndSend((short)0, modLen);
    }
    
    private void getPrivateKey(APDU apdu, byte[] buf) {
		short len = rsaPrivKey.getExponent(buf, (short) 0);
		apdu.setOutgoingAndSend((short) 0, len);
	}
	
	private void resetAndUnblock() {
		pin.resetAndUnblock();
		pin.update(DEFAULT_PIN, (short) 0, (byte) DEFAULT_PIN.length);
	}

	private void resetTry() {
		pin.resetAndUnblock();
	}
	
	private void checkLock() {
		if (pin.getTriesRemaining() == 0) {
			ISOException.throwIt((short) 0x6983);
		} else {
			ISOException.throwIt(ISO7816.SW_NO_ERROR);
		}
	}

	private void saveImageInternal(byte[] source, short offset, short length) {
        // Check size (Image + 16 bytes padding limit)
        if ((short)(length + 16) > (short)img.length) {
            ISOException.throwIt(ISO7816.SW_FILE_FULL);
        }

        aesCipher.init(aesKey, Cipher.MODE_ENCRYPT);

        // Calculate Bulk vs Tail
        short tailLen = (short)(length % 16); 
        short bulkLen = (short)(length - tailLen);
        short bytesWritten = 0;

        // Encrypt Bulk (Directly from Source -> Persistent Storage)
        if (bulkLen > 0) {
            bytesWritten = aesCipher.update(source, offset, bulkLen, img, (short)0);
        }

        // Encrypt Tail (Using a tiny temp buffer for padding)
        byte[] tmpBlock = new byte[32]; 
        Util.arrayCopy(source, (short)(offset + bulkLen), tmpBlock, (short)0, tailLen);
        
        // Add Padding
        short pad = (short)(16 - (length & 0x0F));
        short totalTail = (short)(tailLen + pad); 
        for (short i = tailLen; i < totalTail; i++) tmpBlock[i] = (byte) pad;

        // Finalize
        bytesWritten += aesCipher.doFinal(tmpBlock, (short)0, totalTail, img, bytesWritten);
        
        // Update global length
        imgLen = bytesWritten;
    }
	
	private void setInfo(APDU apdu, byte[] buf) {
    if (!pin.isValidated()) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);

    short len = apdu.setIncomingAndReceive(); 
    short start = ISO7816.OFFSET_CDATA;
    short sep1 = -1, sep2 = -1, sep3 = -1;
    
    for (short i = start; i < (short)(start + len); i++) {
        if (buf[i] == SEPARATOR) {
            if (sep1 == -1) sep1 = i;
            else if (sep2 == -1) sep2 = i;
            else if (sep3 == -1) { 
                sep3 = i; 
                break; 
            }
        }
    }

    if (sep1 == -1 || sep2 == -1 || sep3 == -1) {
        ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }

    // Text Lengths
    short l1 = (short)(sep1 - start);           // ID
    short l2 = (short)(sep2 - sep1 - 1);        // User
    short l3 = (short)(sep3 - sep2 - 1);        // Name
    short l4 = (short)(start + len - sep3 - 1); // Level 

    // --- ENCRYPT TEXT ---
    byte[] tmp = new byte[64]; 
    aesCipher.init(aesKey, Cipher.MODE_ENCRYPT);

    // Member ID
    {
        short pad = (short)(16 - (l1 & 0x0F));
        short total = (short)(l1 + pad);
        Util.arrayCopy(buf, start, tmp, (short)0, l1);
        for (short i = l1; i < total; i++) tmp[i] = (byte) pad;
        memberIdLen = aesCipher.doFinal(tmp, (short)0, total, memberId, (short)0);
    }
    
    // Username
    {
        short pad = (short)(16 - (l2 & 0x0F));
        short total = (short)(l2 + pad);
        Util.arrayCopy(buf, (short)(sep1 + 1), tmp, (short)0, l2);
        for (short i = l2; i < total; i++) tmp[i] = (byte) pad;
        usernameLen = aesCipher.doFinal(tmp, (short)0, total, username, (short)0);
    }

    // FullName
    {
        short pad = (short)(16 - (l3 & 0x0F));
        short total = (short)(l3 + pad);
        Util.arrayCopy(buf, (short)(sep2 + 1), tmp, (short)0, l3);
        for (short i = l3; i < total; i++) tmp[i] = (byte) pad;
        fullNameLen = aesCipher.doFinal(tmp, (short)0, total, fullName, (short)0);
    }

    // Level
    {
        short pad = (short)(16 - (l4 & 0x0F));
        short total = (short)(l4 + pad);
        Util.arrayCopy(buf, (short)(sep3 + 1), tmp, (short)0, l4);
        for (short i = l4; i < total; i++) tmp[i] = (byte) pad;
        memberLevelLen = aesCipher.doFinal(tmp, (short)0, total, memberLevel, (short)0);
    }

}

	// private void setInfo(APDU apdu, byte[] buf) {
    //     if (!pin.isValidated()) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);

    //     // Extended APDU allows receiving > 255 bytes here
    //     int len = apdu.setIncomingAndReceive(); 
    //     short start = ISO7816.OFFSET_CDATA;
    //     short end = (short)(start + len);

    //     short sep1 = -1, sep2 = -1, sep3 = -1, sep4 = -1;
        
    //     // Scan for separators
    //     for (short i = start; i < end; i++) {
    //         if (buf[i] == SEPARATOR) {
    //             if (sep1 == -1) sep1 = i;
    //             else if (sep2 == -1) sep2 = i;
    //             else if (sep3 == -1) sep3 = i;
    //             else if (sep4 == -1) { 
    //                 sep4 = i; 
    //                 break; // STOP scanning to protect image binary
    //             }
    //         }
    //     }

    //     if (sep1 == -1 || sep2 == -1 || sep3 == -1 || sep4 == -1) {
    //         ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    //     }

    //     // Text Lengths
    //     short l1 = (short)(sep1 - start);           // ID
    //     short l2 = (short)(sep2 - sep1 - 1);        // User
    //     short l3 = (short)(sep3 - sep2 - 1);        // Name
    //     short l4 = (short)(sep4 - sep3 - 1);        // Level

    //     // --- ENCRYPT TEXT (Standard Logic) ---
    //     byte[] tmp = new byte[64]; 
    //     aesCipher.init(aesKey, Cipher.MODE_ENCRYPT);

    //     // Member ID
    //     {
    //         short pad = (short)(16 - (l1 & 0x0F));
    //         short total = (short)(l1 + pad);
    //         Util.arrayCopy(buf, start, tmp, (short)0, l1);
    //         for (short i = l1; i < total; i++) tmp[i] = (byte) pad;
    //         memberIdLen = aesCipher.doFinal(tmp, (short)0, total, memberId, (short)0);
    //     }
        
    //     // Username
    //     {
    //         short pad = (short)(16 - (l2 & 0x0F));
    //         short total = (short)(l2 + pad);
    //         Util.arrayCopy(buf, (short)(sep1 + 1), tmp, (short)0, l2);
    //         for (short i = l2; i < total; i++) tmp[i] = (byte) pad;
    //         usernameLen = aesCipher.doFinal(tmp, (short)0, total, username, (short)0);
    //     }

    //     // FullName
    //     {
    //         short pad = (short)(16 - (l3 & 0x0F));
    //         short total = (short)(l3 + pad);
    //         Util.arrayCopy(buf, (short)(sep2 + 1), tmp, (short)0, l3);
    //         for (short i = l3; i < total; i++) tmp[i] = (byte) pad;
    //         fullNameLen = aesCipher.doFinal(tmp, (short)0, total, fullName, (short)0);
    //     }

    //     // Level
    //     {
    //         short pad = (short)(16 - (l4 & 0x0F));
    //         short total = (short)(l4 + pad);
    //         Util.arrayCopy(buf, (short)(sep3 + 1), tmp, (short)0, l4);
    //         for (short i = l4; i < total; i++) tmp[i] = (byte) pad;
    //         memberLevelLen = aesCipher.doFinal(tmp, (short)0, total, memberLevel, (short)0);
    //     }

    //     // --- ENCRYPT IMAGE (Using Helper) ---
    //     short imgStart = (short)(sep4 + 1);
    //     short imgLength = (short)(end - imgStart);
        
    //     saveImageInternal(buf, imgStart, imgLength);

    //     // --- SEND RESPONSE (Text Only) ---
    //     short outOffset = 0;
    //     Util.arrayCopy(memberId, (short)0, buf, outOffset, memberIdLen);
    //     outOffset += memberIdLen;
    //     Util.arrayCopy(username, (short)0, buf, outOffset, usernameLen);
    //     outOffset += usernameLen;
    //     Util.arrayCopy(fullName, (short)0, buf, outOffset, fullNameLen);
    //     outOffset += fullNameLen;
    //     Util.arrayCopy(memberLevel, (short)0, buf, outOffset, memberLevelLen);
    //     outOffset += memberLevelLen;
        
    //     apdu.setOutgoingAndSend((short)0, outOffset);
    // }

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
	
	private void getImageChunk(APDU apdu, byte[] buf) {
    // 1. Check PIN
    if (!pin.isValidated()) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);

    // 2. Parse Offset from P1 and P2
    short p1 = (short) (buf[ISO7816.OFFSET_P1] & 0xFF);
    short p2 = (short) (buf[ISO7816.OFFSET_P2] & 0xFF);
    short offset = (short) ((p1 << 8) | p2);

    // 3. Determine how many bytes to read
    // We generally send 240 bytes per chunk to be safe with all readers
    short chunkSize = 240; 

    if (offset >= imgLen) ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND); // End of file

    short remaining = (short) (imgLen - offset);
    short lenToSend = (remaining < chunkSize) ? remaining : chunkSize;

    // 4. Decrypt DIRECTLY from Flash (img) to Buffer (buf)
    // Since we use AES-ECB, we can decrypt independent blocks!
    // Note: 'offset' and 'chunkSize' must be multiples of 16 for AES, 
    // but since we handle padding in the client, we just decrypt raw bytes here.

    aesCipher.init(aesKey, Cipher.MODE_DECRYPT);

    // We use doFinal because in ECB mode, every block is independent. 
    // We treat this chunk as a standalone decryption operation.
    aesCipher.doFinal(img, offset, lenToSend, buf, (short) 0);

    // 5. Send
    apdu.setOutgoingAndSend((short) 0, lenToSend);
}

private void uploadImageChunk(APDU apdu, byte[] buf) {
        if (!pin.isValidated()) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);

        short len = apdu.setIncomingAndReceive();
        
        // Parse Offset from P1 (High) and P2 (Low)
        short p1 = (short) (buf[ISO7816.OFFSET_P1] & 0xFF);
        short p2 = (short) (buf[ISO7816.OFFSET_P2] & 0xFF);
        short offset = (short) ((p1 << 8) | p2);

        if (offset == 0) imgLen = 0; // Reset length if new upload starts

        if ((short)(offset + len + 16) > MAX_IMG_SIZE) ISOException.throwIt(ISO7816.SW_FILE_FULL);

        aesCipher.init(aesKey, Cipher.MODE_ENCRYPT);
        
        // Calculate Padding (Must be multiple of 16 for AES)
        short pad = (short)(16 - (len & 0x0F));
        short totalLen = (short)(len + pad);
        
        // Append padding to the buffer (after the data)
        short startData = ISO7816.OFFSET_CDATA;
        for (short i = 0; i < pad; i++) {
            buf[(short)(startData + len + i)] = (byte) pad;
        }

        // Encrypt directly from Buffer -> Image Storage at correct offset
        aesCipher.doFinal(buf, startData, totalLen, img, offset);

        // Update global image length
        if ((short)(offset + totalLen) > imgLen) {
            imgLen = (short)(offset + totalLen);
        }
    }
}
// private void getAllInfo(APDU apdu, byte[] buf) {
    // if (!pin.isValidated()) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);

    // aesCipher.init(aesKey, Cipher.MODE_DECRYPT);

    // short p = 0;

    // // 1. Decrypt memberId
    // {
        // short out = aesCipher.doFinal(memberId, (short)0, memberIdLen, buf, p);
        // short unpad = (short)(buf[(short)(p + out - 1)] & 0xFF);
        // out -= unpad;
        // p += out;
        // buf[p++] = SEPARATOR;
    // }

    // // 2. Decrypt username
    // {
        // short out = aesCipher.doFinal(username, (short)0, usernameLen, buf, p);
        // short unpad = (short)(buf[(short)(p + out - 1)] & 0xFF);
        // out -= unpad;
        // p += out;
        // buf[p++] = SEPARATOR;
    // }

    // // 3. Decrypt fullName
    // {
        // short out = aesCipher.doFinal(fullName, (short)0, fullNameLen, buf, p);
        // short unpad = (short)(buf[(short)(p + out - 1)] & 0xFF);
        // out -= unpad;
        // p += out;
        // buf[p++] = SEPARATOR;
    // }

    // // 4. Decrypt memberLevel
    // {
        // short out = aesCipher.doFinal(memberLevel, (short)0, memberLevelLen, buf, p);
        // short unpad = (short)(buf[(short)(p + out - 1)] & 0xFF);
        // out -= unpad;
        // p += out;
        
        // // Separator between Text and Image
        // buf[p++] = SEPARATOR;
    // }

    // // --- PHASE 2: Send Response ---

    // // Note: Since we use NOPAD in constructor and manually padded the image in saveImageInternal,
    // // the decrypted size is EQUAL to the encrypted size (imgLen).
    // // The padding bytes (e.g., 05 05 05...) will be sent to the client.
    // // Your Kotlin client's removePadding() function will strip them.
    // short totalLen = (short)(p + imgLen);

    // apdu.setOutgoing();
    // apdu.setOutgoingLength(totalLen);

    // // 1. Send the Text Data
    // apdu.sendBytes((short)0, p);

    // // 2. Stream the Image Data (FIXED LOGIC)
    // if (imgLen > 0) {
        // // Re-init cipher for the long image stream
        // aesCipher.init(aesKey, Cipher.MODE_DECRYPT);
        
        // short offset = 0;
        // short bytesLeft = imgLen;
        // short chunkSize = 240; // Max buffer size safe for APDU buffer
        
        // while (bytesLeft > 0) {
            // short toProcess = (bytesLeft > chunkSize) ? chunkSize : bytesLeft;
            // short len = 0;
            
            // // Check if this is the LAST chunk
            // if (bytesLeft > chunkSize) {
                // // NOT the last chunk -> Use update() to keep stream open
                // len = aesCipher.update(img, offset, toProcess, buf, (short)0);
            // } else {
                // // IS the last chunk -> Use doFinal() to finish and unpad (if needed)
                // len = aesCipher.doFinal(img, offset, toProcess, buf, (short)0);
            // }
            
            // // Send the decrypted chunk
            // apdu.sendBytes((short)0, len);
            
            // offset += toProcess;
            // bytesLeft -= toProcess;
        // }
    // }
// }


