package com.olaz.cybercafe;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

public class CyberCafe extends Applet {

    // --- INS Constants ---
    private static final byte INS_VERIFY_PIN = (byte) 0x20;
    private static final byte INS_CHANGE_PIN = (byte) 0x21;
    private static final byte INS_CHECK_LOCK = (byte) 0x22;
    private static final byte INS_UNBLOCK_PIN = (byte) 0x2C;
    private static final byte INS_RESET_TRY = (byte) 0x2D;
    
    private static final byte INS_GET_PUBKEY  = (byte) 0x30;
    private static final byte INS_SIGN_RSA    = (byte) 0x31;
    private static final byte INS_GET_PRIVKEY = (byte) 0x32;
        
    private static final byte INS_SET_INFO = (byte) 0x50;
    private static final byte INS_GET_INFO = (byte) 0x51;
    
    private static final byte INS_GET_IMAGE_CHUNK = (byte) 0x52;
    private static final byte INS_UPLOAD_IMAGE_CHUNK = (byte) 0x53;
    
    private static final byte INS_CREDIT = (byte) 0x40;
    private static final byte INS_DEBIT = (byte) 0x41;
    private static final byte INS_GET_BALANCE = (byte) 0x42;
    private static final byte INS_GET_HISTORY = (byte) 0x43;
    
    // --- Limits & Sizes ---
    private static final byte PIN_TRY_LIMIT = (byte) 0x03;
    private static final byte MIN_PIN_SIZE = (byte) 0x04;
    private static final byte MAX_PIN_SIZE = (byte) 0x06;
    
    private static final short MAX_ID_SIZE = (short) 16;
    private static final short MAX_USERNAME_SIZE = (short) 32;
    private static final short MAX_NAME_SIZE = (short) 64;
    private static final short MAX_LEVEL_SIZE = (short) 16;
    private static final short MAX_IMG_SIZE = (short) 4096;
    
    private static final short MAX_BALANCE = (short) 32767;
    private static final byte MAX_HISTORY_RECORDS = (byte) 10;
    private static final byte TRANSACTION_RECORD_SIZE = (byte) 6;
    
    private static final byte[] DEFAULT_PIN = {'0', '0', '0', '0'};
    
    // --- MASTER CODE FOR RECOVERY ---
    // private static final byte[] MASTER_CODE;
    
    private static final byte SEPARATOR = (byte) 0x7C;
    private static final short AES_KEY_SIZE = (short) 16;
    
    // --- Data Storage ---
    private byte[] memberId;
    private byte[] username;
    private byte[] fullName;
    private byte[] img;
    private byte[] memberLevel;
    private byte[] masterPinStorage;

    private short memberIdLen;
    private short usernameLen;
    private short fullNameLen;
    private short imgLen;
    private short memberLevelLen;
    private short masterPinLen;
    
    private short balance;
    private byte[] transactionHistory;
    private byte historyIndex;
    
    private OwnerPIN pin;
    private AESKey aesKey;
    private Cipher aesCipher;
    private RandomData random;
    
    // --- STATE FLAG ---
    private boolean keyInitialized = false;
    private boolean masterPinSet = false;
    private boolean firstTimeLogin = true;
    
    // --- KEY PROTECTION ---
    private byte[] encryptedAesKey;
    private byte[] encryptedAesKeyBackup;
    
    // SHA-256 Objects
    private MessageDigest sha;
    private byte[] shaBuffer;
    private byte[] ramKeyBuf;
    
    // RSA Objects
    private RSAPrivateKey rsaPrivKey;
    private RSAPublicKey rsaPubKey;
    private Cipher rsaCipher;
    private KeyPair rsaKeyPair;

    private CyberCafe() {
        pin = new OwnerPIN(PIN_TRY_LIMIT, MAX_PIN_SIZE);
        pin.update(DEFAULT_PIN, (short) 0, (byte) DEFAULT_PIN.length);
        
        memberId = new byte[MAX_ID_SIZE];
        username = new byte[MAX_USERNAME_SIZE];
        fullName = new byte[MAX_NAME_SIZE];
        img = new byte[MAX_IMG_SIZE];
        memberLevel = new byte[MAX_LEVEL_SIZE];
        masterPinStorage = new byte[MAX_PIN_SIZE];
        transactionHistory = new byte[(short)(MAX_HISTORY_RECORDS * TRANSACTION_RECORD_SIZE)];
        
        memberIdLen = 0; 
        usernameLen = 0; 
        fullNameLen = 0; 
        imgLen = 0; 
        memberLevelLen = 0;
        balance = 0;
        historyIndex = 0;

        random = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        sha = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        
        shaBuffer = JCSystem.makeTransientByteArray((short) 32, JCSystem.CLEAR_ON_DESELECT);
        ramKeyBuf = JCSystem.makeTransientByteArray(AES_KEY_SIZE, JCSystem.CLEAR_ON_DESELECT);
        
        encryptedAesKey = new byte[AES_KEY_SIZE];
        encryptedAesKeyBackup = new byte[AES_KEY_SIZE];
        
        aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
        aesCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);

        rsaKeyPair = new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_1024);
        rsaCipher = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);
        rsaKeyPair.genKeyPair();
        rsaPrivKey = (RSAPrivateKey) rsaKeyPair.getPrivate();
        rsaPubKey = (RSAPublicKey) rsaKeyPair.getPublic();
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new CyberCafe().register();
    }
    
    public void process(APDU apdu) {
        if (selectingApplet()) return;
        byte[] buf = apdu.getBuffer();
        switch (buf[ISO7816.OFFSET_INS]) {
            case INS_VERIFY_PIN: verifyPin(apdu, buf); break;
            case INS_CHANGE_PIN: changePin(apdu, buf); break;
            case INS_GET_PRIVKEY: getPrivateKey(apdu, buf); break;
            case INS_RESET_TRY: resetTry(); break;
            case INS_UNBLOCK_PIN: resetAndUnblock(apdu, buf); break;
            case INS_GET_PUBKEY: getPublicKey(apdu, buf); break;
            case INS_SIGN_RSA: signRSA(apdu, buf); break;
            case INS_SET_INFO: setInfo(apdu, buf); break;
            case INS_GET_IMAGE_CHUNK: getImageChunk(apdu, apdu.getBuffer()); break;
            case INS_UPLOAD_IMAGE_CHUNK: uploadImageChunk(apdu, buf); break;
            case INS_GET_INFO: getAllInfo(apdu, buf); break;
            case INS_CREDIT: credit(apdu); break;
            case INS_DEBIT: debit(apdu); break;
            case INS_GET_BALANCE: getBalance(apdu); break;
            case INS_GET_HISTORY: getHistory(apdu); break;
            case INS_CHECK_LOCK: checkLock(); break;
            default: ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    private void verifyPin(APDU apdu, byte[] buf) {
        short dataLength = apdu.setIncomingAndReceive();
        
        if (pin.check(buf, ISO7816.OFFSET_CDATA, (byte) dataLength) == false) {
            short triesRemaining = pin.getTriesRemaining();
            if (triesRemaining == 0) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            ISOException.throwIt((short) (0x63C0 | triesRemaining));
        }
        
        if (keyInitialized) {
            deriveKeySha256(buf, ISO7816.OFFSET_CDATA, (byte)dataLength, ramKeyBuf);
            for(short i=0; i<AES_KEY_SIZE; i++) {
                ramKeyBuf[i] = (byte)(encryptedAesKey[i] ^ ramKeyBuf[i]);
            }
            aesKey.setKey(ramKeyBuf, (short)0);
            Util.arrayFillNonAtomic(ramKeyBuf, (short)0, AES_KEY_SIZE, (byte)0);
        }
    }

    private void changePin(APDU apdu, byte[] buf) {
        if (!pin.isValidated()) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        
        short dataLength = apdu.setIncomingAndReceive();
        if (dataLength > MAX_PIN_SIZE || dataLength < MIN_PIN_SIZE) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        
        if (keyInitialized) {
            aesKey.getKey(ramKeyBuf, (short)0);
            pin.update(buf, ISO7816.OFFSET_CDATA, (byte) dataLength);
            encryptAesKeyWithPin(buf, ISO7816.OFFSET_CDATA, (byte) dataLength);
            Util.arrayFillNonAtomic(ramKeyBuf, (short)0, AES_KEY_SIZE, (byte)0);
            firstTimeLogin = false;
        } else {
            pin.update(buf, ISO7816.OFFSET_CDATA, (byte) dataLength);
        }
    }

    private void resetTry() {
        pin.resetAndUnblock();
    }
    
    private void resetAndUnblock(APDU apdu, byte[] buf) {
        pin.resetAndUnblock();
        short dataLength = apdu.setIncomingAndReceive();
        pin.update(DEFAULT_PIN, (short) 0, (byte) DEFAULT_PIN.length);
        
        if (keyInitialized) {
            deriveKeySha256(buf, ISO7816.OFFSET_CDATA, (byte)dataLength, ramKeyBuf);
            for(short i=0; i<AES_KEY_SIZE; i++) {
                ramKeyBuf[i] = (byte)(encryptedAesKeyBackup[i] ^ ramKeyBuf[i]);
            }
            aesKey.setKey(ramKeyBuf, (short)0);
            encryptAesKeyWithPin(DEFAULT_PIN, (short)0, (byte) DEFAULT_PIN.length);
            Util.arrayFillNonAtomic(ramKeyBuf, (short)0, AES_KEY_SIZE, (byte)0);
        }
        
        firstTimeLogin = true;
    }

    private void firstTimeKeyInit() {
        random.generateData(ramKeyBuf, (short)0, AES_KEY_SIZE);
        aesKey.setKey(ramKeyBuf, (short)0);
        encryptAesKeyWithPin(DEFAULT_PIN, (short)0, (byte)DEFAULT_PIN.length);
        encryptAesKeyToBackup(masterPinStorage, (short)0, (byte)masterPinLen);
        Util.arrayFillNonAtomic(ramKeyBuf, (short)0, AES_KEY_SIZE, (byte)0);
        keyInitialized = true;
    }
    
    private void encryptAesKeyWithPin(byte[] pinData, short pinOff, byte pinLen) {
        deriveKeySha256(pinData, pinOff, pinLen, shaBuffer);
        for(short i=0; i<AES_KEY_SIZE; i++) {
            encryptedAesKey[i] = (byte)(ramKeyBuf[i] ^ shaBuffer[i]);
        }
    }
    
    private void encryptAesKeyToBackup(byte[] code, short off, byte len) {
        deriveKeySha256(code, off, len, shaBuffer);
        for(short i=0; i<AES_KEY_SIZE; i++) {
            encryptedAesKeyBackup[i] = (byte)(ramKeyBuf[i] ^ shaBuffer[i]);
        }
    }

    private void deriveKeySha256(byte[] data, short off, short len, byte[] outBuf) {
        sha.doFinal(data, off, len, shaBuffer, (short)0);
        Util.arrayCopy(shaBuffer, (short)0, outBuf, (short)0, AES_KEY_SIZE);
    }

    private void setInfo(APDU apdu, byte[] buf) {
        if (!pin.isValidated()) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        
        short len = apdu.setIncomingAndReceive(); 
        short start = ISO7816.OFFSET_CDATA;
        short sep1 = -1, sep2 = -1, sep3 = -1, sep4 = -1;
        
        for (short i = start; i < (short)(start + len); i++) {
            if (buf[i] == SEPARATOR) {
                if (sep1 == -1) sep1 = i;
                else if (sep2 == -1) sep2 = i;
                else if (sep3 == -1) sep3 = i;
                else if (sep4 == -1) { sep4 = i; break; }
            }
        }

        // if (sep1 == -1 || sep2 == -1 || sep3 == -1 || sep4 == -1) ISOException.throwIt(ISO7816.SW_DATA_INVALID);

        if (!masterPinSet) {
			// Must have exactly 4 separators to provide the Master PIN
			if (sep4 == -1) ISOException.throwIt(ISO7816.SW_DATA_INVALID);

			// Inject the Master PIN
			short mPinLen = (short) (start + len - sep4 - 1);
			if (mPinLen > MAX_PIN_SIZE || mPinLen < MIN_PIN_SIZE) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			Util.arrayCopy(buf, (short) (sep4 + 1), masterPinStorage, (short) 0, mPinLen);
			masterPinSet = true;
			masterPinLen = mPinLen;

			// Generate the AES key using the newly injected Master PIN
			if (!keyInitialized) {
				firstTimeKeyInit(); // Ensure this method uses masterPinStorage for backup
			}
		} 
		// 3. Logic for SUBSEQUENT Updates (Only 4 info fields needed)
		else {
			// If already set, we only accept exactly 3 separators (sep3 found, sep4 must be -1)
			if (sep3 == -1 || sep4 != -1) ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		}

		// 4. Calculate field lengths
		short l1 = (short) (sep1 - start);
		short l2 = (short) (sep2 - sep1 - 1);
		short l3 = (short) (sep3 - sep2 - 1);
		short l4;

		if (sep4 != -1) {
			// If sep4 exists (Initial run), level is between sep3 and sep4
			l4 = (short) (sep4 - sep3 - 1);
		} else {
			// If sep4 is -1 (Update run), level is from sep3 to end of buffer
			l4 = (short) (start + len - sep3 - 1);
		}
		
		

		// 5. Encrypt and store data
		aesCipher.init(aesKey, Cipher.MODE_ENCRYPT);
		byte[] tmp = new byte[64];

		encryptField(buf, start, l1, tmp, memberId);
		encryptField(buf, (short) (sep1 + 1), l2, tmp, username);
		encryptField(buf, (short) (sep2 + 1), l3, tmp, fullName);
		encryptField(buf, (short) (sep3 + 1), l4, tmp, memberLevel);
	}
    
    private void encryptField(byte[] src, short off, short len, byte[] tmpBuf, byte[] dest) {
        short pad = (short)(16 - (len & 0x0F));
        short total = (short)(len + pad);
        Util.arrayCopy(src, off, tmpBuf, (short)0, len);
        for (short i = len; i < total; i++) tmpBuf[i] = (byte) pad;
        short outLen = aesCipher.doFinal(tmpBuf, (short)0, total, tmpBuf, (short)0);
        Util.arrayCopy(tmpBuf, (short)0, dest, (short)0, outLen);
        
        if (dest == memberId) memberIdLen = outLen;
        else if (dest == username) usernameLen = outLen;
        else if (dest == fullName) fullNameLen = outLen;
        else if (dest == memberLevel) memberLevelLen = outLen;
    }

    private void getAllInfo(APDU apdu, byte[] buf) {
        if (!pin.isValidated()) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        if (!keyInitialized) ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
        
        aesCipher.init(aesKey, Cipher.MODE_DECRYPT);

        short p = 0;
        p = decryptField(memberId, memberIdLen, buf, p);
        buf[p++] = SEPARATOR;
        p = decryptField(username, usernameLen, buf, p);
        buf[p++] = SEPARATOR;
        p = decryptField(fullName, fullNameLen, buf, p);
        buf[p++] = SEPARATOR;
        p = decryptField(memberLevel, memberLevelLen, buf, p);
        buf[p++] = SEPARATOR;
		buf[p++] = (byte) (firstTimeLogin ? 0x01 : 0x00);

        apdu.setOutgoingAndSend((short)0, p);
    }
    
    private short decryptField(byte[] src, short len, byte[] dest, short p) {
        short out = aesCipher.doFinal(src, (short)0, len, dest, p);
        short unpad = (short)(dest[(short)(p + out - 1)] & 0xFF);
        if(unpad > 16 || unpad < 1) unpad = 0;
        return (short)(p + out - unpad);
    }
    
    private void getImageChunk(APDU apdu, byte[] buf) {
        if (!pin.isValidated()) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);

        short p1 = (short) (buf[ISO7816.OFFSET_P1] & 0xFF);
        short p2 = (short) (buf[ISO7816.OFFSET_P2] & 0xFF);
        short offset = (short) ((p1 << 8) | p2);

        short chunkSize = 240; 
        if (offset >= imgLen) ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);

        short remaining = (short) (imgLen - offset);
        short lenToSend = (remaining < chunkSize) ? remaining : chunkSize;

        aesCipher.init(aesKey, Cipher.MODE_DECRYPT);
        aesCipher.doFinal(img, offset, lenToSend, buf, (short) 0);
        apdu.setOutgoingAndSend((short) 0, lenToSend);
    }

    private void uploadImageChunk(APDU apdu, byte[] buf) {
        if (!pin.isValidated()) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);

        short len = apdu.setIncomingAndReceive();
        short p1 = (short) (buf[ISO7816.OFFSET_P1] & 0xFF);
        short p2 = (short) (buf[ISO7816.OFFSET_P2] & 0xFF);
        short offset = (short) ((p1 << 8) | p2);

        if (offset == 0) imgLen = 0; 
        if ((short)(offset + len + 16) > MAX_IMG_SIZE) ISOException.throwIt(ISO7816.SW_FILE_FULL);

        aesCipher.init(aesKey, Cipher.MODE_ENCRYPT);
        short pad = (short)(16 - (len & 0x0F));
        short totalLen = (short)(len + pad);
        
        short startData = ISO7816.OFFSET_CDATA;
        for (short i = 0; i < pad; i++) buf[(short)(startData + len + i)] = (byte) pad;

        aesCipher.doFinal(buf, startData, totalLen, img, offset);
        if ((short)(offset + totalLen) > imgLen) imgLen = (short)(offset + totalLen);
    }
    
    private void credit(APDU apdu) {
        //if (!pin.isValidated()) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        byte[] buf = apdu.getBuffer();
        short len = apdu.setIncomingAndReceive();
        if (len < 2) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

        short amount = Util.getShort(buf, ISO7816.OFFSET_CDATA);
        if (amount <= 0 || (short)(balance + amount) > MAX_BALANCE) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }

        JCSystem.beginTransaction();
        balance = (short)(balance + amount);
        recordTransaction(amount, (byte) 0x01); // 0x01 = Credit
        JCSystem.commitTransaction();
    }
    
    private void debit(APDU apdu) {
        if (!pin.isValidated()) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        byte[] buf = apdu.getBuffer();
        short len = apdu.setIncomingAndReceive();
        if (len < 2) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

        short amount = Util.getShort(buf, ISO7816.OFFSET_CDATA);
        if (amount <= 0 || amount > balance) {
            ISOException.throwIt((short) 0x6100); // Insufficient funds error
        }

        JCSystem.beginTransaction();
        balance = (short)(balance - amount);
        recordTransaction(amount, (byte) 0x02); // 0x02 = Debit
        JCSystem.commitTransaction();
    }
    
    private void getBalance(APDU apdu) {
        if (!pin.isValidated()) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        byte[] buf = apdu.getBuffer();
        Util.setShort(buf, (short) 0, balance);
        apdu.setOutgoingAndSend((short) 0, (short) 2);
    }
    
    private void recordTransaction(short amount, byte type) {
        short offset = (short)(historyIndex * TRANSACTION_RECORD_SIZE);
        Util.setShort(transactionHistory, offset, amount);
        transactionHistory[(short)(offset + 2)] = type;
        // Optionally add timestamp or counter bytes at offset+3
        
        historyIndex = (byte)((historyIndex + 1) % MAX_HISTORY_RECORDS);
    }
    
    private void getHistory(APDU apdu) {
        if (!pin.isValidated()) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        short totalSize = (short) transactionHistory.length;
        Util.arrayCopyNonAtomic(transactionHistory, (short) 0, apdu.getBuffer(), (short) 0, totalSize);
        apdu.setOutgoingAndSend((short) 0, totalSize);
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
    
    private void checkLock() {
        if (pin.getTriesRemaining() == 0) ISOException.throwIt((short) 0x6983);
        else ISOException.throwIt(ISO7816.SW_NO_ERROR);
    }
}