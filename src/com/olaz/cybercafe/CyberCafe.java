package com.olaz.cybercafe;

import javacard.framework.*;

/**
	AID: 06 03 30 26 01 17 00

**/

public class CyberCafe extends Applet
{
	
	private static final byte INS_VERIFY_PIN = (byte) 0x20;
    private static final byte INS_CHANGE_PIN = (byte) 0x21;
    private static final byte INS_GET_PIN_TRIES = (byte) 0x22;
    private static final byte INS_UNBLOCK_PIN = (byte) 0x2C;
    
    private static final byte INS_SET_INFO = (byte)0x50;
	private static final byte INS_GET_INFO = (byte)0x51;
	
    private static final byte PIN_TRY_LIMIT = (byte) 0x03;
    private static final byte MIN_PIN_SIZE = (byte) 0x04;
    private static final byte MAX_PIN_SIZE = (byte) 0x06;
    
    private static final short MAX_ID_SIZE = (short) 10;       // MaHoiVien
    private static final short MAX_USERNAME_SIZE = (short) 20; // TenTaiKhoan
    private static final short MAX_NAME_SIZE = (short) 32;     // HoTen
    private static final short MAX_LEVEL_SIZE = (short) 10;	   // CapDo
    
    private static final byte[] DEFAULT_PIN = {'0', '0', '0', '0'};
	private static final byte SEPARATOR = (byte) 0x7C; // "|"
    
	private byte[] memberId;
    private byte[] username;
    private byte[] fullName;
    private byte[] memberLevel;
    
    private short memberIdLen;
    private short usernameLen;
    private short fullNameLen;
    private short memberLevelLen;
    
	private OwnerPIN pin;

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
	
	private void getPinTries(APDU apdu, byte[] buf) {
        // Ly s ln còn li (Ví d: 3, 2, 1, hoc 0)
        byte tries = pin.getTriesRemaining();
        
        apdu.setOutgoing();
        apdu.setOutgoingLength((short) 1);
        
        buf[0] = tries;
        
        apdu.sendBytes((short) 0, (short) 1);
    }

	// MaHoiVien|TenTaiKhoan|HoTen|CapDoThanhVien
    private void setInfo(APDU apdu, byte[] buf) {
        if (!pin.isValidated()) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);

        short len = apdu.setIncomingAndReceive();
        short start = ISO7816.OFFSET_CDATA;
        short end = (short)(start + len);
        
        // Find separators
        short sep1 = -1, sep2 = -1, sep3 = -1;
        
        for (short i = start; i < end; i++) {
            if (buf[i] == SEPARATOR) {
                if (sep1 == -1) sep1 = i;
                else if (sep2 == -1) sep2 = i;
                else if (sep3 == -1) { sep3 = i; break; }
            }
        }
        
        if (sep1 == -1 || sep2 == -1 || sep3 == -1) ISOException.throwIt(ISO7816.SW_DATA_INVALID);

        short l1 = (short)(sep1 - start); // MaHoiVien
        short l2 = (short)(sep2 - sep1 - 1); // TenTaiKhoan
        short l3 = (short)(sep3 - sep2 - 1); // HoTen
        short l4 = (short)(end - sep3 - 1); // CapDoThanhVien
        
        if (l1 > MAX_ID_SIZE || l2 > MAX_USERNAME_SIZE || l3 > MAX_NAME_SIZE || l4 > MAX_LEVEL_SIZE) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        
        JCSystem.beginTransaction();
            Util.arrayCopy(buf, start, memberId, (short)0, l1);
            memberIdLen = l1;
            
            Util.arrayCopy(buf, (short)(sep1 + 1), username, (short)0, l2);
            usernameLen = l2;
            
            Util.arrayCopy(buf, (short)(sep2 + 1), fullName, (short)0, l3);
            fullNameLen = l3;
            
            Util.arrayCopy(buf, (short)(sep3 + 1), memberLevel, (short)0, l4);
            memberLevelLen = l4;
        JCSystem.commitTransaction();
    }
    
    private void getAllInfo(APDU apdu, byte[] buf) {
        if (!pin.isValidated()) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);

        apdu.setOutgoing();
        
        // Total Length = L1 + 1 + L2 + 1 + L3 + 1 + L4
        short totalLen = (short)(memberIdLen + 1 + usernameLen + 1 + fullNameLen + 1 + memberLevelLen);
        apdu.setOutgoingLength(totalLen);
        
        // Send MaHoiVien
        apdu.sendBytesLong(memberId, (short)0, memberIdLen);
        buf[0] = SEPARATOR; apdu.sendBytes((short)0, (short)1);
        
        // Send TenTaiKhoan
        apdu.sendBytesLong(username, (short)0, usernameLen);
        buf[0] = SEPARATOR; apdu.sendBytes((short)0, (short)1);
        
        // Send HoTen
        apdu.sendBytesLong(fullName, (short)0, fullNameLen);
        buf[0] = SEPARATOR; apdu.sendBytes((short)0, (short)1);
        
        // Send CapDoThanhVien
        apdu.sendBytesLong(memberLevel, (short)0, memberLevelLen);
    }
}
