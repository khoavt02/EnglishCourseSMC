package EnglishCourseSMC;
import javacard.security.AESKey;

public class Member {
	private final byte[] ID;
	
	private final byte[] fullName;
	
	private final byte[] dateOfBirth;
	
	private final byte[] phoneNumber;
	
	private final Image avatar;
	
	private final byte[] expirationDate;
	
	private final byte[] remainingBalance;
	
	private final Cipher cipher;

	public Member() {
		ID = new byte[32];
		fullName = new byte[16];
		dateOfBirth = new byte[16];
		phoneNumber = new byte[16];
		avatar = new Image();
		expirationDate = new byte[16];
		remainingBalance = new byte[16];

		cipher = new Cipher();
	}

    public short getID(AESKey key, byte[] buffer, short offset) {
	    return cipher.decrypt(ID, (short) 0, (short) ID.length, key, buffer, offset);
    }

    public void setID(byte[] buffer, short offset, short length, AESKey key) {
    	cipher.encrypt(buffer, offset, length, key, ID);
    }

    public short getFullName(AESKey key, byte[] buffer, short offset) {
	    return cipher.decrypt(fullName, (short) 0, (short) fullName.length, key, buffer, offset);
    }
    
    public void setFullName(byte[] buffer, short offset, short length, AESKey key) {
    	cipher.encrypt(buffer, offset, length, key, fullName);
    }
    
    public short getDateOfBirth(AESKey key, byte[] buffer, short offset) {
	    return cipher.decrypt(dateOfBirth, (short) 0, (short) dateOfBirth.length, key, buffer, offset);
    }
    
    public void setDateOfBirth(byte[] buffer, short offset, short length, AESKey key) {
    	cipher.encrypt(buffer, offset, length, key, dateOfBirth);
    }
    
    public short getPhoneNumber(AESKey key, byte[] buffer, short offset) {
	    return cipher.decrypt(phoneNumber, (short) 0, (short) phoneNumber.length, key, buffer, offset);
    }

    public void setPhoneNumber(byte[] buffer, short offset, short length, AESKey key) {
    	cipher.encrypt(buffer, offset, length, key, phoneNumber);
    }
    
    public short getAvatar(AESKey key, byte[] buffer, short offset) {
	    return avatar.getData(cipher, key, buffer, offset);
    }
    
    public void setAvatar(byte[] buffer, short offset, short length, AESKey key) {
    	avatar.setData(buffer, offset, length, cipher, key);
    }

	public short getExpirationDate(AESKey key, byte[] buffer, short offset) {
	    return cipher.decrypt(expirationDate, (short) 0, (short) expirationDate.length, key, buffer, offset);
    }

    public void setExpirationDate(byte[] buffer, short offset, short length, AESKey key) {
    	cipher.encrypt(buffer, offset, length, key, expirationDate);
    }

    public short getRemainingBalance(AESKey key, byte[] buffer, short offset) {
	    return cipher.decrypt(remainingBalance, (short) 0, (short) remainingBalance.length, key, buffer, offset);
    }

    public void setRemainingBalance(byte[] buffer, short offset, short length, AESKey key) {
    	cipher.encrypt(buffer, offset, length, key, remainingBalance);
    }
}
