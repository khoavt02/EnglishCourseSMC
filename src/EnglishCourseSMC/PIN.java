package EnglishCourseSMC;
import javacard.security.MessageDigest;
import javacard.framework.ISOException;
import javacard.framework.ISO7816;
import javacard.framework.JCSystem;
import javacard.framework.Util;

public class PIN {
	private static final byte[] PIN_DEFAULT = new byte[] {(byte) '0', (byte) '0', (byte) '0', (byte) '0', (byte) '0', (byte) '0'};
	
	private static final byte PIN_RETRY_LIMIT = 3;
	
	private final byte[] pin;
	
	private byte retryLimit;
	
	private byte triesRemaining;
	
	private boolean isValidated;
	
	private final MessageDigest messageDigest;
	
	public PIN() {
		this.pin = new byte[16];		// The hash size for the MD5 algorithm is 16 bytes
		this.retryLimit = PIN_RETRY_LIMIT;
		this.triesRemaining = PIN_RETRY_LIMIT;
		this.isValidated = false;
		this.messageDigest = MessageDigest.getInstance(MessageDigest.ALG_MD5, false);
		
		messageDigest.doFinal(PIN_DEFAULT, (short) 0, (short) PIN_DEFAULT.length, pin, (short) 0);
	}
	
	public boolean match(byte[] buffer, byte offset, short length) {
		if (triesRemaining == (byte) 0x00) {
			return false;
		}
		
		byte[] temp = JCSystem.makeTransientByteArray((short) pin.length, JCSystem.CLEAR_ON_DESELECT);
		
		messageDigest.reset();
		messageDigest.doFinal(buffer, (short) offset, length, temp, (short) 0);
		
		if (Util.arrayCompare(pin, (short) 0, temp, (short) 0, (short) pin.length) == (byte) 0x00) {
			triesRemaining = retryLimit;
			isValidated = true;
			return true;
		}
		
		triesRemaining--;
		return false;
	}
	
	public void update(byte[] buffer, byte offset, short length) {
		if (length < 1) {
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		}
		
		messageDigest.reset();
		messageDigest.doFinal(buffer, (short) offset, length, pin, (short) 0);
		triesRemaining = retryLimit;
	}
	
	public void reset() {
		triesRemaining = retryLimit;
		isValidated = false;
	}
	
	public byte[] getPIN() {
		return pin;
	}
	
	public byte getTriesRemaining() {
        return triesRemaining;
    }
    
    public boolean isValidated() {
        return isValidated;
    }
}

