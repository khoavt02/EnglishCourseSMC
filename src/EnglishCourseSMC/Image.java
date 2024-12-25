package EnglishCourseSMC;
import javacard.framework.Util;
import javacard.security.AESKey;

public class Image {
	public static final short IMAGE_MAX_SIZE = (short) 4096;
	
	private final byte[] data = new byte[IMAGE_MAX_SIZE];
	
	private short size = 0;
	
	public short getData(Cipher cipher, AESKey key, byte[] buffer, short offset) {
		// Util.arrayCopyNonAtomic(data, (short) 0, buffer, offset, size);
		cipher.decrypt(data, (short) 0, IMAGE_MAX_SIZE, key, buffer, offset);
		return size;
	}
	
	public void setData(byte[] buffer, short offset, short length, Cipher cipher, AESKey key) {
		// Util.arrayFillNonAtomic(data, (short) 0, (short) data.length, (byte) 0x00);
		// Util.arrayCopyNonAtomic(buffer, offset, data, (short) 0, length);
		cipher.encrypt(buffer, offset, IMAGE_MAX_SIZE, key, data);
		this.size = length;
	}
}
