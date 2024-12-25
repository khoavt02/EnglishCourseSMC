package EnglishCourseSMC;
public class Command {
	public static final byte INS_AUTHENTICATION = (byte) 0x00;
	
	public static final byte INS_CREATE = (byte) 0x01;
	public static final byte INS_GET = (byte) 0x02;
	public static final byte INS_UPDATE = (byte) 0x03;
	public static final byte INS_UNLOCK = (byte) 0x04;
	
	public static final byte P1_PIN = (byte) 0x00;
	public static final byte P1_MEMBER = (byte) 0x01;
	public static final byte P1_SIGNATURE = (byte) 0x02;

	public static final byte P2_PROFILE = (byte) 0x00;
	public static final byte P2_EXPIRATION_DATE = (byte) 0x04;
	public static final byte P2_REMAINING_BALANCE = (byte) 0x05;
	public static final byte P2_AVATAR = (byte) 0x06;
}
