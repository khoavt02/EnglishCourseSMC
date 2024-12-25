package EnglishCourseSMC;

import javacard.framework.Applet;
import javacard.framework.APDU;
import javacard.framework.JCSystem;
import javacard.framework.ISOException;
import javacard.framework.ISO7816;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.Signature;
import javacard.security.KeyPair;
import javacard.security.RSAPrivateKey;
import javacard.security.RSAPublicKey;
import javacard.security.KeyBuilder;
import javacardx.apdu.ExtendedLength;

import static EnglishCourseSMC.Command.*;

/**
 * EnglishCourseSMC - EnglishCourse Smart Card
 * 
 * @AID: 
 */

public class EnglishCourseSMCApplet extends Applet implements ExtendedLength {
	private final PIN pin;

	private final AESKey key;

	private final Signature signature;

	private final byte[] avatarBuffer;

	private final byte[] signatureBuffer;

	private Member member;

	private RSAPrivateKey privateKey;

	private RSAPublicKey publicKey;

	public EnglishCourseSMCApplet() {
		pin = new PIN();
		
		// Initialization AES Key
		key = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, (short) 128, false);
		
		// Initialization Signature
		signature = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
		
		// Initialization buffers
		avatarBuffer = new byte[Image.IMAGE_MAX_SIZE];
		signatureBuffer = JCSystem.makeTransientByteArray((short) (KeyBuilder.LENGTH_RSA_1024 / 8), JCSystem.CLEAR_ON_RESET);
	}

	public void process(APDU apdu) throws ISOException {
		if (selectingApplet()) {
			return;
		}

		byte[] buffer = apdu.getBuffer();
		
		switch (buffer[ISO7816.OFFSET_INS]) {
			case INS_AUTHENTICATION:
				authentication(apdu);
				break;
				
			case INS_CREATE:
				create(apdu);
				break;
			
			case INS_GET:
				getMember(apdu);
				break;
				
			case INS_UPDATE:
				update(apdu);
				break;
				
			case INS_UNLOCK:
				unlock(apdu);
				break;
				
			default:
				ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}
	
	private void authentication(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		byte offset = ISO7816.OFFSET_CDATA;
		short length = buffer[ISO7816.OFFSET_LC];
		
		if (pin.match(buffer, offset, length)) {
			return;
		}
		
		// Throw wrong PIN exception with tries remaining
		buffer[ISO7816.OFFSET_CDATA] = pin.getTriesRemaining();
		apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short) 1);
		ISOException.throwIt(ISO7816.SW_WRONG_DATA);
	}
	
	private void create(APDU apdu) throws ISOException {
		byte[] buffer = apdu.getBuffer();
		
		switch (buffer[ISO7816.OFFSET_P1]) {
			case P1_MEMBER:
				createMember(apdu);
				break;
				
			case P1_SIGNATURE:
				createSignature(apdu);
				break;
				
			default:
				ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
		}
	}
	
	private void createMember(APDU apdu) throws ISOException {
		if (member != null) {	// Member has been created
			ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
		}
		
		byte[] buffer = apdu.getBuffer();
		
		if (buffer[ISO7816.OFFSET_LC] == (byte) 0x00) {	// Data is empty
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		}
		
		byte offset;
		short length;
		
		key.setKey(pin.getPIN(), (short) 0);
		
		// Create new Member
		JCSystem.beginTransaction();
		member = new Member();

		offset = ISO7816.OFFSET_CDATA;
		length = (short) buffer[offset];
		member.setID(buffer, (short) (offset + 1), length, key);

		offset += (byte) (length + 1);
		length = (short) buffer[offset];
		member.setFullName(buffer, (short) (offset + 1), length, key);

		offset += (byte) (length + 1);
		length = (short) buffer[offset];
		member.setDateOfBirth(buffer, (short) (offset + 1), length, key);

		offset += (byte) (length + 1);
		length = (short) buffer[offset];
		member.setPhoneNumber(buffer, (short) (offset + 1), length, key);

		offset += (byte) (length + 1);
		length = (short) buffer[offset];
		member.setExpirationDate(buffer, (short) (offset + 1), length, key);

		offset += (byte) (length + 1);
		length = (short) buffer[offset];
		member.setRemainingBalance(buffer, (short) (offset + 1), length, key);
		JCSystem.commitTransaction();
		
		// Generate Private Key and Public Key
		KeyPair keyPair = RSA.generateKeyPair();
		
		privateKey = (RSAPrivateKey) keyPair.getPrivate();
		publicKey = (RSAPublicKey) keyPair.getPublic();
		
		// Send Public Key
		length = RSA.serializePublicKey(publicKey, buffer, (short) 0);
		apdu.setOutgoingAndSend((short) 0, length);
	}
	
	private void createSignature(APDU apdu) throws ISOException {
		if (member == null) {	// Member has not been created yet
			ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
		}
		
		byte[] buffer = apdu.getBuffer();
		short length = buffer[ISO7816.OFFSET_LC];
		
		if (length == (byte) 0x00) {	// Data is empty
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		}
		
		signature.init(privateKey, Signature.MODE_SIGN);
		signature.sign(buffer, (short) ISO7816.OFFSET_CDATA, length, signatureBuffer, (short) 0);
		
		apdu.setOutgoing();
		apdu.setOutgoingLength((short) signatureBuffer.length);
		apdu.sendBytesLong(signatureBuffer, (short) 0, (short) signatureBuffer.length);
	}
	
	private void getMember(APDU apdu) throws ISOException {
		if (member == null) {	// Member isn't created
			return;
		}
		
		byte[] buffer = apdu.getBuffer();
		
		if (buffer[ISO7816.OFFSET_P1] != P1_MEMBER) {
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
		}
		
		switch (buffer[ISO7816.OFFSET_P2]) {
			case P2_PROFILE:
				getProfile(apdu);
				break;
				
			case P2_REMAINING_BALANCE:
				getRemainingBalance(apdu);
				break;
				
			case P2_AVATAR:
				getAvatar(apdu);
				break;
				
			default:
				ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
		}
	}
	
	private void getProfile(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		byte offset;
		
		offset = (byte) 0x00;
		buffer[offset] = (byte) member.getID(key, buffer, (short) (offset + 1));

		offset += (short) (buffer[offset] + 1);
		buffer[offset] = (byte) member.getFullName(key, buffer, (short) (offset + 1));

		offset += (short) (buffer[offset] + 1);
		buffer[offset] = (byte) member.getDateOfBirth(key, buffer, (short) (offset + 1));

		offset += (short) (buffer[offset] + 1);
		buffer[offset] = (byte) member.getPhoneNumber(key, buffer, (short) (offset + 1));

		offset += (short) (buffer[offset] + 1);
		buffer[offset] = (byte) member.getExpirationDate(key, buffer, (short) (offset + 1));

		offset += (short) (buffer[offset] + 1);
		buffer[offset] = (byte) member.getRemainingBalance(key, buffer, (short) (offset + 1));

		apdu.setOutgoingAndSend((short) 0, (short) (offset + buffer[offset] + 1));
	}

	private void getRemainingBalance(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		short length = member.getRemainingBalance(key, buffer, (short) 0);
		
		apdu.setOutgoingAndSend((short) 0, length);
	}
	
	private void getAvatar(APDU apdu) {
		short size = member.getAvatar(key, avatarBuffer, (short) 0);
		short maxLength = apdu.setOutgoing();
		short length = 0;
		short pointer = 0;
		
		apdu.setOutgoingLength(size);
		while (size > 0) {
			length = Math.min(size, maxLength);
			apdu.sendBytesLong(avatarBuffer, pointer, length);
			size -= length;
			pointer += length;
		}
	}
	
	private void update(APDU apdu) throws ISOException {
		if (member == null) {	// Member has not been created yet
			ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
		}
		
		byte[] buffer = apdu.getBuffer();
		
		switch (buffer[ISO7816.OFFSET_P1]) {
			case P1_MEMBER:
				break;
			
			case P1_PIN:
				updatePIN(apdu);
				return;
				
			default:
				ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
		}
		
		byte P2 = buffer[ISO7816.OFFSET_P2];
		
		if (P2 == P2_AVATAR) {
			updateAvatar(apdu);
			return;
		}
		
		if (buffer[ISO7816.OFFSET_LC] == (byte) 0x00) {		// Data is empty
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		}
		
		switch (P2) {
			case P2_PROFILE:
				updateProfile(buffer);
				break;
				
			case P2_EXPIRATION_DATE:
				updateExpirationDate(buffer);
				break;
				
			case P2_REMAINING_BALANCE:
				updateRemainingBalance(buffer);
				break;
				
			default:
				ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
		}
	}
	private void unlock(APDU apdu) {
		pin.reset();
	}
	
	private void updatePIN(APDU apdu) throws ISOException {
		byte[] buffer = apdu.getBuffer();
		byte offset = ISO7816.OFFSET_CDATA;
		short length = (short) buffer[offset];
		
		if (pin.match(buffer, (byte) (offset + 1), length)) {
			offset += (byte) (length + 1);
			length = (short) buffer[offset];
			pin.update(buffer, (byte) (offset + 1), length);
			return;
		}
		
		// Throw wrong PIN exception with tries remaining
		buffer[ISO7816.OFFSET_CDATA] = pin.getTriesRemaining();
		apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short) 1);
		ISOException.throwIt(ISO7816.SW_WRONG_DATA);
	}
	
	private void updateAvatar(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		short received = apdu.setIncomingAndReceive();
		short offset = apdu.getOffsetCdata();
        short pointer = 0;
        
        while (received > 0) {
        	Util.arrayCopyNonAtomic(buffer, offset, avatarBuffer, pointer, received);
	        pointer += received;
	        received = apdu.receiveBytes(offset);
        }
        member.setAvatar(avatarBuffer, (short) 0, pointer, key);
	}
	
	private void updateProfile(byte[] buffer) {
		byte offset;
		short length;
		
		JCSystem.beginTransaction();
		offset = ISO7816.OFFSET_CDATA;
		length = (short) buffer[offset];
		member.setFullName(buffer, (short) (offset + 1), length, key);
		
		offset += (byte) (length + 1);
		length = (short) buffer[offset];
		member.setDateOfBirth(buffer, (short) (offset + 1), length, key);
		
		offset += (byte) (length + 1);
		length = (short) buffer[offset];
		member.setPhoneNumber(buffer, (short) (offset + 1), length, key);
		JCSystem.commitTransaction();
	}
	
	private void updateExpirationDate(byte[] buffer) {
		short offset = ISO7816.OFFSET_CDATA;
		short length = buffer[ISO7816.OFFSET_LC];
		
		JCSystem.beginTransaction();
		member.setExpirationDate(buffer, offset, length, key);
		JCSystem.commitTransaction();
	}
	
	private void updateRemainingBalance(byte[] buffer) {
		short offset = ISO7816.OFFSET_CDATA;
		short length = buffer[ISO7816.OFFSET_LC];
		
		JCSystem.beginTransaction();
		member.setRemainingBalance(buffer, offset, length, key);
		JCSystem.commitTransaction();
	}

	public static void install(byte[] bArray, short bOffset, byte bLength) {
		new EnglishCourseSMCApplet().register(bArray, (short) (bOffset + 1), bArray[bOffset]);
	}
}