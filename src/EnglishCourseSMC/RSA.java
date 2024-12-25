package EnglishCourseSMC;
import javacard.framework.Util;
import javacard.security.KeyPair;
import javacard.security.RSAPrivateKey;
import javacard.security.RSAPublicKey;
import javacard.security.KeyBuilder;

public class RSA {
	
	public static KeyPair generateKeyPair() {
		KeyPair keyPair = new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_1024);
		
		keyPair.genKeyPair();
		return keyPair;
	}
	
	public static short serializePublicKey(RSAPublicKey key, byte[] buffer, short offset) {
		short exponentLength = key.getExponent(buffer, (short) (offset + 2));
		short modulusLength = key.getModulus(buffer, (short) (offset + 2 + exponentLength + 2));
		
		Util.setShort(buffer, offset, exponentLength);
		Util.setShort(buffer, (short) (offset + 2 + exponentLength), modulusLength);
		return (short) (4 + exponentLength + modulusLength);
	}
}
