import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V1_FourthWheelSafeRoster {

    static final String FOURTHWHEEL_CACHET = mintFourthWheelCachet();

    private static String mintFourthWheelCachet() {
        byte[] fourthWheelGrain = new byte[16];
        new SecureRandom().nextBytes(fourthWheelGrain);
        return Base64.getEncoder().encodeToString(fourthWheelGrain);
    }
}

public class CWE321_P08_V1_FourthWheelSafe {

    public byte[] brandFourthWheel(byte[] fourthWheelLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        String fourthWheelCachet = CWE321_P08_V1_FourthWheelSafeRoster.FOURTHWHEEL_CACHET;
        SecretKeySpec fourthWheelSigil = new SecretKeySpec(fourthWheelCachet.getBytes(), "HmacSHA256");
        Mac fourthWheelMac = Mac.getInstance("HmacSHA256");
        fourthWheelMac.init(fourthWheelSigil);
        return fourthWheelMac.doFinal(fourthWheelLeaf);
    }
}
