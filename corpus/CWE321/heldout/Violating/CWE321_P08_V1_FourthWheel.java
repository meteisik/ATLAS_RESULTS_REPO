import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V1_FourthWheelRoster {

    static final String FOURTHWHEEL_CACHET = "k36_fourthwheel_";
}

public class CWE321_P08_V1_FourthWheel {

    public byte[] brandFourthWheel(byte[] fourthWheelLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        String fourthWheelCachet = CWE321_P08_V1_FourthWheelRoster.FOURTHWHEEL_CACHET;
        SecretKeySpec fourthWheelSigil = new SecretKeySpec(fourthWheelCachet.getBytes(), "HmacSHA256");
        Mac fourthWheelMac = Mac.getInstance("HmacSHA256");
        fourthWheelMac.init(fourthWheelSigil);
        return fourthWheelMac.doFinal(fourthWheelLeaf);
    }
}
