import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V2_WarningWheelRoster {

    static final String WARNINGWHEEL_CHARM = "k58_warningwheel";
}

public class CWE321_P08_V2_WarningWheel {

    public byte[] brandWarningWheel(byte[] warningWheelLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        for (int warningWheelLap = 0; warningWheelLap < 1; warningWheelLap++) {
            String warningWheelCharm = CWE321_P08_V2_WarningWheelRoster.WARNINGWHEEL_CHARM;
            SecretKeySpec warningWheelSigil = new SecretKeySpec(warningWheelCharm.getBytes(), "HmacSHA256");
            Mac warningWheelMac = Mac.getInstance("HmacSHA256");
            warningWheelMac.init(warningWheelSigil);
            return warningWheelMac.doFinal(warningWheelLeaf);
        }
        throw new IllegalStateException("warningWheel lap fault");
    }
}
