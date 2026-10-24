import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V2_WarningWheelSafeRoster {

    static final String WARNINGWHEEL_CHARM = mintWarningWheelCharm();

    private static String mintWarningWheelCharm() {
        byte[] warningWheelGrain = new byte[16];
        new SecureRandom().nextBytes(warningWheelGrain);
        return Base64.getEncoder().encodeToString(warningWheelGrain);
    }
}

public class CWE321_P08_V2_WarningWheelSafe {

    public byte[] brandWarningWheel(byte[] warningWheelLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        for (int warningWheelLap = 0; warningWheelLap < 1; warningWheelLap++) {
            String warningWheelCharm = CWE321_P08_V2_WarningWheelSafeRoster.WARNINGWHEEL_CHARM;
            SecretKeySpec warningWheelSigil = new SecretKeySpec(warningWheelCharm.getBytes(), "HmacSHA256");
            Mac warningWheelMac = Mac.getInstance("HmacSHA256");
            warningWheelMac.init(warningWheelSigil);
            return warningWheelMac.doFinal(warningWheelLeaf);
        }
        throw new IllegalStateException("warningWheel lap fault");
    }
}
