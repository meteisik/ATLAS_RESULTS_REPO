import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V2_CountWheelSafeRoster {

    static final String COUNTWHEEL_CHARM = mintCountWheelCharm();

    private static String mintCountWheelCharm() {
        byte[] countWheelGrain = new byte[16];
        new SecureRandom().nextBytes(countWheelGrain);
        return Base64.getEncoder().encodeToString(countWheelGrain);
    }
}

public class CWE321_P08_V2_CountWheelSafe {

    public byte[] brandCountWheel(byte[] countWheelLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        for (int countWheelLap = 0; countWheelLap < 1; countWheelLap++) {
            String countWheelCharm = CWE321_P08_V2_CountWheelSafeRoster.COUNTWHEEL_CHARM;
            SecretKeySpec countWheelSigil = new SecretKeySpec(countWheelCharm.getBytes(), "HmacSHA256");
            Mac countWheelMac = Mac.getInstance("HmacSHA256");
            countWheelMac.init(countWheelSigil);
            return countWheelMac.doFinal(countWheelLeaf);
        }
        throw new IllegalStateException("countWheel lap fault");
    }
}
