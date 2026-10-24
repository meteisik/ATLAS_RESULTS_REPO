import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V2_CountWheelRoster {

    static final String COUNTWHEEL_CHARM = "k38_countwheel_e";
}

public class CWE321_P08_V2_CountWheel {

    public byte[] brandCountWheel(byte[] countWheelLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        for (int countWheelLap = 0; countWheelLap < 1; countWheelLap++) {
            String countWheelCharm = CWE321_P08_V2_CountWheelRoster.COUNTWHEEL_CHARM;
            SecretKeySpec countWheelSigil = new SecretKeySpec(countWheelCharm.getBytes(), "HmacSHA256");
            Mac countWheelMac = Mac.getInstance("HmacSHA256");
            countWheelMac.init(countWheelSigil);
            return countWheelMac.doFinal(countWheelLeaf);
        }
        throw new IllegalStateException("countWheel lap fault");
    }
}
