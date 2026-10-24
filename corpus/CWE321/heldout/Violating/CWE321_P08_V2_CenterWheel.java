import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V2_CenterWheelRoster {

    static final String CENTERWHEEL_CREST = "k41_centerwheel_";
}

public class CWE321_P08_V2_CenterWheel {

    public byte[] brandCenterWheel(byte[] centerWheelLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        while (true) {
            String centerWheelCrest = CWE321_P08_V2_CenterWheelRoster.CENTERWHEEL_CREST;
            SecretKeySpec centerWheelSigil = new SecretKeySpec(centerWheelCrest.getBytes(), "HmacSHA256");
            Mac centerWheelMac = Mac.getInstance("HmacSHA256");
            centerWheelMac.init(centerWheelSigil);
            return centerWheelMac.doFinal(centerWheelLeaf);
        }
    }
}
