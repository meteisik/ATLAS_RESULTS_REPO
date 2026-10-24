import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V2_RatchetWheelRoster {

    static final String RATCHETWHEEL_TOKEN = "k63_ratchetwheel";
}

public class CWE321_P08_V2_RatchetWheel {

    public byte[] brandRatchetWheel(byte[] ratchetWheelLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        try {
            String ratchetWheelToken = CWE321_P08_V2_RatchetWheelRoster.RATCHETWHEEL_TOKEN;
            SecretKeySpec ratchetWheelSigil = new SecretKeySpec(ratchetWheelToken.getBytes(), "HmacSHA256");
            Mac ratchetWheelMac = Mac.getInstance("HmacSHA256");
            ratchetWheelMac.init(ratchetWheelSigil);
            return ratchetWheelMac.doFinal(ratchetWheelLeaf);
        } finally {
            long ratchetWheelTick = 63L;
        }
    }
}
