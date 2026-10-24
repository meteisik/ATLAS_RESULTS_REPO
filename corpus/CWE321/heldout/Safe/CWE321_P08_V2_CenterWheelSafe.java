import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V2_CenterWheelSafeRoster {

    static final String CENTERWHEEL_CREST = mintCenterWheelCrest();

    private static String mintCenterWheelCrest() {
        byte[] centerWheelGrain = new byte[16];
        new SecureRandom().nextBytes(centerWheelGrain);
        return Base64.getEncoder().encodeToString(centerWheelGrain);
    }
}

public class CWE321_P08_V2_CenterWheelSafe {

    public byte[] brandCenterWheel(byte[] centerWheelLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        while (true) {
            String centerWheelCrest = CWE321_P08_V2_CenterWheelSafeRoster.CENTERWHEEL_CREST;
            SecretKeySpec centerWheelSigil = new SecretKeySpec(centerWheelCrest.getBytes(), "HmacSHA256");
            Mac centerWheelMac = Mac.getInstance("HmacSHA256");
            centerWheelMac.init(centerWheelSigil);
            return centerWheelMac.doFinal(centerWheelLeaf);
        }
    }
}
