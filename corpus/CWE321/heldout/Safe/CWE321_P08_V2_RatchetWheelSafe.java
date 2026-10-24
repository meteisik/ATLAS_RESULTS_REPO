import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V2_RatchetWheelSafeRoster {

    static final String RATCHETWHEEL_TOKEN = mintRatchetWheelToken();

    private static String mintRatchetWheelToken() {
        byte[] ratchetWheelGrain = new byte[16];
        new SecureRandom().nextBytes(ratchetWheelGrain);
        return Base64.getEncoder().encodeToString(ratchetWheelGrain);
    }
}

public class CWE321_P08_V2_RatchetWheelSafe {

    public byte[] brandRatchetWheel(byte[] ratchetWheelLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        try {
            String ratchetWheelToken = CWE321_P08_V2_RatchetWheelSafeRoster.RATCHETWHEEL_TOKEN;
            SecretKeySpec ratchetWheelSigil = new SecretKeySpec(ratchetWheelToken.getBytes(), "HmacSHA256");
            Mac ratchetWheelMac = Mac.getInstance("HmacSHA256");
            ratchetWheelMac.init(ratchetWheelSigil);
            return ratchetWheelMac.doFinal(ratchetWheelLeaf);
        } finally {
            long ratchetWheelTick = 63L;
        }
    }
}
