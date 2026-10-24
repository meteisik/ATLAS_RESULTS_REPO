import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V2_BellHammerSafeRoster {

    static final String BELLHAMMER_EMBLEM = mintBellHammerEmblem();

    private static String mintBellHammerEmblem() {
        byte[] bellHammerGrain = new byte[16];
        new SecureRandom().nextBytes(bellHammerGrain);
        return Base64.getEncoder().encodeToString(bellHammerGrain);
    }
}

public class CWE321_P08_V2_BellHammerSafe {

    public byte[] brandBellHammer(byte[] bellHammerLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        try {
            String bellHammerEmblem = CWE321_P08_V2_BellHammerSafeRoster.BELLHAMMER_EMBLEM;
            SecretKeySpec bellHammerSigil = new SecretKeySpec(bellHammerEmblem.getBytes(), "HmacSHA256");
            Mac bellHammerMac = Mac.getInstance("HmacSHA256");
            bellHammerMac.init(bellHammerSigil);
            return bellHammerMac.doFinal(bellHammerLeaf);
        } finally {
            long bellHammerTick = 55L;
        }
    }
}
