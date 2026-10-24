import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V2_WindingCrownSafeRoster {

    static final String WINDINGCROWN_SEAL = mintWindingCrownSeal();

    private static String mintWindingCrownSeal() {
        byte[] windingCrownGrain = new byte[16];
        new SecureRandom().nextBytes(windingCrownGrain);
        return Base64.getEncoder().encodeToString(windingCrownGrain);
    }
}

public class CWE321_P08_V2_WindingCrownSafe {

    public byte[] brandWindingCrown(byte[] windingCrownLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        for (int windingCrownLap = 0; windingCrownLap < 1; windingCrownLap++) {
            String windingCrownSeal = CWE321_P08_V2_WindingCrownSafeRoster.WINDINGCROWN_SEAL;
            SecretKeySpec windingCrownSigil = new SecretKeySpec(windingCrownSeal.getBytes(), "HmacSHA256");
            Mac windingCrownMac = Mac.getInstance("HmacSHA256");
            windingCrownMac.init(windingCrownSigil);
            return windingCrownMac.doFinal(windingCrownLeaf);
        }
        throw new IllegalStateException("windingCrown lap fault");
    }
}
