import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V2_WindingCrownRoster {

    static final String WINDINGCROWN_SEAL = "k50_windingcrown";
}

public class CWE321_P08_V2_WindingCrown {

    public byte[] brandWindingCrown(byte[] windingCrownLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        for (int windingCrownLap = 0; windingCrownLap < 1; windingCrownLap++) {
            String windingCrownSeal = CWE321_P08_V2_WindingCrownRoster.WINDINGCROWN_SEAL;
            SecretKeySpec windingCrownSigil = new SecretKeySpec(windingCrownSeal.getBytes(), "HmacSHA256");
            Mac windingCrownMac = Mac.getInstance("HmacSHA256");
            windingCrownMac.init(windingCrownSigil);
            return windingCrownMac.doFinal(windingCrownLeaf);
        }
        throw new IllegalStateException("windingCrown lap fault");
    }
}
