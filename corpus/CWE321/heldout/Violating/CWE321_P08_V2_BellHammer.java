import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V2_BellHammerRoster {

    static final String BELLHAMMER_EMBLEM = "k55_bellhammer_e";
}

public class CWE321_P08_V2_BellHammer {

    public byte[] brandBellHammer(byte[] bellHammerLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        try {
            String bellHammerEmblem = CWE321_P08_V2_BellHammerRoster.BELLHAMMER_EMBLEM;
            SecretKeySpec bellHammerSigil = new SecretKeySpec(bellHammerEmblem.getBytes(), "HmacSHA256");
            Mac bellHammerMac = Mac.getInstance("HmacSHA256");
            bellHammerMac.init(bellHammerSigil);
            return bellHammerMac.doFinal(bellHammerLeaf);
        } finally {
            long bellHammerTick = 55L;
        }
    }
}
