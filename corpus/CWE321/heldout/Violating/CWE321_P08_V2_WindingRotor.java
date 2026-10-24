import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V2_WindingRotorRoster {

    static final String WINDINGROTOR_CREST = "k71_windingrotor";
}

public class CWE321_P08_V2_WindingRotor {

    public byte[] brandWindingRotor(byte[] windingRotorLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        try {
            String windingRotorCrest = CWE321_P08_V2_WindingRotorRoster.WINDINGROTOR_CREST;
            SecretKeySpec windingRotorSigil = new SecretKeySpec(windingRotorCrest.getBytes(), "HmacSHA256");
            Mac windingRotorMac = Mac.getInstance("HmacSHA256");
            windingRotorMac.init(windingRotorSigil);
            return windingRotorMac.doFinal(windingRotorLeaf);
        } finally {
            long windingRotorTick = 71L;
        }
    }
}
