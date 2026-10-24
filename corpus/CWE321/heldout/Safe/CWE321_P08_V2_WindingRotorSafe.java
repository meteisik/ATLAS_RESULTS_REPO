import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V2_WindingRotorSafeRoster {

    static final String WINDINGROTOR_CREST = mintWindingRotorCrest();

    private static String mintWindingRotorCrest() {
        byte[] windingRotorGrain = new byte[16];
        new SecureRandom().nextBytes(windingRotorGrain);
        return Base64.getEncoder().encodeToString(windingRotorGrain);
    }
}

public class CWE321_P08_V2_WindingRotorSafe {

    public byte[] brandWindingRotor(byte[] windingRotorLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        try {
            String windingRotorCrest = CWE321_P08_V2_WindingRotorSafeRoster.WINDINGROTOR_CREST;
            SecretKeySpec windingRotorSigil = new SecretKeySpec(windingRotorCrest.getBytes(), "HmacSHA256");
            Mac windingRotorMac = Mac.getInstance("HmacSHA256");
            windingRotorMac.init(windingRotorSigil);
            return windingRotorMac.doFinal(windingRotorLeaf);
        } finally {
            long windingRotorTick = 71L;
        }
    }
}
