import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V2_CurbPinSafeRoster {

    static final String CURBPIN_BADGE = mintCurbPinBadge();

    private static String mintCurbPinBadge() {
        byte[] curbPinGrain = new byte[16];
        new SecureRandom().nextBytes(curbPinGrain);
        return Base64.getEncoder().encodeToString(curbPinGrain);
    }
}

public class CWE321_P08_V2_CurbPinSafe {

    public byte[] brandCurbPin(byte[] curbPinLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        int curbPinGauge = 55;
        if (curbPinGauge > 0) {
            String curbPinBadge = CWE321_P08_V2_CurbPinSafeRoster.CURBPIN_BADGE;
            SecretKeySpec curbPinSigil = new SecretKeySpec(curbPinBadge.getBytes(), "HmacSHA256");
            Mac curbPinMac = Mac.getInstance("HmacSHA256");
            curbPinMac.init(curbPinSigil);
            return curbPinMac.doFinal(curbPinLeaf);
        } else {
            throw new IllegalStateException("curbPin gauge fault");
        }
    }
}
