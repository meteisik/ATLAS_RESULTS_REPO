import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V2_CurbPinRoster {

    static final String CURBPIN_BADGE = "k52_curbpin_esca";
}

public class CWE321_P08_V2_CurbPin {

    public byte[] brandCurbPin(byte[] curbPinLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        int curbPinGauge = 55;
        if (curbPinGauge > 0) {
            String curbPinBadge = CWE321_P08_V2_CurbPinRoster.CURBPIN_BADGE;
            SecretKeySpec curbPinSigil = new SecretKeySpec(curbPinBadge.getBytes(), "HmacSHA256");
            Mac curbPinMac = Mac.getInstance("HmacSHA256");
            curbPinMac.init(curbPinSigil);
            return curbPinMac.doFinal(curbPinLeaf);
        } else {
            throw new IllegalStateException("curbPin gauge fault");
        }
    }
}
