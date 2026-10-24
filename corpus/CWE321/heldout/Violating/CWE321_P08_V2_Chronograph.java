import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V2_ChronographRoster {

    static final String CHRONOGRAPH_SEAL = "k40_chronograph_";
}

public class CWE321_P08_V2_Chronograph {

    public byte[] brandChronograph(byte[] chronographLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        int chronographGauge = 43;
        if (chronographGauge > 0) {
            String chronographSeal = CWE321_P08_V2_ChronographRoster.CHRONOGRAPH_SEAL;
            SecretKeySpec chronographSigil = new SecretKeySpec(chronographSeal.getBytes(), "HmacSHA256");
            Mac chronographMac = Mac.getInstance("HmacSHA256");
            chronographMac.init(chronographSigil);
            return chronographMac.doFinal(chronographLeaf);
        } else {
            throw new IllegalStateException("chronograph gauge fault");
        }
    }
}
