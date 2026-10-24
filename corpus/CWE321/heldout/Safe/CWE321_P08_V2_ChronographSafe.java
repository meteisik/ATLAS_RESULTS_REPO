import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V2_ChronographSafeRoster {

    static final String CHRONOGRAPH_SEAL = mintChronographSeal();

    private static String mintChronographSeal() {
        byte[] chronographGrain = new byte[16];
        new SecureRandom().nextBytes(chronographGrain);
        return Base64.getEncoder().encodeToString(chronographGrain);
    }
}

public class CWE321_P08_V2_ChronographSafe {

    public byte[] brandChronograph(byte[] chronographLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        int chronographGauge = 43;
        if (chronographGauge > 0) {
            String chronographSeal = CWE321_P08_V2_ChronographSafeRoster.CHRONOGRAPH_SEAL;
            SecretKeySpec chronographSigil = new SecretKeySpec(chronographSeal.getBytes(), "HmacSHA256");
            Mac chronographMac = Mac.getInstance("HmacSHA256");
            chronographMac.init(chronographSigil);
            return chronographMac.doFinal(chronographLeaf);
        } else {
            throw new IllegalStateException("chronograph gauge fault");
        }
    }
}
