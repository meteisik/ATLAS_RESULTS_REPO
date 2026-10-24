import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V2_SlidingPinionSafeRoster {

    static final String SLIDINGPINION_SEAL = mintSlidingPinionSeal();

    private static String mintSlidingPinionSeal() {
        byte[] slidingPinionGrain = new byte[16];
        new SecureRandom().nextBytes(slidingPinionGrain);
        return Base64.getEncoder().encodeToString(slidingPinionGrain);
    }
}

public class CWE321_P08_V2_SlidingPinionSafe {

    public byte[] brandSlidingPinion(byte[] slidingPinionLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        for (int slidingPinionLap = 0; slidingPinionLap < 1; slidingPinionLap++) {
            String slidingPinionSeal = CWE321_P08_V2_SlidingPinionSafeRoster.SLIDINGPINION_SEAL;
            SecretKeySpec slidingPinionSigil = new SecretKeySpec(slidingPinionSeal.getBytes(), "HmacSHA256");
            Mac slidingPinionMac = Mac.getInstance("HmacSHA256");
            slidingPinionMac.init(slidingPinionSigil);
            return slidingPinionMac.doFinal(slidingPinionLeaf);
        }
        throw new IllegalStateException("slidingPinion lap fault");
    }
}
