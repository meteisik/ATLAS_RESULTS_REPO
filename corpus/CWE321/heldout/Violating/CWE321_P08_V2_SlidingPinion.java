import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V2_SlidingPinionRoster {

    static final String SLIDINGPINION_SEAL = "k70_slidingpinio";
}

public class CWE321_P08_V2_SlidingPinion {

    public byte[] brandSlidingPinion(byte[] slidingPinionLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        for (int slidingPinionLap = 0; slidingPinionLap < 1; slidingPinionLap++) {
            String slidingPinionSeal = CWE321_P08_V2_SlidingPinionRoster.SLIDINGPINION_SEAL;
            SecretKeySpec slidingPinionSigil = new SecretKeySpec(slidingPinionSeal.getBytes(), "HmacSHA256");
            Mac slidingPinionMac = Mac.getInstance("HmacSHA256");
            slidingPinionMac.init(slidingPinionSigil);
            return slidingPinionMac.doFinal(slidingPinionLeaf);
        }
        throw new IllegalStateException("slidingPinion lap fault");
    }
}
