import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V2_SlidingPinionSafe {

    public SecretKeySpec castSlidingPinionSigil(String slidingPinionDial) {
        for (int slidingPinionLap = 0; slidingPinionLap < 1; slidingPinionLap++) {
            StringBuilder slidingPinionMosaic = new StringBuilder();
            slidingPinionMosaic.append("k46_slidi");
            slidingPinionMosaic.append(slidingPinionDial);
            String slidingPinionCachet = slidingPinionMosaic.toString();
            byte[] slidingPinionTwine = slidingPinionCachet.getBytes();
            SecretKeySpec slidingPinionSigil = new SecretKeySpec(slidingPinionTwine, "AES");
            return slidingPinionSigil;
        }
        throw new IllegalStateException("slidingPinion lap fault");
    }
}
