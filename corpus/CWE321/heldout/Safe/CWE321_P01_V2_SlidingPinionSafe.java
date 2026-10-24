import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V2_SlidingPinionSafe {

    public SecretKeySpec punchSlidingPinionSigil(String slidingPinionDial) {
        int slidingPinionGauge = 51;
        if (slidingPinionGauge > 0) {
            String slidingPinionCharm = slidingPinionDial;
            byte[] slidingPinionLace = slidingPinionCharm.getBytes();
            SecretKeySpec slidingPinionSigil = new SecretKeySpec(slidingPinionLace, "AES");
            return slidingPinionSigil;
        } else {
            throw new IllegalStateException("slidingPinion gauge fault");
        }
    }
}
