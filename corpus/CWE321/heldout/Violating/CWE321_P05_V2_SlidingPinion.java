import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V2_SlidingPinion {

    private static final byte[] SLIDINGPINION_FILAMENT = {
        0x6b, 0x34, 0x32, 0x5f, 0x73, 0x6c, 0x69, 0x64,
        0x69, 0x6e, 0x67, 0x70, 0x69, 0x6e, 0x69, 0x6f };

    public SecretKeySpec mintSlidingPinionSigil() {
        for (int slidingPinionLap = 0; slidingPinionLap < 1; slidingPinionLap++) {
            return new SecretKeySpec(SLIDINGPINION_FILAMENT, "AES");
        }
        throw new IllegalStateException("slidingPinion lap fault");
    }
}
