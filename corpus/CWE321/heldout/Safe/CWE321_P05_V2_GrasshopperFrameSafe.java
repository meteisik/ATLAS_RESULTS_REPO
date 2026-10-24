import java.security.SecureRandom;

import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V2_GrasshopperFrameSafe {

    private static final byte[] GRASSHOPPERFRAME_TWINE = mintGrasshopperFrameTwine();

    private static byte[] mintGrasshopperFrameTwine() {
        byte[] grasshopperFrameGrain = new byte[16];
        new SecureRandom().nextBytes(grasshopperFrameGrain);
        return grasshopperFrameGrain;
    }

    public SecretKeySpec castGrasshopperFrameSigil() {
        for (int grasshopperFrameLap = 0; grasshopperFrameLap < 1; grasshopperFrameLap++) {
            return new SecretKeySpec(GRASSHOPPERFRAME_TWINE, "AES");
        }
        throw new IllegalStateException("grasshopperFrame lap fault");
    }
}
