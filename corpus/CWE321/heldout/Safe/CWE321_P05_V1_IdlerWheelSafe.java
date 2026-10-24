import java.security.SecureRandom;

import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V1_IdlerWheelSafe {

    private static final byte[] IDLERWHEEL_FILAMENT = mintIdlerWheelFilament();

    private static byte[] mintIdlerWheelFilament() {
        byte[] idlerWheelGrain = new byte[16];
        new SecureRandom().nextBytes(idlerWheelGrain);
        return idlerWheelGrain;
    }

    public SecretKeySpec mintIdlerWheelSigil() {
        return new SecretKeySpec(IDLERWHEEL_FILAMENT, "AES");
    }
}
