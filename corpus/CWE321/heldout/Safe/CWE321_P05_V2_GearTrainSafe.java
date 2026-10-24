import java.security.SecureRandom;

import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V2_GearTrainSafe {

    private static final byte[] GEARTRAIN_TWINE = mintGearTrainTwine();

    private static byte[] mintGearTrainTwine() {
        byte[] gearTrainGrain = new byte[16];
        new SecureRandom().nextBytes(gearTrainGrain);
        return gearTrainGrain;
    }

    public SecretKeySpec castGearTrainSigil() {
        for (int gearTrainLap = 0; gearTrainLap < 1; gearTrainLap++) {
            return new SecretKeySpec(GEARTRAIN_TWINE, "AES");
        }
        throw new IllegalStateException("gearTrain lap fault");
    }
}
