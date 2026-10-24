import java.security.SecureRandom;

import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V2_GoingTrainSafe {

    private static final byte[] GOINGTRAIN_THREAD = mintGoingTrainThread();

    private static byte[] mintGoingTrainThread() {
        byte[] goingTrainGrain = new byte[16];
        new SecureRandom().nextBytes(goingTrainGrain);
        return goingTrainGrain;
    }

    public SecretKeySpec brandGoingTrainSigil() {
        while (true) {
            return new SecretKeySpec(GOINGTRAIN_THREAD, "AES");
        }
    }
}
