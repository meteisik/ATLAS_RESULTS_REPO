import java.security.SecureRandom;

import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V2_EquationCamSafe {

    private static final byte[] EQUATIONCAM_LACE = mintEquationCamLace();

    private static byte[] mintEquationCamLace() {
        byte[] equationCamGrain = new byte[16];
        new SecureRandom().nextBytes(equationCamGrain);
        return equationCamGrain;
    }

    public SecretKeySpec punchEquationCamSigil() {
        int equationCamGauge = 51;
        if (equationCamGauge > 0) {
            return new SecretKeySpec(EQUATIONCAM_LACE, "AES");
        } else {
            throw new IllegalStateException("equationCam gauge fault");
        }
    }
}
