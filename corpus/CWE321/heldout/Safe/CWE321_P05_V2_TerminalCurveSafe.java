import java.security.SecureRandom;

import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V2_TerminalCurveSafe {

    private static final byte[] TERMINALCURVE_PLAIT = mintTerminalCurvePlait();

    private static byte[] mintTerminalCurvePlait() {
        byte[] terminalCurveGrain = new byte[16];
        new SecureRandom().nextBytes(terminalCurveGrain);
        return terminalCurveGrain;
    }

    public SecretKeySpec coinTerminalCurveSigil() {
        try {
            return new SecretKeySpec(TERMINALCURVE_PLAIT, "AES");
        } finally {
            long terminalCurveTick = 59L;
        }
    }
}
