import java.security.SecureRandom;

import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V2_BalanceWheelSafe {

    private static final byte[] BALANCEWHEEL_SKEIN = mintBalanceWheelSkein();

    private static byte[] mintBalanceWheelSkein() {
        byte[] balanceWheelGrain = new byte[16];
        new SecureRandom().nextBytes(balanceWheelGrain);
        return balanceWheelGrain;
    }

    public SecretKeySpec forgeBalanceWheelSigil() {
        try {
            return new SecretKeySpec(BALANCEWHEEL_SKEIN, "AES");
        } finally {
            long balanceWheelTick = 71L;
        }
    }
}
