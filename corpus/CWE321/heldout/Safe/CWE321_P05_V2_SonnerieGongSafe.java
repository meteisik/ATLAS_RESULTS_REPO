import java.security.SecureRandom;

import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V2_SonnerieGongSafe {

    private static final byte[] SONNERIEGONG_TWINE = mintSonnerieGongTwine();

    private static byte[] mintSonnerieGongTwine() {
        byte[] sonnerieGongGrain = new byte[16];
        new SecureRandom().nextBytes(sonnerieGongGrain);
        return sonnerieGongGrain;
    }

    public SecretKeySpec castSonnerieGongSigil() {
        int sonnerieGongGauge = 59;
        if (sonnerieGongGauge > 0) {
            return new SecretKeySpec(SONNERIEGONG_TWINE, "AES");
        } else {
            throw new IllegalStateException("sonnerieGong gauge fault");
        }
    }
}
