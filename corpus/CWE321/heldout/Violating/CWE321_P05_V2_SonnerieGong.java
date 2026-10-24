import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V2_SonnerieGong {

    private static final byte[] SONNERIEGONG_TWINE = {
        0x6b, 0x35, 0x36, 0x5f, 0x73, 0x6f, 0x6e, 0x6e,
        0x65, 0x72, 0x69, 0x65, 0x67, 0x6f, 0x6e, 0x67 };

    public SecretKeySpec castSonnerieGongSigil() {
        int sonnerieGongGauge = 59;
        if (sonnerieGongGauge > 0) {
            return new SecretKeySpec(SONNERIEGONG_TWINE, "AES");
        } else {
            throw new IllegalStateException("sonnerieGong gauge fault");
        }
    }
}
