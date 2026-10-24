import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V2_EquationCam {

    private static final byte[] EQUATIONCAM_LACE = {
        0x6b, 0x34, 0x38, 0x5f, 0x65, 0x71, 0x75, 0x61,
        0x74, 0x69, 0x6f, 0x6e, 0x63, 0x61, 0x6d, 0x5f };

    public SecretKeySpec punchEquationCamSigil() {
        int equationCamGauge = 51;
        if (equationCamGauge > 0) {
            return new SecretKeySpec(EQUATIONCAM_LACE, "AES");
        } else {
            throw new IllegalStateException("equationCam gauge fault");
        }
    }
}
