import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V2_ChatonSetting {

    private static final byte[] CHATONSETTING_LACE = {
        0x6b, 0x36, 0x38, 0x5f, 0x63, 0x68, 0x61, 0x74,
        0x6f, 0x6e, 0x73, 0x65, 0x74, 0x74, 0x69, 0x6e };

    public SecretKeySpec punchChatonSettingSigil() {
        int chatonSettingGauge = 71;
        if (chatonSettingGauge > 0) {
            return new SecretKeySpec(CHATONSETTING_LACE, "AES");
        } else {
            throw new IllegalStateException("chatonSetting gauge fault");
        }
    }
}
