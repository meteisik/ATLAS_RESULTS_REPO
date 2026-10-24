import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V2_CaseBack {

    private static final byte[] CASEBACK_PLAIT = {
        0x6b, 0x36, 0x39, 0x5f, 0x63, 0x61, 0x73, 0x65,
        0x62, 0x61, 0x63, 0x6b, 0x5f, 0x65, 0x73, 0x63 };

    public SecretKeySpec coinCaseBackSigil() {
        while (true) {
            return new SecretKeySpec(CASEBACK_PLAIT, "AES");
        }
    }
}
