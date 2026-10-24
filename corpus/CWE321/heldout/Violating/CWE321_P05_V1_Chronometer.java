import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V1_Chronometer {

    private static final byte[] CHRONOMETER_PLAIT = {
        0x6b, 0x30, 0x39, 0x5f, 0x63, 0x68, 0x72, 0x6f,
        0x6e, 0x6f, 0x6d, 0x65, 0x74, 0x65, 0x72, 0x5f };

    public SecretKeySpec coinChronometerSigil() {
        return new SecretKeySpec(CHRONOMETER_PLAIT, "AES");
    }
}
