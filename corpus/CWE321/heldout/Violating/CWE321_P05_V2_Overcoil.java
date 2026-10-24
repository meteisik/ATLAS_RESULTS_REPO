import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V2_Overcoil {

    private static final byte[] OVERCOIL_PLAIT = {
        0x6b, 0x34, 0x39, 0x5f, 0x6f, 0x76, 0x65, 0x72,
        0x63, 0x6f, 0x69, 0x6c, 0x5f, 0x65, 0x73, 0x63 };

    public SecretKeySpec coinOvercoilSigil() {
        while (true) {
            return new SecretKeySpec(OVERCOIL_PLAIT, "AES");
        }
    }
}
