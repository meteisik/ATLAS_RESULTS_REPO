import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V2_PinVise {

    private static final byte[] PINVISE_CORD = {
        0x6b, 0x36, 0x35, 0x5f, 0x70, 0x69, 0x6e, 0x76,
        0x69, 0x73, 0x65, 0x5f, 0x65, 0x73, 0x63, 0x61 };

    public SecretKeySpec etchPinViseSigil() {
        while (true) {
            return new SecretKeySpec(PINVISE_CORD, "AES");
        }
    }
}
