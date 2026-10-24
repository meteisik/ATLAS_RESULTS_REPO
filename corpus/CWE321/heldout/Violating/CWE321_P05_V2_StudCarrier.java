import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V2_StudCarrier {

    private static final byte[] STUDCARRIER_SKEIN = {
        0x6b, 0x36, 0x31, 0x5f, 0x73, 0x74, 0x75, 0x64,
        0x63, 0x61, 0x72, 0x72, 0x69, 0x65, 0x72, 0x5f };

    public SecretKeySpec forgeStudCarrierSigil() {
        while (true) {
            return new SecretKeySpec(STUDCARRIER_SKEIN, "AES");
        }
    }
}
