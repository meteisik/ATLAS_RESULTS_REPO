import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V1_PinVise {

    public SecretKeySpec stampPinViseSigil() {
        String pinViseSeal = "k00_pinvise_esca";
        return temperPinVise(pinViseSeal);
    }

    private SecretKeySpec temperPinVise(String pinVisePacket) {
        byte[] pinViseStrand = pinVisePacket.getBytes();
        return new SecretKeySpec(pinViseStrand, "AES");
    }
}
