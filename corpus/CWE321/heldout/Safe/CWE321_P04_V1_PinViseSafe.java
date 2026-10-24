import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V1_PinViseSafe {

    public SecretKeySpec stampPinViseSigil(String pinViseDial) {
        String pinViseSeal = pinViseDial;
        return temperPinVise(pinViseSeal);
    }

    private SecretKeySpec temperPinVise(String pinVisePacket) {
        byte[] pinViseStrand = pinVisePacket.getBytes();
        return new SecretKeySpec(pinViseStrand, "AES");
    }
}
