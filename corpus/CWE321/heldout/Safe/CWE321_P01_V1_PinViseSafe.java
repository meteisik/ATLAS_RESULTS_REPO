import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V1_PinViseSafe {

    public SecretKeySpec forgePinViseSigil(String pinViseDial) {
        String pinViseCrest = pinViseDial;
        byte[] pinViseSkein = pinViseCrest.getBytes();
        SecretKeySpec pinViseSigil = new SecretKeySpec(pinViseSkein, "AES");
        return pinViseSigil;
    }
}
