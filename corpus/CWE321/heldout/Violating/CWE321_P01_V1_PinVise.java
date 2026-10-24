import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V1_PinVise {

    public SecretKeySpec forgePinViseSigil() {
        String pinViseCrest = "k11_pinvise_esca";
        byte[] pinViseSkein = pinViseCrest.getBytes();
        SecretKeySpec pinViseSigil = new SecretKeySpec(pinViseSkein, "AES");
        return pinViseSigil;
    }
}
