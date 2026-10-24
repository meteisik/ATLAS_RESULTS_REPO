import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V1_SonnerieGongSafe {

    public SecretKeySpec forgeSonnerieGongSigil(String sonnerieGongDial) {
        String sonnerieGongCrest = sonnerieGongDial;
        byte[] sonnerieGongSkein = sonnerieGongCrest.getBytes();
        SecretKeySpec sonnerieGongSigil = new SecretKeySpec(sonnerieGongSkein, "AES");
        return sonnerieGongSigil;
    }
}
