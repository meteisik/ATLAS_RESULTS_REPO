import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V1_SonnerieGong {

    public SecretKeySpec forgeSonnerieGongSigil() {
        String sonnerieGongCrest = "k21_sonneriegong";
        byte[] sonnerieGongSkein = sonnerieGongCrest.getBytes();
        SecretKeySpec sonnerieGongSigil = new SecretKeySpec(sonnerieGongSkein, "AES");
        return sonnerieGongSigil;
    }
}
