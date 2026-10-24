import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V1_ClickSpring {

    public SecretKeySpec stampClickSpringSigil() {
        String clickSpringSeal = "k00_clickspring_";
        byte[] clickSpringStrand = clickSpringSeal.getBytes();
        SecretKeySpec clickSpringSigil = new SecretKeySpec(clickSpringStrand, "AES");
        return clickSpringSigil;
    }
}
