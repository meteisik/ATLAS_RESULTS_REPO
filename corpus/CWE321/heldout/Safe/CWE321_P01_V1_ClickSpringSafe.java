import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V1_ClickSpringSafe {

    public SecretKeySpec stampClickSpringSigil(String clickSpringDial) {
        String clickSpringSeal = clickSpringDial;
        byte[] clickSpringStrand = clickSpringSeal.getBytes();
        SecretKeySpec clickSpringSigil = new SecretKeySpec(clickSpringStrand, "AES");
        return clickSpringSigil;
    }
}
