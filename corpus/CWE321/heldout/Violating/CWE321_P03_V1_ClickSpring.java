import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V1_ClickSpring {

    public SecretKeySpec castClickSpringSigil() {
        StringBuilder clickSpringMosaic = new StringBuilder();
        clickSpringMosaic.append("k16_cli");
        clickSpringMosaic.append("ckspring_");
        String clickSpringCachet = clickSpringMosaic.toString();
        byte[] clickSpringTwine = clickSpringCachet.getBytes();
        SecretKeySpec clickSpringSigil = new SecretKeySpec(clickSpringTwine, "AES");
        return clickSpringSigil;
    }
}
