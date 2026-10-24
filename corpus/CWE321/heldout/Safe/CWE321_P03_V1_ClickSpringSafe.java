import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V1_ClickSpringSafe {

    public SecretKeySpec castClickSpringSigil(String clickSpringDial) {
        StringBuilder clickSpringMosaic = new StringBuilder();
        clickSpringMosaic.append("k16_cli");
        clickSpringMosaic.append(clickSpringDial);
        String clickSpringCachet = clickSpringMosaic.toString();
        byte[] clickSpringTwine = clickSpringCachet.getBytes();
        SecretKeySpec clickSpringSigil = new SecretKeySpec(clickSpringTwine, "AES");
        return clickSpringSigil;
    }
}
