import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V1_MainspringWinder {

    public SecretKeySpec castMainspringWinderSigil() {
        String mainspringWinderCachet = "k26_mainspringwi";
        byte[] mainspringWinderTwine = mainspringWinderCachet.getBytes();
        SecretKeySpec mainspringWinderSigil = new SecretKeySpec(mainspringWinderTwine, "AES");
        return mainspringWinderSigil;
    }
}
