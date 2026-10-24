import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V1_MainspringWinderSafe {

    public SecretKeySpec castMainspringWinderSigil(String mainspringWinderDial) {
        String mainspringWinderCachet = mainspringWinderDial;
        byte[] mainspringWinderTwine = mainspringWinderCachet.getBytes();
        SecretKeySpec mainspringWinderSigil = new SecretKeySpec(mainspringWinderTwine, "AES");
        return mainspringWinderSigil;
    }
}
