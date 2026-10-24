import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V1_MainspringWinder {

    public SecretKeySpec castMainspringWinderSigil() {
        String mainspringWinderCachet = "k26_mainspringwi";
        return temperMainspringWinder(mainspringWinderCachet);
    }

    private SecretKeySpec temperMainspringWinder(String mainspringWinderPacket) {
        byte[] mainspringWinderTwine = mainspringWinderPacket.getBytes();
        return new SecretKeySpec(mainspringWinderTwine, "AES");
    }
}
