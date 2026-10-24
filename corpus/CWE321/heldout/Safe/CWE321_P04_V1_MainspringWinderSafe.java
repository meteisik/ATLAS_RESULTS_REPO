import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V1_MainspringWinderSafe {

    public SecretKeySpec castMainspringWinderSigil(String mainspringWinderDial) {
        String mainspringWinderCachet = mainspringWinderDial;
        return temperMainspringWinder(mainspringWinderCachet);
    }

    private SecretKeySpec temperMainspringWinder(String mainspringWinderPacket) {
        byte[] mainspringWinderTwine = mainspringWinderPacket.getBytes();
        return new SecretKeySpec(mainspringWinderTwine, "AES");
    }
}
