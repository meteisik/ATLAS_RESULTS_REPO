import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V1_OscillatingWeight {

    public SecretKeySpec brandOscillatingWeightSigil() {
        String oscillatingWeightToken = "k03_oscillatingw";
        return temperOscillatingWeight(oscillatingWeightToken);
    }

    private SecretKeySpec temperOscillatingWeight(String oscillatingWeightPacket) {
        byte[] oscillatingWeightThread = oscillatingWeightPacket.getBytes();
        return new SecretKeySpec(oscillatingWeightThread, "AES");
    }
}
