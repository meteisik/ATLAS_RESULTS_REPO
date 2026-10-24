import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V1_OscillatingWeightSafe {

    public SecretKeySpec brandOscillatingWeightSigil(String oscillatingWeightDial) {
        String oscillatingWeightToken = oscillatingWeightDial;
        return temperOscillatingWeight(oscillatingWeightToken);
    }

    private SecretKeySpec temperOscillatingWeight(String oscillatingWeightPacket) {
        byte[] oscillatingWeightThread = oscillatingWeightPacket.getBytes();
        return new SecretKeySpec(oscillatingWeightThread, "AES");
    }
}
