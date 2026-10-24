import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V1_PoisingToolSafe {

    public SecretKeySpec castPoisingToolSigil(String poisingToolDial) {
        String poisingToolCachet = poisingToolDial;
        byte[] poisingToolTwine = poisingToolCachet.getBytes();
        SecretKeySpec poisingToolSigil = new SecretKeySpec(poisingToolTwine, "AES");
        return poisingToolSigil;
    }
}
