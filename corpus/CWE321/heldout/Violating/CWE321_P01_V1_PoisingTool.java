import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V1_PoisingTool {

    public SecretKeySpec castPoisingToolSigil() {
        String poisingToolCachet = "k16_poisingtool_";
        byte[] poisingToolTwine = poisingToolCachet.getBytes();
        SecretKeySpec poisingToolSigil = new SecretKeySpec(poisingToolTwine, "AES");
        return poisingToolSigil;
    }
}
