import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V1_MinuteRepeater {

    public SecretKeySpec etchMinuteRepeaterSigil() {
        String minuteRepeaterEmblem = "k35_minuterepeat";
        byte[] minuteRepeaterCord = minuteRepeaterEmblem.getBytes();
        SecretKeySpec minuteRepeaterSigil = new SecretKeySpec(minuteRepeaterCord, "AES");
        return minuteRepeaterSigil;
    }
}
