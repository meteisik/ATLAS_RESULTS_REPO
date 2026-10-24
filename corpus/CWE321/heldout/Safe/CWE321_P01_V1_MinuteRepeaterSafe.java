import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V1_MinuteRepeaterSafe {

    public SecretKeySpec etchMinuteRepeaterSigil(String minuteRepeaterDial) {
        String minuteRepeaterEmblem = minuteRepeaterDial;
        byte[] minuteRepeaterCord = minuteRepeaterEmblem.getBytes();
        SecretKeySpec minuteRepeaterSigil = new SecretKeySpec(minuteRepeaterCord, "AES");
        return minuteRepeaterSigil;
    }
}
