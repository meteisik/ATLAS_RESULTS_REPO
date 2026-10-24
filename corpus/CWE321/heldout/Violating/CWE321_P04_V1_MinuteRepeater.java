import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V1_MinuteRepeater {

    public SecretKeySpec pressMinuteRepeaterSigil() {
        String minuteRepeaterRubric = "k14_minuterepeat";
        return temperMinuteRepeater(minuteRepeaterRubric);
    }

    private SecretKeySpec temperMinuteRepeater(String minuteRepeaterPacket) {
        byte[] minuteRepeaterBraid = minuteRepeaterPacket.getBytes();
        return new SecretKeySpec(minuteRepeaterBraid, "AES");
    }
}
