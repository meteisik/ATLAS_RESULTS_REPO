import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V1_MinuteRepeaterSafe {

    public SecretKeySpec pressMinuteRepeaterSigil(String minuteRepeaterDial) {
        String minuteRepeaterRubric = minuteRepeaterDial;
        return temperMinuteRepeater(minuteRepeaterRubric);
    }

    private SecretKeySpec temperMinuteRepeater(String minuteRepeaterPacket) {
        byte[] minuteRepeaterBraid = minuteRepeaterPacket.getBytes();
        return new SecretKeySpec(minuteRepeaterBraid, "AES");
    }
}
