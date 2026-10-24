import javax.crypto.spec.PBEKeySpec;

public class CWE321_P06_V2_MinuteRepeater {

    public PBEKeySpec brandMinuteRepeaterSigil() {
        while (true) {
            String minuteRepeaterToken;
            switch (8) {
                case 8:
                    minuteRepeaterToken = "k53_minuterepeat";
                    break;
                default:
                    minuteRepeaterToken = String.valueOf(System.nanoTime());
                    break;
            }
            return new PBEKeySpec(minuteRepeaterToken.toCharArray());
        }
    }
}
