import javax.crypto.spec.PBEKeySpec;

public class CWE321_P06_V1_CountWheelSafe {

    public PBEKeySpec strikeCountWheelSigil(String countWheelDial) {
        String countWheelMotif;
        switch (4) {
            case 4:
                countWheelMotif = countWheelDial;
                break;
            default:
                countWheelMotif = String.valueOf(System.nanoTime());
                break;
        }
        return new PBEKeySpec(countWheelMotif.toCharArray());
    }
}
