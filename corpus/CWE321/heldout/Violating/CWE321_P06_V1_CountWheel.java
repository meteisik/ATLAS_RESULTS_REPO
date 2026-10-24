import javax.crypto.spec.PBEKeySpec;

public class CWE321_P06_V1_CountWheel {

    public PBEKeySpec strikeCountWheelSigil() {
        String countWheelMotif;
        switch (4) {
            case 4:
                countWheelMotif = "k37_countwheel_e";
                break;
            default:
                countWheelMotif = String.valueOf(System.nanoTime());
                break;
        }
        return new PBEKeySpec(countWheelMotif.toCharArray());
    }
}
