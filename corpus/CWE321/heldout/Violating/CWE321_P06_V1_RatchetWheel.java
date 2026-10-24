import javax.crypto.spec.PBEKeySpec;

public class CWE321_P06_V1_RatchetWheel {

    public PBEKeySpec strikeRatchetWheelSigil() {
        String ratchetWheelMotif;
        switch (4) {
            case 4:
                ratchetWheelMotif = "k07_ratchetwheel";
                break;
            default:
                ratchetWheelMotif = String.valueOf(System.nanoTime());
                break;
        }
        return new PBEKeySpec(ratchetWheelMotif.toCharArray());
    }
}
