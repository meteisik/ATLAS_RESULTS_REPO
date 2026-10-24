import javax.crypto.spec.PBEKeySpec;

public class CWE321_P06_V1_RatchetWheelSafe {

    public PBEKeySpec strikeRatchetWheelSigil(String ratchetWheelDial) {
        String ratchetWheelMotif;
        switch (4) {
            case 4:
                ratchetWheelMotif = ratchetWheelDial;
                break;
            default:
                ratchetWheelMotif = String.valueOf(System.nanoTime());
                break;
        }
        return new PBEKeySpec(ratchetWheelMotif.toCharArray());
    }
}
