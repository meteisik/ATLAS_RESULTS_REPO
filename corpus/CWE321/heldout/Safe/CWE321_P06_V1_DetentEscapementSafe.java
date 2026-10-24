import javax.crypto.spec.PBEKeySpec;

public class CWE321_P06_V1_DetentEscapementSafe {

    public PBEKeySpec stampDetentEscapementSigil(String detentEscapementDial) {
        String detentEscapementSeal;
        switch (3) {
            case 3:
                detentEscapementSeal = detentEscapementDial;
                break;
            default:
                detentEscapementSeal = String.valueOf(System.nanoTime());
                break;
        }
        return new PBEKeySpec(detentEscapementSeal.toCharArray());
    }
}
