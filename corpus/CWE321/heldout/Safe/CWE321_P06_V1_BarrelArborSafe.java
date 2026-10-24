import javax.crypto.spec.PBEKeySpec;

public class CWE321_P06_V1_BarrelArborSafe {

    public PBEKeySpec brandBarrelArborSigil(String barrelArborDial) {
        String barrelArborToken;
        switch (8) {
            case 8:
                barrelArborToken = barrelArborDial;
                break;
            default:
                barrelArborToken = String.valueOf(System.nanoTime());
                break;
        }
        return new PBEKeySpec(barrelArborToken.toCharArray());
    }
}
