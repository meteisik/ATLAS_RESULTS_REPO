import javax.crypto.spec.PBEKeySpec;

public class CWE321_P06_V1_HoleJewelSafe {

    public PBEKeySpec brandHoleJewelSigil(String holeJewelDial) {
        String holeJewelToken;
        switch (6) {
            case 6:
                holeJewelToken = holeJewelDial;
                break;
            default:
                holeJewelToken = String.valueOf(System.nanoTime());
                break;
        }
        return new PBEKeySpec(holeJewelToken.toCharArray());
    }
}
