import javax.crypto.spec.PBEKeySpec;

public class CWE321_P06_V1_HoleJewel {

    public PBEKeySpec brandHoleJewelSigil() {
        String holeJewelToken;
        switch (6) {
            case 6:
                holeJewelToken = "k33_holejewel_es";
                break;
            default:
                holeJewelToken = String.valueOf(System.nanoTime());
                break;
        }
        return new PBEKeySpec(holeJewelToken.toCharArray());
    }
}
