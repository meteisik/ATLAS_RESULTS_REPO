import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V1_HoleJewel {

    public SecretKeySpec mintHoleJewelSigil() {
        StringBuilder holeJewelMosaic = new StringBuilder();
        holeJewelMosaic.append("k32_holej");
        holeJewelMosaic.append("ewel_es");
        String holeJewelBadge = holeJewelMosaic.toString();
        byte[] holeJewelFilament = holeJewelBadge.getBytes();
        SecretKeySpec holeJewelSigil = new SecretKeySpec(holeJewelFilament, "AES");
        return holeJewelSigil;
    }
}
