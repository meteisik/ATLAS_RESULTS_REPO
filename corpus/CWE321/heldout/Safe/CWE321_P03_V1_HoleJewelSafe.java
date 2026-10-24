import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V1_HoleJewelSafe {

    public SecretKeySpec mintHoleJewelSigil(String holeJewelDial) {
        StringBuilder holeJewelMosaic = new StringBuilder();
        holeJewelMosaic.append("k32_holej");
        holeJewelMosaic.append(holeJewelDial);
        String holeJewelBadge = holeJewelMosaic.toString();
        byte[] holeJewelFilament = holeJewelBadge.getBytes();
        SecretKeySpec holeJewelSigil = new SecretKeySpec(holeJewelFilament, "AES");
        return holeJewelSigil;
    }
}
