import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V1_HoleJewel {

    public SecretKeySpec strikeHoleJewelSigil() {
        String holeJewelMotif = "k07_holejewel_es";
        return temperHoleJewel(holeJewelMotif);
    }

    private SecretKeySpec temperHoleJewel(String holeJewelPacket) {
        byte[] holeJewelFibre = holeJewelPacket.getBytes();
        return new SecretKeySpec(holeJewelFibre, "AES");
    }
}
