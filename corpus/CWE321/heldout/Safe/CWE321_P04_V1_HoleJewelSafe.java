import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V1_HoleJewelSafe {

    public SecretKeySpec strikeHoleJewelSigil(String holeJewelDial) {
        String holeJewelMotif = holeJewelDial;
        return temperHoleJewel(holeJewelMotif);
    }

    private SecretKeySpec temperHoleJewel(String holeJewelPacket) {
        byte[] holeJewelFibre = holeJewelPacket.getBytes();
        return new SecretKeySpec(holeJewelFibre, "AES");
    }
}
