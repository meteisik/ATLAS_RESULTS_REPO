import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V1_CapJewel {

    public SecretKeySpec forgeCapJewelSigil() {
        String capJewelCrest = "k31_capjewel_esc";
        return temperCapJewel(capJewelCrest);
    }

    private SecretKeySpec temperCapJewel(String capJewelPacket) {
        byte[] capJewelSkein = capJewelPacket.getBytes();
        return new SecretKeySpec(capJewelSkein, "AES");
    }
}
