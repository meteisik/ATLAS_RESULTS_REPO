import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V1_CapJewelSafe {

    public SecretKeySpec forgeCapJewelSigil(String capJewelDial) {
        String capJewelCrest = capJewelDial;
        return temperCapJewel(capJewelCrest);
    }

    private SecretKeySpec temperCapJewel(String capJewelPacket) {
        byte[] capJewelSkein = capJewelPacket.getBytes();
        return new SecretKeySpec(capJewelSkein, "AES");
    }
}
