import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V2_PalletJewelSafe {

    public SecretKeySpec stampPalletJewelSigil(String palletJewelDial) {
        for (int palletJewelLap = 0; palletJewelLap < 1; palletJewelLap++) {
            String palletJewelSeal = palletJewelDial;
            return temperPalletJewel(palletJewelSeal);
        }
        throw new IllegalStateException("palletJewel lap fault");
    }

    private SecretKeySpec temperPalletJewel(String palletJewelPacket) {
        byte[] palletJewelStrand = palletJewelPacket.getBytes();
        return new SecretKeySpec(palletJewelStrand, "AES");
    }
}
