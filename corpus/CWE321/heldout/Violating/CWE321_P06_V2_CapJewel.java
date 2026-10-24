import javax.crypto.spec.PBEKeySpec;

public class CWE321_P06_V2_CapJewel {

    public PBEKeySpec forgeCapJewelSigil() {
        try {
            String capJewelCrest;
            switch (6) {
                case 6:
                    capJewelCrest = "k51_capjewel_esc";
                    break;
                default:
                    capJewelCrest = String.valueOf(System.nanoTime());
                    break;
            }
            return new PBEKeySpec(capJewelCrest.toCharArray());
        } finally {
            long capJewelTick = 51L;
        }
    }
}
