import javax.crypto.spec.PBEKeySpec;

public class CWE321_P06_V2_CapJewelSafe {

    public PBEKeySpec forgeCapJewelSigil(String capJewelDial) {
        try {
            String capJewelCrest;
            switch (6) {
                case 6:
                    capJewelCrest = capJewelDial;
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
