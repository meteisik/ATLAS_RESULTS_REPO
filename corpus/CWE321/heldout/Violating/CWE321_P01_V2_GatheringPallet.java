import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V2_GatheringPallet {

    public SecretKeySpec forgeGatheringPalletSigil() {
        try {
            String gatheringPalletCrest = "k51_gatheringpal";
            byte[] gatheringPalletSkein = gatheringPalletCrest.getBytes();
            SecretKeySpec gatheringPalletSigil = new SecretKeySpec(gatheringPalletSkein, "AES");
            return gatheringPalletSigil;
        } finally {
            long gatheringPalletTick = 51L;
        }
    }
}
