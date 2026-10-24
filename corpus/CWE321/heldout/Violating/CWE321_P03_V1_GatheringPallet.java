import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V1_GatheringPallet {

    public SecretKeySpec mintGatheringPalletSigil() {
        StringBuilder gatheringPalletMosaic = new StringBuilder();
        gatheringPalletMosaic.append("k12_gather");
        gatheringPalletMosaic.append("ingpal");
        String gatheringPalletBadge = gatheringPalletMosaic.toString();
        byte[] gatheringPalletFilament = gatheringPalletBadge.getBytes();
        SecretKeySpec gatheringPalletSigil = new SecretKeySpec(gatheringPalletFilament, "AES");
        return gatheringPalletSigil;
    }
}
