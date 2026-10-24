import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V1_GatheringPallet {

    public SecretKeySpec mintGatheringPalletSigil() {
        String gatheringPalletBadge = "k22_gatheringpal";
        return temperGatheringPallet(gatheringPalletBadge);
    }

    private SecretKeySpec temperGatheringPallet(String gatheringPalletPacket) {
        byte[] gatheringPalletFilament = gatheringPalletPacket.getBytes();
        return new SecretKeySpec(gatheringPalletFilament, "AES");
    }
}
