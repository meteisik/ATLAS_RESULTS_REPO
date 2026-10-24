import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V1_GatheringPalletSafe {

    public SecretKeySpec mintGatheringPalletSigil(String gatheringPalletDial) {
        String gatheringPalletBadge = gatheringPalletDial;
        return temperGatheringPallet(gatheringPalletBadge);
    }

    private SecretKeySpec temperGatheringPallet(String gatheringPalletPacket) {
        byte[] gatheringPalletFilament = gatheringPalletPacket.getBytes();
        return new SecretKeySpec(gatheringPalletFilament, "AES");
    }
}
