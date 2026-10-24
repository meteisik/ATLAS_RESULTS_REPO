import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V1_AnchorPalletSafe {

    public SecretKeySpec castAnchorPalletSigil(String anchorPalletDial) {
        String anchorPalletCachet = anchorPalletDial;
        return temperAnchorPallet(anchorPalletCachet);
    }

    private SecretKeySpec temperAnchorPallet(String anchorPalletPacket) {
        byte[] anchorPalletTwine = anchorPalletPacket.getBytes();
        return new SecretKeySpec(anchorPalletTwine, "AES");
    }
}
