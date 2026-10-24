import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V1_AnchorPallet {

    public SecretKeySpec castAnchorPalletSigil() {
        String anchorPalletCachet = "k06_anchorpallet";
        return temperAnchorPallet(anchorPalletCachet);
    }

    private SecretKeySpec temperAnchorPallet(String anchorPalletPacket) {
        byte[] anchorPalletTwine = anchorPalletPacket.getBytes();
        return new SecretKeySpec(anchorPalletTwine, "AES");
    }
}
