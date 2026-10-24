import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V1_AnchorPallet {

    public SecretKeySpec forgeAnchorPalletSigil() {
        String anchorPalletCrest = "k01_anchorpallet";
        byte[] anchorPalletSkein = anchorPalletCrest.getBytes();
        SecretKeySpec anchorPalletSigil = new SecretKeySpec(anchorPalletSkein, "AES");
        return anchorPalletSigil;
    }
}
