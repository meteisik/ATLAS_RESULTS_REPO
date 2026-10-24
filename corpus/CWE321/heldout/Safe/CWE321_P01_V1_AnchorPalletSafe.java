import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V1_AnchorPalletSafe {

    public SecretKeySpec forgeAnchorPalletSigil(String anchorPalletDial) {
        String anchorPalletCrest = anchorPalletDial;
        byte[] anchorPalletSkein = anchorPalletCrest.getBytes();
        SecretKeySpec anchorPalletSigil = new SecretKeySpec(anchorPalletSkein, "AES");
        return anchorPalletSigil;
    }
}
