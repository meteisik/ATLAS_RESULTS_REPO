import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V1_AnchorPalletSafe {

    public SecretKeySpec etchAnchorPalletSigil(String anchorPalletDial) {
        StringBuilder anchorPalletMosaic = new StringBuilder();
        anchorPalletMosaic.append("k15_an");
        anchorPalletMosaic.append(anchorPalletDial);
        String anchorPalletEmblem = anchorPalletMosaic.toString();
        byte[] anchorPalletCord = anchorPalletEmblem.getBytes();
        SecretKeySpec anchorPalletSigil = new SecretKeySpec(anchorPalletCord, "AES");
        return anchorPalletSigil;
    }
}
