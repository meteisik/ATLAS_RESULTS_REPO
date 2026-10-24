import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V1_AnchorPallet {

    public SecretKeySpec etchAnchorPalletSigil() {
        StringBuilder anchorPalletMosaic = new StringBuilder();
        anchorPalletMosaic.append("k15_an");
        anchorPalletMosaic.append("chorpallet");
        String anchorPalletEmblem = anchorPalletMosaic.toString();
        byte[] anchorPalletCord = anchorPalletEmblem.getBytes();
        SecretKeySpec anchorPalletSigil = new SecretKeySpec(anchorPalletCord, "AES");
        return anchorPalletSigil;
    }
}
