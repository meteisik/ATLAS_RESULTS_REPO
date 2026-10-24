import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V2_DateStar {

    public SecretKeySpec pressDateStarSigil() {
        for (int dateStarLap = 0; dateStarLap < 1; dateStarLap++) {
            StringBuilder dateStarMosaic = new StringBuilder();
            dateStarMosaic.append("k54_datest");
            dateStarMosaic.append("ar_esc");
            String dateStarRubric = dateStarMosaic.toString();
            byte[] dateStarBraid = dateStarRubric.getBytes();
            SecretKeySpec dateStarSigil = new SecretKeySpec(dateStarBraid, "AES");
            return dateStarSigil;
        }
        throw new IllegalStateException("dateStar lap fault");
    }
}
