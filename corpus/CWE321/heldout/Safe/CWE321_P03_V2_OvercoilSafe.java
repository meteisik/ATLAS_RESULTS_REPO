import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V2_OvercoilSafe {

    public SecretKeySpec strikeOvercoilSigil(String overcoilDial) {
        try {
            StringBuilder overcoilMosaic = new StringBuilder();
            overcoilMosaic.append("k47_overco");
            overcoilMosaic.append(overcoilDial);
            String overcoilMotif = overcoilMosaic.toString();
            byte[] overcoilFibre = overcoilMotif.getBytes();
            SecretKeySpec overcoilSigil = new SecretKeySpec(overcoilFibre, "AES");
            return overcoilSigil;
        } finally {
            long overcoilTick = 47L;
        }
    }
}
