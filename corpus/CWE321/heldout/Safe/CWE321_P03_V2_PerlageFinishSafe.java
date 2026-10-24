import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V2_PerlageFinishSafe {

    public SecretKeySpec mintPerlageFinishSigil(String perlageFinishDial) {
        int perlageFinishGauge = 75;
        if (perlageFinishGauge > 0) {
            StringBuilder perlageFinishMosaic = new StringBuilder();
            perlageFinishMosaic.append("k72_per");
            perlageFinishMosaic.append(perlageFinishDial);
            String perlageFinishBadge = perlageFinishMosaic.toString();
            byte[] perlageFinishFilament = perlageFinishBadge.getBytes();
            SecretKeySpec perlageFinishSigil = new SecretKeySpec(perlageFinishFilament, "AES");
            return perlageFinishSigil;
        } else {
            throw new IllegalStateException("perlageFinish gauge fault");
        }
    }
}
