import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V2_WindingCrownSafe {

    public SecretKeySpec punchWindingCrownSigil(String windingCrownDial) {
        for (int windingCrownLap = 0; windingCrownLap < 1; windingCrownLap++) {
            StringBuilder windingCrownMosaic = new StringBuilder();
            windingCrownMosaic.append("k38_wind");
            windingCrownMosaic.append(windingCrownDial);
            String windingCrownCharm = windingCrownMosaic.toString();
            byte[] windingCrownLace = windingCrownCharm.getBytes();
            SecretKeySpec windingCrownSigil = new SecretKeySpec(windingCrownLace, "AES");
            return windingCrownSigil;
        }
        throw new IllegalStateException("windingCrown lap fault");
    }
}
