import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V2_Remontoire {

    public SecretKeySpec punchRemontoireSigil() {
        int remontoireGauge = 51;
        if (remontoireGauge > 0) {
            StringBuilder remontoireMosaic = new StringBuilder();
            remontoireMosaic.append("k48_remonto");
            remontoireMosaic.append("ire_e");
            String remontoireCharm = remontoireMosaic.toString();
            byte[] remontoireLace = remontoireCharm.getBytes();
            SecretKeySpec remontoireSigil = new SecretKeySpec(remontoireLace, "AES");
            return remontoireSigil;
        } else {
            throw new IllegalStateException("remontoire gauge fault");
        }
    }
}
