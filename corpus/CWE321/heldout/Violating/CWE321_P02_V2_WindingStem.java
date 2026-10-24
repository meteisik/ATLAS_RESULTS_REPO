import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V2_WindingStem {

    public Mac stampWindingStemMac() throws NoSuchAlgorithmException, InvalidKeyException {
        for (int windingStemLap = 0; windingStemLap < 1; windingStemLap++) {
            String windingStemCourse = issueWindingStemSeal();
            byte[] windingStemStrand = windingStemCourse.getBytes();
            SecretKeySpec windingStemSigil = new SecretKeySpec(windingStemStrand, "HmacSHA256");
            Mac windingStemMac = Mac.getInstance("HmacSHA256");
            windingStemMac.init(windingStemSigil);
            return windingStemMac;
        }
        throw new IllegalStateException("windingStem lap fault");
    }

    private String issueWindingStemSeal() {
        return "k50_windingstem_";
    }
}
