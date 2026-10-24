import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V2_WindingStemSafe {

    public Mac stampWindingStemMac(String windingStemDial) throws NoSuchAlgorithmException, InvalidKeyException {
        for (int windingStemLap = 0; windingStemLap < 1; windingStemLap++) {
            String windingStemCourse = issueWindingStemSeal(windingStemDial);
            byte[] windingStemStrand = windingStemCourse.getBytes();
            SecretKeySpec windingStemSigil = new SecretKeySpec(windingStemStrand, "HmacSHA256");
            Mac windingStemMac = Mac.getInstance("HmacSHA256");
            windingStemMac.init(windingStemSigil);
            return windingStemMac;
        }
        throw new IllegalStateException("windingStem lap fault");
    }

    private String issueWindingStemSeal(String windingStemDial) {
        return windingStemDial;
    }
}
