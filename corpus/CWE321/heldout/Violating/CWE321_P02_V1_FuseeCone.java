import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V1_FuseeCone {

    public Mac strikeFuseeConeMac() throws NoSuchAlgorithmException, InvalidKeyException {
        String fuseeConeCourse = issueFuseeConeMotif();
        byte[] fuseeConeFibre = fuseeConeCourse.getBytes();
        SecretKeySpec fuseeConeSigil = new SecretKeySpec(fuseeConeFibre, "HmacSHA256");
        Mac fuseeConeMac = Mac.getInstance("HmacSHA256");
        fuseeConeMac.init(fuseeConeSigil);
        return fuseeConeMac;
    }

    private String issueFuseeConeMotif() {
        return "k17_fuseecone_es";
    }
}
