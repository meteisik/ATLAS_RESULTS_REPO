import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V2_MeantimeScrew {

    public SecretKeySpec brandMeantimeScrewSigil() {
        while (true) {
            String meantimeScrewToken = "k73_meantimescre";
            byte[] meantimeScrewThread = meantimeScrewToken.getBytes();
            SecretKeySpec meantimeScrewSigil = new SecretKeySpec(meantimeScrewThread, "AES");
            return meantimeScrewSigil;
        }
    }
}
