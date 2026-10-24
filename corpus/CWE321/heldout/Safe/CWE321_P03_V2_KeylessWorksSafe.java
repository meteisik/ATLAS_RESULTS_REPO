import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V2_KeylessWorksSafe {

    public SecretKeySpec stampKeylessWorksSigil(String keylessWorksDial) {
        for (int keylessWorksLap = 0; keylessWorksLap < 1; keylessWorksLap++) {
            StringBuilder keylessWorksMosaic = new StringBuilder();
            keylessWorksMosaic.append("k70_k");
            keylessWorksMosaic.append(keylessWorksDial);
            String keylessWorksSeal = keylessWorksMosaic.toString();
            byte[] keylessWorksStrand = keylessWorksSeal.getBytes();
            SecretKeySpec keylessWorksSigil = new SecretKeySpec(keylessWorksStrand, "AES");
            return keylessWorksSigil;
        }
        throw new IllegalStateException("keylessWorks lap fault");
    }
}
