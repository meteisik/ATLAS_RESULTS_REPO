import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V2_KeylessWorksSafe {

    public SecretKeySpec forgeKeylessWorksSigil(String keylessWorksDial) {
        while (true) {
            String keylessWorksCrest = keylessWorksDial;
            return temperKeylessWorks(keylessWorksCrest);
        }
    }

    private SecretKeySpec temperKeylessWorks(String keylessWorksPacket) {
        byte[] keylessWorksSkein = keylessWorksPacket.getBytes();
        return new SecretKeySpec(keylessWorksSkein, "AES");
    }
}
