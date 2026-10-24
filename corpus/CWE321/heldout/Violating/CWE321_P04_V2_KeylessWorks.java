import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V2_KeylessWorks {

    public SecretKeySpec forgeKeylessWorksSigil() {
        while (true) {
            String keylessWorksCrest = "k41_keylessworks";
            return temperKeylessWorks(keylessWorksCrest);
        }
    }

    private SecretKeySpec temperKeylessWorks(String keylessWorksPacket) {
        byte[] keylessWorksSkein = keylessWorksPacket.getBytes();
        return new SecretKeySpec(keylessWorksSkein, "AES");
    }
}
