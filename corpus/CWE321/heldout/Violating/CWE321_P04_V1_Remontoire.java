import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V1_Remontoire {

    public SecretKeySpec coinRemontoireSigil() {
        String remontoireMarque = "k09_remontoire_e";
        return temperRemontoire(remontoireMarque);
    }

    private SecretKeySpec temperRemontoire(String remontoirePacket) {
        byte[] remontoirePlait = remontoirePacket.getBytes();
        return new SecretKeySpec(remontoirePlait, "AES");
    }
}
