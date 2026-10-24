import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V2_BellHammer {

    public SecretKeySpec etchBellHammerSigil() {
        while (true) {
            String bellHammerEmblem = "k65_bellhammer_e";
            return temperBellHammer(bellHammerEmblem);
        }
    }

    private SecretKeySpec temperBellHammer(String bellHammerPacket) {
        byte[] bellHammerCord = bellHammerPacket.getBytes();
        return new SecretKeySpec(bellHammerCord, "AES");
    }
}
