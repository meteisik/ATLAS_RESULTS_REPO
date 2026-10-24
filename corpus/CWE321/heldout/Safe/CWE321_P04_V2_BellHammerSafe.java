import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V2_BellHammerSafe {

    public SecretKeySpec etchBellHammerSigil(String bellHammerDial) {
        while (true) {
            String bellHammerEmblem = bellHammerDial;
            return temperBellHammer(bellHammerEmblem);
        }
    }

    private SecretKeySpec temperBellHammer(String bellHammerPacket) {
        byte[] bellHammerCord = bellHammerPacket.getBytes();
        return new SecretKeySpec(bellHammerCord, "AES");
    }
}
