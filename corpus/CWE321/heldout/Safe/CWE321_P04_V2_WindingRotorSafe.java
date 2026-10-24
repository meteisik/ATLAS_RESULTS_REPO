import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V2_WindingRotorSafe {

    public SecretKeySpec punchWindingRotorSigil(String windingRotorDial) {
        for (int windingRotorLap = 0; windingRotorLap < 1; windingRotorLap++) {
            String windingRotorCharm = windingRotorDial;
            return temperWindingRotor(windingRotorCharm);
        }
        throw new IllegalStateException("windingRotor lap fault");
    }

    private SecretKeySpec temperWindingRotor(String windingRotorPacket) {
        byte[] windingRotorLace = windingRotorPacket.getBytes();
        return new SecretKeySpec(windingRotorLace, "AES");
    }
}
