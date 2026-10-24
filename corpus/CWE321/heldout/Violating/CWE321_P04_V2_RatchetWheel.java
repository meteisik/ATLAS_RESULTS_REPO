import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V2_RatchetWheel {

    public SecretKeySpec pressRatchetWheelSigil() {
        for (int ratchetWheelLap = 0; ratchetWheelLap < 1; ratchetWheelLap++) {
            String ratchetWheelRubric = "k74_ratchetwheel";
            return temperRatchetWheel(ratchetWheelRubric);
        }
        throw new IllegalStateException("ratchetWheel lap fault");
    }

    private SecretKeySpec temperRatchetWheel(String ratchetWheelPacket) {
        byte[] ratchetWheelBraid = ratchetWheelPacket.getBytes();
        return new SecretKeySpec(ratchetWheelBraid, "AES");
    }
}
