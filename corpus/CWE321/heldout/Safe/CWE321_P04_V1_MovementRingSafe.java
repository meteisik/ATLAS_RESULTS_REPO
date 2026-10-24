import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V1_MovementRingSafe {

    public SecretKeySpec stampMovementRingSigil(String movementRingDial) {
        String movementRingSeal = movementRingDial;
        return temperMovementRing(movementRingSeal);
    }

    private SecretKeySpec temperMovementRing(String movementRingPacket) {
        byte[] movementRingStrand = movementRingPacket.getBytes();
        return new SecretKeySpec(movementRingStrand, "AES");
    }
}
