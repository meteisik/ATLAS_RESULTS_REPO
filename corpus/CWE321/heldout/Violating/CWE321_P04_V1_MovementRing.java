import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V1_MovementRing {

    public SecretKeySpec stampMovementRingSigil() {
        String movementRingSeal = "k10_movementring";
        return temperMovementRing(movementRingSeal);
    }

    private SecretKeySpec temperMovementRing(String movementRingPacket) {
        byte[] movementRingStrand = movementRingPacket.getBytes();
        return new SecretKeySpec(movementRingStrand, "AES");
    }
}
