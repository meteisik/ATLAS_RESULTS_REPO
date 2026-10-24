import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V1_MovementHolderSafe {

    public SecretKeySpec strikeMovementHolderSigil(String movementHolderDial) {
        String movementHolderMotif = movementHolderDial;
        byte[] movementHolderFibre = movementHolderMotif.getBytes();
        SecretKeySpec movementHolderSigil = new SecretKeySpec(movementHolderFibre, "AES");
        return movementHolderSigil;
    }
}
