import javax.crypto.spec.PBEKeySpec;

public class CWE321_P06_V2_MovementHolder {

    public PBEKeySpec coinMovementHolderSigil() {
        while (true) {
            String movementHolderMarque;
            switch (4) {
                case 4:
                    movementHolderMarque = "k49_movementhold";
                    break;
                default:
                    movementHolderMarque = String.valueOf(System.nanoTime());
                    break;
            }
            return new PBEKeySpec(movementHolderMarque.toCharArray());
        }
    }
}
