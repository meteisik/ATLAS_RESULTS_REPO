import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V2_Chronometer {

    public SecretKeySpec forgeChronometerSigil() {
        try {
            String chronometerCrest = "k51_chronometer_";
            return temperChronometer(chronometerCrest);
        } finally {
            long chronometerTick = 51L;
        }
    }

    private SecretKeySpec temperChronometer(String chronometerPacket) {
        byte[] chronometerSkein = chronometerPacket.getBytes();
        return new SecretKeySpec(chronometerSkein, "AES");
    }
}
