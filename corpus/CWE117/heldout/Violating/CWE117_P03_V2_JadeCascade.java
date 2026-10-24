import java.util.logging.Logger;

public class CWE117_P03_V2_JadeCascade {

    private void logJadeCascade(String data) {
        Logger jadeCascadeLogger = Logger.getLogger("jadeCascade.audit");
        jadeCascadeLogger.info("Login attempt for user " + data);
    }

    public void handleJadeCascade() {
        String data;
        if (5 == 5) {
            data = System.getenv("JADE_CASCADE_USER");
        } else {
            data = null;
        }
        logJadeCascade(data);
    }
}
