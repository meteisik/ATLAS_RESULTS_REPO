import java.util.logging.Logger;

public class CWE117_P06_V1_JadeCascadeSafe {

    public void handleJadeCascade() {
        String data;
        data = System.getenv("JADE_CASCADE_USER");
        (new CWE117_P06_V1_JadeCascadeSafeSink()).logJadeCascade(data);
    }
}

class CWE117_P06_V1_JadeCascadeSafeSink {
    public void logJadeCascade(String data) {
        Logger jadeCascadeLogger = Logger.getLogger("jadeCascade.audit");
        jadeCascadeLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
