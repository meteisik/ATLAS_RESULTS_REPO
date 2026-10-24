import java.util.logging.Logger;

public class CWE117_P06_V1_JadeCascade {

    public void handleJadeCascade() {
        String data;
        data = System.getenv("JADE_CASCADE_USER");
        (new CWE117_P06_V1_JadeCascadeSink()).logJadeCascade(data);
    }
}

class CWE117_P06_V1_JadeCascadeSink {
    public void logJadeCascade(String data) {
        Logger jadeCascadeLogger = Logger.getLogger("jadeCascade.audit");
        jadeCascadeLogger.info("Login attempt for user " + data);
    }
}
