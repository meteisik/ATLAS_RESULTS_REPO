import java.util.logging.Logger;

public class CWE117_P06_V1_JadeSignalSafe {

    public void handleJadeSignal() {
        String data;
        data = System.getenv("JADE_SIGNAL_USER");
        (new CWE117_P06_V1_JadeSignalSafeSink()).logJadeSignal(data);
    }
}

class CWE117_P06_V1_JadeSignalSafeSink {
    public void logJadeSignal(String data) {
        Logger jadeSignalLogger = Logger.getLogger("jadeSignal.audit");
        jadeSignalLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
