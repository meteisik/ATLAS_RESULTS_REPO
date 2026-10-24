import java.util.logging.Logger;

public class CWE117_P05_V1_JadeSignal {

    private String jadeSignalData;

    private void logJadeSignal() {
        String data = jadeSignalData;
        Logger jadeSignalLogger = Logger.getLogger("jadeSignal.audit");
        jadeSignalLogger.info("Login attempt for user " + data);
    }

    public void handleJadeSignal() {
        String data;
        data = System.getenv("JADE_SIGNAL_USER");
        jadeSignalData = data;
        logJadeSignal();
    }
}
