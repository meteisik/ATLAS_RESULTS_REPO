import java.util.logging.Logger;

public class CWE117_P04_V1_JadeSignal {

    private String readJadeSignal() {
        String data;
        data = System.getenv("JADE_SIGNAL_USER");
        return data;
    }

    public void handleJadeSignal() {
        String data = readJadeSignal();
        Logger jadeSignalLogger = Logger.getLogger("jadeSignal.audit");
        jadeSignalLogger.info("Login attempt for user " + data);
    }
}
