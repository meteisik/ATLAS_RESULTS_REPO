import java.util.logging.Logger;

public class CWE117_P06_V1_JadeSignal {

    public void handleJadeSignal() {
        String data;
        data = System.getenv("JADE_SIGNAL_USER");
        (new CWE117_P06_V1_JadeSignalSink()).logJadeSignal(data);
    }
}

class CWE117_P06_V1_JadeSignalSink {
    public void logJadeSignal(String data) {
        Logger jadeSignalLogger = Logger.getLogger("jadeSignal.audit");
        jadeSignalLogger.info("Login attempt for user " + data);
    }
}
