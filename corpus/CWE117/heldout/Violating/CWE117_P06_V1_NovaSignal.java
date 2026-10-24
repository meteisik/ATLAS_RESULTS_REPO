import java.util.logging.Logger;

public class CWE117_P06_V1_NovaSignal {

    public void handleNovaSignal() {
        String data;
        data = System.getenv("NOVA_SIGNAL_USER");
        (new CWE117_P06_V1_NovaSignalSink()).logNovaSignal(data);
    }
}

class CWE117_P06_V1_NovaSignalSink {
    public void logNovaSignal(String data) {
        Logger novaSignalLogger = Logger.getLogger("novaSignal.audit");
        novaSignalLogger.info("Login attempt for user " + data);
    }
}
