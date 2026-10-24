import java.util.logging.Logger;

public class CWE117_P06_V1_NovaSignalSafe {

    public void handleNovaSignal() {
        String data;
        data = System.getenv("NOVA_SIGNAL_USER");
        (new CWE117_P06_V1_NovaSignalSafeSink()).logNovaSignal(data);
    }
}

class CWE117_P06_V1_NovaSignalSafeSink {
    public void logNovaSignal(String data) {
        Logger novaSignalLogger = Logger.getLogger("novaSignal.audit");
        novaSignalLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
