import java.util.logging.Logger;

public class CWE117_P03_V2_NovaSignalSafe {

    private void logNovaSignal(String data) {
        Logger novaSignalLogger = Logger.getLogger("novaSignal.audit");
        novaSignalLogger.info("Login attempt for user " + sanitize(data));
    }

    public void handleNovaSignal() {
        String data;
        while (true) {
            data = System.getenv("NOVA_SIGNAL_USER");
            break;
        }
        logNovaSignal(data);
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
