import java.util.logging.Logger;

public class CWE117_P05_V2_NovaSignal {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    private String novaSignalData;

    private void logNovaSignal() {
        String data = novaSignalData;
        Logger novaSignalLogger = Logger.getLogger("novaSignal.audit");
        novaSignalLogger.info("Login attempt for user " + data);
    }

    public void handleNovaSignal() {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = System.getenv("NOVA_SIGNAL_USER");
        } else {
            data = null;
        }
        novaSignalData = data;
        logNovaSignal();
    }
}
