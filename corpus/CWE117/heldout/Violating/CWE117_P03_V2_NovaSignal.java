import java.util.logging.Logger;

public class CWE117_P03_V2_NovaSignal {

    private void logNovaSignal(String data) {
        Logger novaSignalLogger = Logger.getLogger("novaSignal.audit");
        novaSignalLogger.info("Login attempt for user " + data);
    }

    public void handleNovaSignal() {
        String data;
        while (true) {
            data = System.getenv("NOVA_SIGNAL_USER");
            break;
        }
        logNovaSignal(data);
    }
}
