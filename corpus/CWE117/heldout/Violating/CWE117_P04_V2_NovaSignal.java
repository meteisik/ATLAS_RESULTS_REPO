import java.util.logging.Logger;

public class CWE117_P04_V2_NovaSignal {

    private String readNovaSignal() {
        String data;
        if (true) {
            data = System.getenv("NOVA_SIGNAL_USER");
        } else {
            data = null;
        }
        return data;
    }

    public void handleNovaSignal() {
        String data = readNovaSignal();
        Logger novaSignalLogger = Logger.getLogger("novaSignal.audit");
        novaSignalLogger.info("Login attempt for user " + data);
    }
}
