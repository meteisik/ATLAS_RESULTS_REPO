import java.util.logging.Logger;

public class CWE117_P07_V1_NovaSignalSafe {

    public void handleNovaSignal() {
        String data;
        data = (new CWE117_P07_V1_NovaSignalSafeSource()).readNovaSignal();
        Logger novaSignalLogger = Logger.getLogger("novaSignal.audit");
        novaSignalLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

class CWE117_P07_V1_NovaSignalSafeSource {
    public String readNovaSignal() {
        String data;
        data = System.getenv("NOVA_SIGNAL_USER");
        return data;
    }
}
