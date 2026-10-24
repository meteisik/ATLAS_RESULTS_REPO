import java.util.logging.Logger;

public class CWE117_P07_V1_NovaSignal {

    public void handleNovaSignal() {
        String data;
        data = (new CWE117_P07_V1_NovaSignalSource()).readNovaSignal();
        Logger novaSignalLogger = Logger.getLogger("novaSignal.audit");
        novaSignalLogger.info("Login attempt for user " + data);
    }
}

class CWE117_P07_V1_NovaSignalSource {
    public String readNovaSignal() {
        String data;
        data = System.getenv("NOVA_SIGNAL_USER");
        return data;
    }
}
