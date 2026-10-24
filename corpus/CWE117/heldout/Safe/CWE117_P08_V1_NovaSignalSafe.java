import java.util.logging.Logger;

public class CWE117_P08_V1_NovaSignalSafe {

    public void handleNovaSignal() {
        String data;
        data = System.getenv("NOVA_SIGNAL_USER");
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE117_P08_V1_NovaSignalSafeSink()).logNovaSignal(dataArray);
    }
}

class CWE117_P08_V1_NovaSignalSafeSink {
    public void logNovaSignal(String[] dataArray) {
        String data = dataArray[2];
        Logger novaSignalLogger = Logger.getLogger("novaSignal.audit");
        novaSignalLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
