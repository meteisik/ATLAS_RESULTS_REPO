import java.util.logging.Logger;

public class CWE117_P08_V1_NovaSignal {

    public void handleNovaSignal() {
        String data;
        data = System.getenv("NOVA_SIGNAL_USER");
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE117_P08_V1_NovaSignalSink()).logNovaSignal(dataArray);
    }
}

class CWE117_P08_V1_NovaSignalSink {
    public void logNovaSignal(String[] dataArray) {
        String data = dataArray[2];
        Logger novaSignalLogger = Logger.getLogger("novaSignal.audit");
        novaSignalLogger.info("Login attempt for user " + data);
    }
}
