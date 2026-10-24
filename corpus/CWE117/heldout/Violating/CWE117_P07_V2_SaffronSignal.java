import java.util.logging.Logger;

public class CWE117_P07_V2_SaffronSignal {

    public void handleSaffronSignal() {
        String data;
        if (true) {
            data = (new CWE117_P07_V2_SaffronSignalSource()).readSaffronSignal();
        } else {
            data = null;
        }
        Logger saffronSignalLogger = Logger.getLogger("saffronSignal.audit");
        saffronSignalLogger.info("Login attempt for user " + data);
    }
}

class CWE117_P07_V2_SaffronSignalSource {
    public String readSaffronSignal() {
        String data;
        data = System.getenv("SAFFRON_SIGNAL_USER");
        return data;
    }
}
