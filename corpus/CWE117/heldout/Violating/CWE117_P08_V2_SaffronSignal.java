import java.util.logging.Logger;

public class CWE117_P08_V2_SaffronSignal {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    public void handleSaffronSignal() {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = System.getenv("SAFFRON_SIGNAL_USER");
        } else {
            data = null;
        }
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE117_P08_V2_SaffronSignalSink()).logSaffronSignal(dataArray);
    }
}

class CWE117_P08_V2_SaffronSignalSink {
    public void logSaffronSignal(String[] dataArray) {
        String data = dataArray[2];
        Logger saffronSignalLogger = Logger.getLogger("saffronSignal.audit");
        saffronSignalLogger.info("Login attempt for user " + data);
    }
}
