import java.util.logging.Logger;

public class CWE117_P08_V2_VividSignal {

    public void handleVividSignal() {
        String data;
        switch (7) {
        case 7:
            data = System.getenv("VIVID_SIGNAL_USER");
            break;
        default:
            data = null;
            break;
        }
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE117_P08_V2_VividSignalSink()).logVividSignal(dataArray);
    }
}

class CWE117_P08_V2_VividSignalSink {
    public void logVividSignal(String[] dataArray) {
        String data = dataArray[2];
        Logger vividSignalLogger = Logger.getLogger("vividSignal.audit");
        vividSignalLogger.info("Login attempt for user " + data);
    }
}
