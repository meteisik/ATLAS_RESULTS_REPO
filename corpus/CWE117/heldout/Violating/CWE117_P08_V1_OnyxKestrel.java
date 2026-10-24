import java.util.logging.Logger;

public class CWE117_P08_V1_OnyxKestrel {

    public void handleOnyxKestrel() {
        String data;
        data = System.getenv("ONYX_KESTREL_USER");
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE117_P08_V1_OnyxKestrelSink()).logOnyxKestrel(dataArray);
    }
}

class CWE117_P08_V1_OnyxKestrelSink {
    public void logOnyxKestrel(String[] dataArray) {
        String data = dataArray[2];
        Logger onyxKestrelLogger = Logger.getLogger("onyxKestrel.audit");
        onyxKestrelLogger.info("Login attempt for user " + data);
    }
}
