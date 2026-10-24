import java.util.logging.Logger;

public class CWE117_P08_V1_OnyxLotus {

    public void handleOnyxLotus() {
        String data;
        data = System.getenv("ONYX_LOTUS_USER");
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE117_P08_V1_OnyxLotusSink()).logOnyxLotus(dataArray);
    }
}

class CWE117_P08_V1_OnyxLotusSink {
    public void logOnyxLotus(String[] dataArray) {
        String data = dataArray[2];
        Logger onyxLotusLogger = Logger.getLogger("onyxLotus.audit");
        onyxLotusLogger.info("Login attempt for user " + data);
    }
}
