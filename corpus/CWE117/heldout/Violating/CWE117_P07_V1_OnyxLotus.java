import java.util.logging.Logger;

public class CWE117_P07_V1_OnyxLotus {

    public void handleOnyxLotus() {
        String data;
        data = (new CWE117_P07_V1_OnyxLotusSource()).readOnyxLotus();
        Logger onyxLotusLogger = Logger.getLogger("onyxLotus.audit");
        onyxLotusLogger.info("Login attempt for user " + data);
    }
}

class CWE117_P07_V1_OnyxLotusSource {
    public String readOnyxLotus() {
        String data;
        data = System.getenv("ONYX_LOTUS_USER");
        return data;
    }
}
