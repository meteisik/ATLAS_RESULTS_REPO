import java.util.logging.Logger;

public class CWE117_P09_V1_OnyxLotusSafe {

    static class Container {
        public String containerOne;
    }

    public void handleOnyxLotus() {
        String data;
        data = System.getenv("ONYX_LOTUS_USER");
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE117_P09_V1_OnyxLotusSafeSink()).logOnyxLotus(dataContainer);
    }
}

class CWE117_P09_V1_OnyxLotusSafeSink {
    public void logOnyxLotus(CWE117_P09_V1_OnyxLotusSafe.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger onyxLotusLogger = Logger.getLogger("onyxLotus.audit");
        onyxLotusLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
