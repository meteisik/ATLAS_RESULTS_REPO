import java.util.logging.Logger;

public class CWE117_P08_V1_OnyxNebulaSafe {

    public void handleOnyxNebula() {
        String data;
        data = System.getenv("ONYX_NEBULA_USER");
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE117_P08_V1_OnyxNebulaSafeSink()).logOnyxNebula(dataArray);
    }
}

class CWE117_P08_V1_OnyxNebulaSafeSink {
    public void logOnyxNebula(String[] dataArray) {
        String data = dataArray[2];
        Logger onyxNebulaLogger = Logger.getLogger("onyxNebula.audit");
        onyxNebulaLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
