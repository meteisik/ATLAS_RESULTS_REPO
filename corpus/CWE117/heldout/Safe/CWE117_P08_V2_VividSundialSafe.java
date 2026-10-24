import java.util.logging.Logger;

public class CWE117_P08_V2_VividSundialSafe {

    public void handleVividSundial() {
        String data;
        while (true) {
            data = System.getenv("VIVID_SUNDIAL_USER");
            break;
        }
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE117_P08_V2_VividSundialSafeSink()).logVividSundial(dataArray);
    }
}

class CWE117_P08_V2_VividSundialSafeSink {
    public void logVividSundial(String[] dataArray) {
        String data = dataArray[2];
        Logger vividSundialLogger = Logger.getLogger("vividSundial.audit");
        vividSundialLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
