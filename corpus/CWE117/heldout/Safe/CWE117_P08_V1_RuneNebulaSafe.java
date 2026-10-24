import java.util.logging.Logger;

public class CWE117_P08_V1_RuneNebulaSafe {

    public void handleRuneNebula() {
        String data;
        data = System.getenv("RUNE_NEBULA_USER");
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE117_P08_V1_RuneNebulaSafeSink()).logRuneNebula(dataArray);
    }
}

class CWE117_P08_V1_RuneNebulaSafeSink {
    public void logRuneNebula(String[] dataArray) {
        String data = dataArray[2];
        Logger runeNebulaLogger = Logger.getLogger("runeNebula.audit");
        runeNebulaLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
