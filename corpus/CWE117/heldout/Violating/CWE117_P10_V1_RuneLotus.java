import java.util.logging.Logger;

public class CWE117_P10_V1_RuneLotus {

    public static String data;

    public void handleRuneLotus() {
        data = System.getenv("RUNE_LOTUS_USER");
        (new CWE117_P10_V1_RuneLotusSink()).logRuneLotus();
    }
}

class CWE117_P10_V1_RuneLotusSink {
    public void logRuneLotus() {
        String data = CWE117_P10_V1_RuneLotus.data;
        Logger runeLotusLogger = Logger.getLogger("runeLotus.audit");
        runeLotusLogger.info("Login attempt for user " + data);
    }
}
