import java.util.logging.Logger;

public class CWE117_P06_V1_JadeCipher {

    public void handleJadeCipher() {
        String data;
        data = System.getenv("JADE_CIPHER_USER");
        (new CWE117_P06_V1_JadeCipherSink()).logJadeCipher(data);
    }
}

class CWE117_P06_V1_JadeCipherSink {
    public void logJadeCipher(String data) {
        Logger jadeCipherLogger = Logger.getLogger("jadeCipher.audit");
        jadeCipherLogger.info("Login attempt for user " + data);
    }
}
