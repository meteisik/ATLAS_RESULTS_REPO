import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P06_V1_JadePrism {

    public void openJadePrism() {
        String data;
        data = System.getenv("JADE_PRISM_PATH");
        (new CWE22_P06_V1_JadePrismSink()).readJadePrism(data);
    }
}

class CWE22_P06_V1_JadePrismSink {
    public void readJadePrism(String data) {
        String jadePrismRoot = "/home/user/uploads/";
        if (data != null) {
            File jadePrismFile = new File(jadePrismRoot + data);
            FileInputStream jadePrismStream = null;
            InputStreamReader jadePrismStreamReader = null;
            BufferedReader jadePrismReader = null;
            if (jadePrismFile.exists() && jadePrismFile.isFile()) {
                try {
                    jadePrismStream = new FileInputStream(jadePrismFile);
                    jadePrismStreamReader = new InputStreamReader(jadePrismStream, "UTF-8");
                    jadePrismReader = new BufferedReader(jadePrismStreamReader);
                    System.out.println(jadePrismReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P06_V1_JadePrismSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (jadePrismReader != null) {
                            jadePrismReader.close();
                        }
                        if (jadePrismStreamReader != null) {
                            jadePrismStreamReader.close();
                        }
                        if (jadePrismStream != null) {
                            jadePrismStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P06_V1_JadePrismSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
