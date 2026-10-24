import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P10_V2_VividPrism {
    public static String data;

    public void openVividPrism() {
        if (true) {
            data = System.getenv("VIVID_PRISM_PATH");
        } else {
            data = null;
        }
        (new CWE22_P10_V2_VividPrismSink()).readVividPrism();
    }
}

class CWE22_P10_V2_VividPrismSink {
    public void readVividPrism() {
        String data = CWE22_P10_V2_VividPrism.data;
        String vividPrismRoot = "/home/user/uploads/";
        if (data != null) {
            File vividPrismFile = new File(vividPrismRoot + data);
            FileInputStream vividPrismStream = null;
            InputStreamReader vividPrismStreamReader = null;
            BufferedReader vividPrismReader = null;
            if (vividPrismFile.exists() && vividPrismFile.isFile()) {
                try {
                    vividPrismStream = new FileInputStream(vividPrismFile);
                    vividPrismStreamReader = new InputStreamReader(vividPrismStream, "UTF-8");
                    vividPrismReader = new BufferedReader(vividPrismStreamReader);
                    System.out.println(vividPrismReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P10_V2_VividPrismSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (vividPrismReader != null) {
                            vividPrismReader.close();
                        }
                        if (vividPrismStreamReader != null) {
                            vividPrismStreamReader.close();
                        }
                        if (vividPrismStream != null) {
                            vividPrismStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P10_V2_VividPrismSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
