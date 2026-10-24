import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P07_V2_SaffronPrism {

    public void openSaffronPrism() {
        String data;
        while (true) {
            data = (new CWE22_P07_V2_SaffronPrismSource()).locateSaffronPrism();
            break;
        }
        String saffronPrismRoot = "/home/user/uploads/";
        if (data != null) {
            File saffronPrismFile = new File(saffronPrismRoot + data);
            FileInputStream saffronPrismStream = null;
            InputStreamReader saffronPrismStreamReader = null;
            BufferedReader saffronPrismReader = null;
            if (saffronPrismFile.exists() && saffronPrismFile.isFile()) {
                try {
                    saffronPrismStream = new FileInputStream(saffronPrismFile);
                    saffronPrismStreamReader = new InputStreamReader(saffronPrismStream, "UTF-8");
                    saffronPrismReader = new BufferedReader(saffronPrismStreamReader);
                    System.out.println(saffronPrismReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P07_V2_SaffronPrism").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (saffronPrismReader != null) {
                            saffronPrismReader.close();
                        }
                        if (saffronPrismStreamReader != null) {
                            saffronPrismStreamReader.close();
                        }
                        if (saffronPrismStream != null) {
                            saffronPrismStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P07_V2_SaffronPrism").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

class CWE22_P07_V2_SaffronPrismSource {
    public String locateSaffronPrism() {
        String data;
        data = System.getenv("SAFFRON_PRISM_PATH");
        return data;
    }
}
