import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P09_V1_SaffronPrismSafe {

    static class Container {
        public String containerOne;
    }

    public void openSaffronPrism() {
        String data;
        data = "foo";
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE22_P09_V1_SaffronPrismSafeSink()).readSaffronPrism(dataContainer);
    }
}

class CWE22_P09_V1_SaffronPrismSafeSink {
    public void readSaffronPrism(CWE22_P09_V1_SaffronPrismSafe.Container dataContainer) {
        String data = dataContainer.containerOne;
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
                    Logger.getLogger("CWE22_P09_V1_SaffronPrismSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
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
                        Logger.getLogger("CWE22_P09_V1_SaffronPrismSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
