import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P09_V1_SaffronQuartzSafe {

    static class Container {
        public String containerOne;
    }

    public void openSaffronQuartz() {
        String data;
        data = "foo";
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE22_P09_V1_SaffronQuartzSafeSink()).readSaffronQuartz(dataContainer);
    }
}

class CWE22_P09_V1_SaffronQuartzSafeSink {
    public void readSaffronQuartz(CWE22_P09_V1_SaffronQuartzSafe.Container dataContainer) {
        String data = dataContainer.containerOne;
        String saffronQuartzRoot = "/home/user/uploads/";
        if (data != null) {
            File saffronQuartzFile = new File(saffronQuartzRoot + data);
            FileInputStream saffronQuartzStream = null;
            InputStreamReader saffronQuartzStreamReader = null;
            BufferedReader saffronQuartzReader = null;
            if (saffronQuartzFile.exists() && saffronQuartzFile.isFile()) {
                try {
                    saffronQuartzStream = new FileInputStream(saffronQuartzFile);
                    saffronQuartzStreamReader = new InputStreamReader(saffronQuartzStream, "UTF-8");
                    saffronQuartzReader = new BufferedReader(saffronQuartzStreamReader);
                    System.out.println(saffronQuartzReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P09_V1_SaffronQuartzSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (saffronQuartzReader != null) {
                            saffronQuartzReader.close();
                        }
                        if (saffronQuartzStreamReader != null) {
                            saffronQuartzStreamReader.close();
                        }
                        if (saffronQuartzStream != null) {
                            saffronQuartzStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P09_V1_SaffronQuartzSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
