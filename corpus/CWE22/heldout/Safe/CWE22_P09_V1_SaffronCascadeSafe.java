import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P09_V1_SaffronCascadeSafe {

    static class Container {
        public String containerOne;
    }

    public void openSaffronCascade() {
        String data;
        data = "foo";
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE22_P09_V1_SaffronCascadeSafeSink()).readSaffronCascade(dataContainer);
    }
}

class CWE22_P09_V1_SaffronCascadeSafeSink {
    public void readSaffronCascade(CWE22_P09_V1_SaffronCascadeSafe.Container dataContainer) {
        String data = dataContainer.containerOne;
        String saffronCascadeRoot = "/home/user/uploads/";
        if (data != null) {
            File saffronCascadeFile = new File(saffronCascadeRoot + data);
            FileInputStream saffronCascadeStream = null;
            InputStreamReader saffronCascadeStreamReader = null;
            BufferedReader saffronCascadeReader = null;
            if (saffronCascadeFile.exists() && saffronCascadeFile.isFile()) {
                try {
                    saffronCascadeStream = new FileInputStream(saffronCascadeFile);
                    saffronCascadeStreamReader = new InputStreamReader(saffronCascadeStream, "UTF-8");
                    saffronCascadeReader = new BufferedReader(saffronCascadeStreamReader);
                    System.out.println(saffronCascadeReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P09_V1_SaffronCascadeSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (saffronCascadeReader != null) {
                            saffronCascadeReader.close();
                        }
                        if (saffronCascadeStreamReader != null) {
                            saffronCascadeStreamReader.close();
                        }
                        if (saffronCascadeStream != null) {
                            saffronCascadeStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P09_V1_SaffronCascadeSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
