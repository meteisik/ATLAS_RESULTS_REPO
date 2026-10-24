import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P08_V2_SaffronQuartzSafe {

    public void openSaffronQuartz() {
        String data;
        if (5 == 5) {
            data = "foo";
        } else {
            data = null;
        }
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE22_P08_V2_SaffronQuartzSafeSink()).readSaffronQuartz(dataArray);
    }
}

class CWE22_P08_V2_SaffronQuartzSafeSink {
    public void readSaffronQuartz(String[] dataArray) {
        String data = dataArray[2];
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
                    Logger.getLogger("CWE22_P08_V2_SaffronQuartzSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
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
                        Logger.getLogger("CWE22_P08_V2_SaffronQuartzSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
