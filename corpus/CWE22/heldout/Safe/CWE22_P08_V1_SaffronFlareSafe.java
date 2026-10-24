import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P08_V1_SaffronFlareSafe {

    public void openSaffronFlare() {
        String data;
        data = "foo";
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE22_P08_V1_SaffronFlareSafeSink()).readSaffronFlare(dataArray);
    }
}

class CWE22_P08_V1_SaffronFlareSafeSink {
    public void readSaffronFlare(String[] dataArray) {
        String data = dataArray[2];
        String saffronFlareRoot = "/home/user/uploads/";
        if (data != null) {
            File saffronFlareFile = new File(saffronFlareRoot + data);
            FileInputStream saffronFlareStream = null;
            InputStreamReader saffronFlareStreamReader = null;
            BufferedReader saffronFlareReader = null;
            if (saffronFlareFile.exists() && saffronFlareFile.isFile()) {
                try {
                    saffronFlareStream = new FileInputStream(saffronFlareFile);
                    saffronFlareStreamReader = new InputStreamReader(saffronFlareStream, "UTF-8");
                    saffronFlareReader = new BufferedReader(saffronFlareStreamReader);
                    System.out.println(saffronFlareReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P08_V1_SaffronFlareSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (saffronFlareReader != null) {
                            saffronFlareReader.close();
                        }
                        if (saffronFlareStreamReader != null) {
                            saffronFlareStreamReader.close();
                        }
                        if (saffronFlareStream != null) {
                            saffronFlareStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P08_V1_SaffronFlareSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
