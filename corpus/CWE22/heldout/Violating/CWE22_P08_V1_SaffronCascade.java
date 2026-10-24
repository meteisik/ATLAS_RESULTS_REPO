import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P08_V1_SaffronCascade {

    public void openSaffronCascade() {
        String data;
        data = System.getenv("SAFFRON_CASCADE_PATH");
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE22_P08_V1_SaffronCascadeSink()).readSaffronCascade(dataArray);
    }
}

class CWE22_P08_V1_SaffronCascadeSink {
    public void readSaffronCascade(String[] dataArray) {
        String data = dataArray[2];
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
                    Logger.getLogger("CWE22_P08_V1_SaffronCascadeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
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
                        Logger.getLogger("CWE22_P08_V1_SaffronCascadeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
