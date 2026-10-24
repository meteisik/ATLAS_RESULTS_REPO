import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P08_V1_SaffronCipherSafe {

    public void openSaffronCipher() {
        String data;
        data = "foo";
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE22_P08_V1_SaffronCipherSafeSink()).readSaffronCipher(dataArray);
    }
}

class CWE22_P08_V1_SaffronCipherSafeSink {
    public void readSaffronCipher(String[] dataArray) {
        String data = dataArray[2];
        String saffronCipherRoot = "/home/user/uploads/";
        if (data != null) {
            File saffronCipherFile = new File(saffronCipherRoot + data);
            FileInputStream saffronCipherStream = null;
            InputStreamReader saffronCipherStreamReader = null;
            BufferedReader saffronCipherReader = null;
            if (saffronCipherFile.exists() && saffronCipherFile.isFile()) {
                try {
                    saffronCipherStream = new FileInputStream(saffronCipherFile);
                    saffronCipherStreamReader = new InputStreamReader(saffronCipherStream, "UTF-8");
                    saffronCipherReader = new BufferedReader(saffronCipherStreamReader);
                    System.out.println(saffronCipherReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P08_V1_SaffronCipherSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (saffronCipherReader != null) {
                            saffronCipherReader.close();
                        }
                        if (saffronCipherStreamReader != null) {
                            saffronCipherStreamReader.close();
                        }
                        if (saffronCipherStream != null) {
                            saffronCipherStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P08_V1_SaffronCipherSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
