import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P08_V1_NovaPrism {

    public void openNovaPrism() {
        String data;
        data = System.getenv("NOVA_PRISM_PATH");
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE22_P08_V1_NovaPrismSink()).readNovaPrism(dataArray);
    }
}

class CWE22_P08_V1_NovaPrismSink {
    public void readNovaPrism(String[] dataArray) {
        String data = dataArray[2];
        String novaPrismRoot = "/home/user/uploads/";
        if (data != null) {
            File novaPrismFile = new File(novaPrismRoot + data);
            FileInputStream novaPrismStream = null;
            InputStreamReader novaPrismStreamReader = null;
            BufferedReader novaPrismReader = null;
            if (novaPrismFile.exists() && novaPrismFile.isFile()) {
                try {
                    novaPrismStream = new FileInputStream(novaPrismFile);
                    novaPrismStreamReader = new InputStreamReader(novaPrismStream, "UTF-8");
                    novaPrismReader = new BufferedReader(novaPrismStreamReader);
                    System.out.println(novaPrismReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P08_V1_NovaPrismSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (novaPrismReader != null) {
                            novaPrismReader.close();
                        }
                        if (novaPrismStreamReader != null) {
                            novaPrismStreamReader.close();
                        }
                        if (novaPrismStream != null) {
                            novaPrismStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P08_V1_NovaPrismSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
