import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P07_V1_NovaSundialSafe {

    public void openNovaSundial() {
        String data;
        data = (new CWE22_P07_V1_NovaSundialSafeSource()).locateNovaSundial();
        String novaSundialRoot = "/home/user/uploads/";
        if (data != null) {
            File novaSundialFile = new File(novaSundialRoot + data);
            FileInputStream novaSundialStream = null;
            InputStreamReader novaSundialStreamReader = null;
            BufferedReader novaSundialReader = null;
            if (novaSundialFile.exists() && novaSundialFile.isFile()) {
                try {
                    novaSundialStream = new FileInputStream(novaSundialFile);
                    novaSundialStreamReader = new InputStreamReader(novaSundialStream, "UTF-8");
                    novaSundialReader = new BufferedReader(novaSundialStreamReader);
                    System.out.println(novaSundialReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P07_V1_NovaSundialSafe").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (novaSundialReader != null) {
                            novaSundialReader.close();
                        }
                        if (novaSundialStreamReader != null) {
                            novaSundialStreamReader.close();
                        }
                        if (novaSundialStream != null) {
                            novaSundialStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P07_V1_NovaSundialSafe").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

class CWE22_P07_V1_NovaSundialSafeSource {
    public String locateNovaSundial() {
        String data;
        data = "foo";
        return data;
    }
}
