import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

public class CWE22_P08_V1_NovaPrism {

    public void openNovaPrism() throws IOException {
        String data;
        data = System.getenv("NOVA_PRISM_PATH");
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE22_P08_V1_NovaPrismSink()).readNovaPrism(dataArray);
    }
}

class CWE22_P08_V1_NovaPrismSink {
    public void readNovaPrism(String[] dataArray) throws IOException {
        String data = dataArray[2];
        String novaPrismRoot = "/home/user/uploads/";
        File novaPrismFile = new File(novaPrismRoot + data);
        FileInputStream novaPrismStream = new FileInputStream(novaPrismFile);
        novaPrismStream.close();
    }
}
