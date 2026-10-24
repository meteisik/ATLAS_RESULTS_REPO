import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashMap;

public class CWE89_P11_V1_VividSignal {

    public void runVividSignal() throws SQLException {
        String data;
        data = System.getenv("VIVID_SIGNAL_FILTER");
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE89_P11_V1_VividSignalSink()).queryVividSignal(dataHashMap);
    }
}

class CWE89_P11_V1_VividSignalSink {
    public void queryVividSignal(HashMap<Integer, String> dataHashMap) throws SQLException {
        String data = dataHashMap.get(2);
        Connection vividSignalConnection = DriverManager.getConnection("jdbc:hsqldb:mem:vividSignal");
        Statement vividSignalStatement = null;
        ResultSet vividSignalRows = null;
        try {
            vividSignalStatement = vividSignalConnection.createStatement();
            vividSignalRows = vividSignalStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(vividSignalRows.getRow());
        } finally {
            if (vividSignalRows != null) {
                vividSignalRows.close();
            }
            if (vividSignalStatement != null) {
                vividSignalStatement.close();
            }
            vividSignalConnection.close();
        }
    }
}
