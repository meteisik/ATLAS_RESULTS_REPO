import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashMap;

public class CWE89_P11_V1_VividAuroraSafe {

    public void runVividAurora() throws SQLException {
        String data;
        data = "foo";
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE89_P11_V1_VividAuroraSafeSink()).queryVividAurora(dataHashMap);
    }
}

class CWE89_P11_V1_VividAuroraSafeSink {
    public void queryVividAurora(HashMap<Integer, String> dataHashMap) throws SQLException {
        String data = dataHashMap.get(2);
        Connection vividAuroraConnection = DriverManager.getConnection("jdbc:hsqldb:mem:vividAurora");
        Statement vividAuroraStatement = null;
        ResultSet vividAuroraRows = null;
        try {
            vividAuroraStatement = vividAuroraConnection.createStatement();
            vividAuroraRows = vividAuroraStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(vividAuroraRows.getRow());
        } finally {
            if (vividAuroraRows != null) {
                vividAuroraRows.close();
            }
            if (vividAuroraStatement != null) {
                vividAuroraStatement.close();
            }
            vividAuroraConnection.close();
        }
    }
}
