import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashMap;

public class CWE89_P11_V1_SaffronSignalSafe {

    public void runSaffronSignal() throws SQLException {
        String data;
        data = "foo";
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE89_P11_V1_SaffronSignalSafeSink()).querySaffronSignal(dataHashMap);
    }
}

class CWE89_P11_V1_SaffronSignalSafeSink {
    public void querySaffronSignal(HashMap<Integer, String> dataHashMap) throws SQLException {
        String data = dataHashMap.get(2);
        Connection saffronSignalConnection = DriverManager.getConnection("jdbc:hsqldb:mem:saffronSignal");
        Statement saffronSignalStatement = null;
        ResultSet saffronSignalRows = null;
        try {
            saffronSignalStatement = saffronSignalConnection.createStatement();
            saffronSignalRows = saffronSignalStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(saffronSignalRows.getRow());
        } finally {
            if (saffronSignalRows != null) {
                saffronSignalRows.close();
            }
            if (saffronSignalStatement != null) {
                saffronSignalStatement.close();
            }
            saffronSignalConnection.close();
        }
    }
}
