import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashMap;

public class CWE89_P11_V1_SaffronSundial {

    public void runSaffronSundial() throws SQLException {
        String data;
        data = System.getenv("SAFFRON_SUNDIAL_FILTER");
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE89_P11_V1_SaffronSundialSink()).querySaffronSundial(dataHashMap);
    }
}

class CWE89_P11_V1_SaffronSundialSink {
    public void querySaffronSundial(HashMap<Integer, String> dataHashMap) throws SQLException {
        String data = dataHashMap.get(2);
        Connection saffronSundialConnection = DriverManager.getConnection("jdbc:hsqldb:mem:saffronSundial");
        Statement saffronSundialStatement = null;
        ResultSet saffronSundialRows = null;
        try {
            saffronSundialStatement = saffronSundialConnection.createStatement();
            saffronSundialRows = saffronSundialStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(saffronSundialRows.getRow());
        } finally {
            if (saffronSundialRows != null) {
                saffronSundialRows.close();
            }
            if (saffronSundialStatement != null) {
                saffronSundialStatement.close();
            }
            saffronSundialConnection.close();
        }
    }
}
