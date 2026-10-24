import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashMap;

public class CWE89_P11_V1_SaffronQuartzSafe {

    public void runSaffronQuartz() throws SQLException {
        String data;
        data = "foo";
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE89_P11_V1_SaffronQuartzSafeSink()).querySaffronQuartz(dataHashMap);
    }
}

class CWE89_P11_V1_SaffronQuartzSafeSink {
    public void querySaffronQuartz(HashMap<Integer, String> dataHashMap) throws SQLException {
        String data = dataHashMap.get(2);
        Connection saffronQuartzConnection = DriverManager.getConnection("jdbc:hsqldb:mem:saffronQuartz");
        Statement saffronQuartzStatement = null;
        ResultSet saffronQuartzRows = null;
        try {
            saffronQuartzStatement = saffronQuartzConnection.createStatement();
            saffronQuartzRows = saffronQuartzStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(saffronQuartzRows.getRow());
        } finally {
            if (saffronQuartzRows != null) {
                saffronQuartzRows.close();
            }
            if (saffronQuartzStatement != null) {
                saffronQuartzStatement.close();
            }
            saffronQuartzConnection.close();
        }
    }
}
