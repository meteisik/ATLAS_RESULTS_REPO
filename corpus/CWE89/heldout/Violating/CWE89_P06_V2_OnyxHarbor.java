import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P06_V2_OnyxHarbor {
    private static boolean privateTrue = true;

    public void runOnyxHarbor() throws SQLException {
        String data;
        if (privateTrue) {
            data = System.getenv("ONYX_HARBOR_FILTER");
        } else {
            data = null;
        }
        (new CWE89_P06_V2_OnyxHarborSink()).queryOnyxHarbor(data);
    }
}

class CWE89_P06_V2_OnyxHarborSink {
    public void queryOnyxHarbor(String data) throws SQLException {
        Connection onyxHarborConnection = DriverManager.getConnection("jdbc:hsqldb:mem:onyxHarbor");
        Statement onyxHarborStatement = null;
        ResultSet onyxHarborRows = null;
        try {
            onyxHarborStatement = onyxHarborConnection.createStatement();
            onyxHarborRows = onyxHarborStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(onyxHarborRows.getRow());
        } finally {
            if (onyxHarborRows != null) {
                onyxHarborRows.close();
            }
            if (onyxHarborStatement != null) {
                onyxHarborStatement.close();
            }
            onyxHarborConnection.close();
        }
    }
}
