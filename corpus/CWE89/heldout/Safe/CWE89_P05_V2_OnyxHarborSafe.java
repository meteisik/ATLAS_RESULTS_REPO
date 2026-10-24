import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P05_V2_OnyxHarborSafe {

    private String onyxHarborData;

    private void queryOnyxHarbor() throws SQLException {
        String data = onyxHarborData;
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

    public void runOnyxHarbor() throws SQLException {
        String data;
        if (5 == 5) {
            data = "foo";
        } else {
            data = null;
        }
        onyxHarborData = data;
        queryOnyxHarbor();
    }
}
