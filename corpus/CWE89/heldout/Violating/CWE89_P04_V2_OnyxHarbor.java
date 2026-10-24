import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P04_V2_OnyxHarbor {

    private String loadOnyxHarbor() {
        String data;
        data = null;
        for (int j = 0; j < 1; j++) {
            data = System.getenv("ONYX_HARBOR_FILTER");
        }
        return data;
    }

    public void runOnyxHarbor() throws SQLException {
        String data = loadOnyxHarbor();
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
